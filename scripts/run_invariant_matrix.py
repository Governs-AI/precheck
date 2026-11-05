#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""Run the decision-path invariant matrix against one or more commits.

The harness in this checkout is copied onto a detached worktree of each
commit. Pytest then imports that commit's ``app`` package, so the same cells
run against that tree. The worktree is deleted afterwards. The commit itself
is not changed.

Example:
    python scripts/run_invariant_matrix.py \\
        --commit b19caba64baccbe0cc6e564912433e567a8d2c89 \\
        --commit e4ed50ce0a10880bc103437b6008eb58f747a7e4 \\
        --output tests/invariants/matrix_results.csv
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HARNESS_ROOT = Path(__file__).resolve().parents[1]
OVERLAY_FILES = (
    "tests/test_budget_all_paths.py",
    "tests/test_policy_store_fail_closed.py",
)
CSV_FIELDS = ("cell_id", "path", "state", "control", "commit", "result", "note")


def _test_env() -> None:
    """Match tests/conftest.py so importing the harness does not reject secrets."""
    os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
    os.environ.setdefault("DEBUG", "true")
    os.environ.setdefault("PII_TOKEN_SALT", "test-salt-for-ci-only")
    os.environ.setdefault("WEBHOOK_SECRET", "test-webhook-secret-ci")
    os.environ.setdefault("REDIS_URL", "")
    os.environ.setdefault("WEBHOOK_BASE_URL", "")
    os.environ.setdefault("WEBHOOK_CONN_KEY", "")
    os.environ.setdefault("KEY_HMAC_SECRET", "test-hmac-secret-for-ci-only")


def main(argv: list[str] | None = None) -> int:
    _test_env()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--commit",
        action="append",
        required=True,
        help="Commit to measure. Repeat for more than one.",
    )
    parser.add_argument(
        "--output",
        default=str(HARNESS_ROOT / "tests" / "invariants" / "matrix_results.csv"),
    )
    parser.add_argument(
        "--environment",
        default=str(HARNESS_ROOT / "tests" / "invariants" / "matrix_environment.txt"),
    )
    args = parser.parse_args(argv)

    # Import after args parse so --help does not load the service.
    sys.path.insert(0, str(HARNESS_ROOT))
    from tests.invariants.matrix import iter_cells

    expected_ids = {cell.id for cell in iter_cells()}
    rows = []
    env_lines = [
        "measurement=detached worktree of the commit, harness overlaid from {}".format(
            HARNESS_ROOT
        ),
        "python={}".format(sys.version.replace("\n", " ")),
    ]
    exit_code = 0
    for commit in args.commit:
        sha = _rev_parse(commit)
        measured, details = _measure(sha, expected_ids)
        rows.extend(_sorted_rows(measured, sha))
        env_lines.append("")
        env_lines.extend(details)
        if len(measured) != len(expected_ids):
            exit_code = 1

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    env_path = Path(args.environment)
    env_path.write_text("\n".join(env_lines) + "\n", encoding="utf-8")
    print("wrote {} rows to {}".format(len(rows), output))
    print("wrote {}".format(env_path))
    return exit_code


def _rev_parse(commit: str) -> str:
    return subprocess.check_output(
        ["git", "rev-parse", commit], cwd=HARNESS_ROOT, text=True
    ).strip()


def _measure(sha: str, expected_ids: set[str]) -> tuple[list[dict], list[str]]:
    worktree = Path(tempfile.mkdtemp(prefix="invariant-pin-{}-".format(sha[:12])))
    # mkdtemp creates the directory; git worktree add requires it to be absent.
    worktree.rmdir()
    results_path = Path(tempfile.mkdtemp(prefix="invariant-results-")) / "cells.json"
    command = [
        sys.executable,
        "-m",
        "pytest",
        "tests/invariants",
        "-o",
        "addopts=-q --tb=line",
        "-p",
        "no:cov",
        "-p",
        "no:cacheprovider",
    ]
    details = [
        "commit={}".format(sha),
        "command={}".format(" ".join(command)),
        "worktree_removed_after_run=yes",
    ]
    try:
        subprocess.check_call(
            ["git", "worktree", "add", "--detach", str(worktree), sha],
            cwd=HARNESS_ROOT,
        )
        _overlay(worktree)
        details.append(
            "requirements_sha256={}".format(_hash_file(worktree / "requirements.txt"))
        )
        env = os.environ.copy()
        env["INVARIANT_RESULTS_PATH"] = str(results_path)
        env.pop("PYTHONPATH", None)
        completed = subprocess.run(command, cwd=worktree, env=env)
        details.append("pytest_exit={}".format(completed.returncode))
        if not results_path.exists():
            details.append("cells=0")
            details.append("error=pytest did not write a cell report")
            return [], details
        payload = json.loads(results_path.read_text(encoding="utf-8"))
        details.append("cells={}".format(len(payload)))
        missing = expected_ids.difference(item["cell_id"] for item in payload)
        extra = {item["cell_id"] for item in payload}.difference(expected_ids)
        if missing:
            details.append("missing={}".format(",".join(sorted(missing))))
        if extra:
            details.append("extra={}".format(",".join(sorted(extra))))
        detectors = sorted(
            {
                _detector_from_note(item.get("note") or "")
                for item in payload
                if _detector_from_note(item.get("note") or "")
            }
        )
        if detectors:
            details.append("detector={}".format(",".join(detectors)))
        return payload, details
    finally:
        subprocess.call(
            ["git", "worktree", "remove", "--force", str(worktree)],
            cwd=HARNESS_ROOT,
        )
        if worktree.exists():
            shutil.rmtree(worktree, ignore_errors=True)
        if results_path.parent.exists():
            shutil.rmtree(results_path.parent, ignore_errors=True)


def _overlay(worktree: Path) -> None:
    destination = worktree / "tests" / "invariants"
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(
        HARNESS_ROOT / "tests" / "invariants",
        destination,
        ignore=shutil.ignore_patterns(
            "__pycache__", "*.pyc", "matrix_results.csv", "matrix_environment.txt"
        ),
    )
    for relative in OVERLAY_FILES:
        shutil.copy2(HARNESS_ROOT / relative, worktree / relative)


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def _detector_from_note(note: str) -> str:
    for part in note.split(";"):
        part = part.strip()
        if part.startswith("detector="):
            return part.split("=", 1)[1]
    return ""


def _sorted_rows(payload: list[dict], sha: str) -> list[dict]:
    rows = []
    for item in payload:
        rows.append(
            {
                "cell_id": item.get("cell_id", ""),
                "path": item.get("path", ""),
                "state": item.get("state", ""),
                "control": item.get("control", ""),
                "commit": sha,
                "result": item.get("result", ""),
                "note": item.get("note", ""),
            }
        )
    rows.sort(
        key=lambda row: (row["path"], row["cell_id"], row["control"], row["state"])
    )
    return rows


if __name__ == "__main__":
    sys.exit(main())
