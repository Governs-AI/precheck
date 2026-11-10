# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""Collect invariant cell results when INVARIANT_RESULTS_PATH is set.

Fixtures are imported from the existing suites so store outages and API keys
are not reimplemented here.
"""

from __future__ import annotations

import json
import os

_RESULTS = {}


def _cell_id(nodeid: str):
    if "[" not in nodeid or not nodeid.endswith("]"):
        return None
    return nodeid.split("[", 1)[1][:-1]


def pytest_runtest_logreport(report):
    if not os.environ.get("INVARIANT_RESULTS_PATH"):
        return
    cell_id = _cell_id(report.nodeid)
    if not cell_id:
        return

    if report.when == "setup" and report.failed:
        _RESULTS.setdefault(
            cell_id,
            {
                "cell_id": cell_id,
                "path": "",
                "state": "",
                "control": "",
                "result": "fail",
                "note": "setup failed: {}".format(_short(report.longrepr)),
            },
        )
        return

    if report.when != "call":
        return

    from tests.invariants.matrix import LAST_NOTES

    outcome = LAST_NOTES.get(cell_id)
    if outcome is not None:
        _RESULTS[cell_id] = {
            "cell_id": outcome.cell_id,
            "path": outcome.path,
            "state": outcome.state,
            "control": outcome.control,
            "result": outcome.result,
            "note": outcome.note,
        }
        return

    if report.passed:
        result = "pass"
        note = ""
    elif report.skipped:
        text = _skip_text(report)
        if text.startswith("N/A:"):
            result = "n/a"
            note = text[4:].strip()
        else:
            result = "skip"
            note = text[5:].strip() if text.startswith("SKIP:") else text
    else:
        result = "fail"
        note = _short(report.longrepr)
    _RESULTS[cell_id] = {
        "cell_id": cell_id,
        "path": "",
        "state": "",
        "control": "",
        "result": result,
        "note": note,
    }


def pytest_sessionfinish(session, exitstatus):
    path = os.environ.get("INVARIANT_RESULTS_PATH")
    if not path:
        return
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(list(_RESULTS.values()), handle, indent=2, sort_keys=True)
        handle.write("\n")


def _skip_text(report) -> str:
    longrepr = report.longrepr
    if isinstance(longrepr, tuple) and len(longrepr) >= 3:
        return str(longrepr[2])
    return str(longrepr)


def _short(longrepr) -> str:
    text = str(longrepr).strip().replace("\n", " ")
    return text[:500]
