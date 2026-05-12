# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""
Smoke test for multilingual spaCy models baked into the precheck image.

Run inside the built container:

    docker run --rm <image> python scripts/smoke_multilingual_pii.py

Exits non-zero if any configured model fails to load, which is how CI (and the
Dockerfile RUN layer, if the test is wired there) enforces the acceptance
criteria for GOV-585 / TASKS.md §3.5a.

The script also prints per-model load times so we can track the startup-cost
impact of the multilingual models over time.
"""

import sys
import time
from typing import List, Tuple

MODELS: List[str] = [
    "en_core_web_sm",
    "es_core_news_sm",
    "fr_core_news_sm",
    "de_core_news_sm",
    "zh_core_web_sm",
]


def _load_all() -> Tuple[List[Tuple[str, float]], List[Tuple[str, str]]]:
    import spacy

    ok: List[Tuple[str, float]] = []
    failed: List[Tuple[str, str]] = []
    for model in MODELS:
        t0 = time.perf_counter()
        try:
            spacy.load(model)
        except Exception as exc:
            failed.append((model, f"{type(exc).__name__}: {exc}"))
            continue
        ok.append((model, time.perf_counter() - t0))
    return ok, failed


def main() -> int:
    ok, failed = _load_all()

    for model, elapsed in ok:
        print(f"loaded  {model:<22} {elapsed*1000:7.1f} ms")
    for model, err in failed:
        print(f"FAILED  {model:<22} {err}")

    total = sum(elapsed for _, elapsed in ok)
    print(f"total cold-load time across {len(ok)} model(s): {total*1000:.1f} ms")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
