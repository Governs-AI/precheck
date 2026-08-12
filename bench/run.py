# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""Run the PII detection benchmark against precheck's redaction paths.

Usage (from precheck/):
    venv/bin/python -m bench.run                 # all arms, all languages
    venv/bin/python -m bench.run --arms regex    # single arm
    venv/bin/python -m bench.run --json out.json # machine-readable report

Metrics
-------
leakage       fraction of ground-truth PII values that survive verbatim in the
              output. This is the safety metric: one surviving value is a
              disclosure regardless of how many others were caught.
item_leakage  fraction of items where at least one value survived.
over_redact   fraction of clean-tier items (no PII) that were modified anyway.
latency_ms    per-call wall clock, p50/p95.

Leakage is deliberately the headline rather than span F1: an operator cares
whether the SSN left the building, not how many characters overlapped.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections import defaultdict
from typing import Callable, Dict, List, Optional, Tuple

from bench.corpus import HIGH_SENSITIVITY, Item, build

Arm = Callable[[str, str], Tuple[str, List[str]]]

# The entity allowlist the pre-fix code passed to Presidio: the keys of
# ANONYMIZE_OPERATORS as they stood before PERSON/LOCATION/NRP were added.
# Frozen here so the `legacy` arm keeps measuring what shipped even as the
# application constant moves on.
LEGACY_ENTITIES = [
    "DEFAULT",
    "CREDIT_CARD",
    "PHONE_NUMBER",
    "EMAIL_ADDRESS",
    "IP_ADDRESS",
    "IBAN_CODE",
    "US_SSN",
    "US_MEDICAL_RECORD_NUMBER",
    "US_HEALTH_MEMBER_ID",
    "US_NPI",
    "US_DEA",
    "US_DATE_OF_BIRTH",
    "PCI_CVV",
    "PCI_EXPIRY",
    "API_KEY",
    "JWT_TOKEN",
]


# ---------------------------------------------------------------------------
# Arms
# ---------------------------------------------------------------------------


def arm_regex(text: str, lang: str) -> Tuple[str, List[str]]:
    from app.policies import anonymize_text_regex

    return anonymize_text_regex(text)


def arm_legacy(text: str, lang: str) -> Tuple[str, List[str]]:
    """Reproduces the pre-fix shipped path: English-only, allowlist-constrained.

    Kept so before/after numbers come out of a single run rather than being
    compared across two trees.
    """
    from app.policies import ANALYZER, ANONYMIZER
    from app.policies import entity_type_to_placeholder, is_false_positive
    from presidio_anonymizer.entities import OperatorConfig

    if ANALYZER is None:
        return text, []
    try:
        results = ANALYZER.analyze(
            text=text, entities=LEGACY_ENTITIES, language="en"
        )
    except Exception:
        return text, []
    # The pre-fix code passed the whole text to the false-positive filter
    # rather than the matched span, so the filter almost never fired. Preserved
    # here deliberately: this arm documents what shipped, not what should have.
    results = [r for r in results if not is_false_positive(r.entity_type, "", text)]
    if not results:
        return text, []
    ops = {
        r.entity_type: OperatorConfig(
            "replace", {"new_value": entity_type_to_placeholder(r.entity_type)}
        )
        for r in results
    }
    out = ANONYMIZER.anonymize(text=text, analyzer_results=results, operators=ops).text
    return out, sorted({f"pii.redacted:{r.entity_type.lower()}" for r in results})


def arm_presidio(text: str, lang: str) -> Tuple[str, List[str]]:
    """Current shipped entry point with no caller hint."""
    from app.policies import anonymize_text_presidio

    return anonymize_text_presidio(text)


def arm_presidio_unrestricted(text: str, lang: str) -> Tuple[str, List[str]]:
    """Diagnostic: same model, no entity allowlist, still English-pinned.

    The delta between this and `presidio` is the cost of the entity allowlist
    alone — i.e. detection the loaded model already performs and the pipeline
    then discards.
    """
    from app.policies import ANALYZER, ANONYMIZER, entity_type_to_placeholder
    from presidio_anonymizer.entities import OperatorConfig

    if ANALYZER is None:
        return text, []
    results = ANALYZER.analyze(text=text, language="en")
    if not results:
        return text, []
    ops = {
        r.entity_type: OperatorConfig(
            "replace", {"new_value": entity_type_to_placeholder(r.entity_type)}
        )
        for r in results
    }
    out = ANONYMIZER.anonymize(text=text, analyzer_results=results, operators=ops).text
    return out, sorted({f"pii.redacted:{r.entity_type.lower()}" for r in results})


def arm_precheck_fixed(text: str, lang: str) -> Tuple[str, List[str]]:
    """Post-fix path: multi-language analyzer + widened entity set.

    Passes the corpus language as the caller hint, which is what an SDK caller
    does via tool_config.metadata.language.
    """
    from app.policies import anonymize_text_presidio

    return anonymize_text_presidio(text, language=lang)


def arm_precheck_fixed_nohint(text: str, lang: str) -> Tuple[str, List[str]]:
    """Post-fix path with no language hint — exercises PRESIDIO_LANGUAGE_MODE."""
    from app.policies import anonymize_text_presidio

    return anonymize_text_presidio(text)


ARMS: Dict[str, Arm] = {
    "regex": arm_regex,
    "legacy": arm_legacy,
    "presidio": arm_presidio,
    "presidio_unrestricted": arm_presidio_unrestricted,
    "fixed": arm_precheck_fixed,
    "fixed_nohint": arm_precheck_fixed_nohint,
}


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


class Accumulator:
    def __init__(self) -> None:
        self.spans_total = 0
        self.spans_leaked = 0
        self.items_total = 0
        self.items_leaked = 0
        self.clean_total = 0
        self.clean_modified = 0
        self.latencies: List[float] = []
        self.by_entity: Dict[str, List[int]] = defaultdict(lambda: [0, 0])  # [leaked, total]

    def rate(self, num: int, den: int) -> Optional[float]:
        return round(num / den, 4) if den else None

    def summary(self) -> Dict[str, object]:
        lat = sorted(self.latencies)
        p50 = round(statistics.median(lat), 2) if lat else None
        p95 = round(lat[int(len(lat) * 0.95)], 2) if len(lat) >= 20 else None
        return {
            "spans": self.spans_total,
            "leakage": self.rate(self.spans_leaked, self.spans_total),
            "item_leakage": self.rate(self.items_leaked, self.items_total),
            "over_redact": self.rate(self.clean_modified, self.clean_total),
            "latency_p50_ms": p50,
            "latency_p95_ms": p95,
        }


def score_item(item: Item, out: str) -> Tuple[int, int, List[str]]:
    """Return (leaked_spans, total_spans, leaked_entity_types)."""
    leaked = 0
    types: List[str] = []
    for span in item.spans:
        if span.value and span.value in out:
            leaked += 1
            types.append(span.type)
    return leaked, len(item.spans), types


def run_arm(name: str, arm: Arm, items: List[Item]) -> Dict[str, object]:
    overall = Accumulator()
    by_lang: Dict[str, Accumulator] = defaultdict(Accumulator)
    by_tier: Dict[str, Accumulator] = defaultdict(Accumulator)
    high_sens = Accumulator()

    for item in items:
        t0 = time.perf_counter()
        try:
            out, _reasons = arm(item.text, item.lang)
        except Exception as exc:  # an arm that crashes leaks everything
            print(f"  ! {name} raised on {item.id}: {type(exc).__name__}: {exc}", file=sys.stderr)
            out = item.text
        elapsed_ms = (time.perf_counter() - t0) * 1000

        leaked, total, leaked_types = score_item(item, out)

        for acc in (overall, by_lang[item.lang], by_tier[item.tier]):
            acc.latencies.append(elapsed_ms)
            acc.spans_total += total
            acc.spans_leaked += leaked
            acc.items_total += 1
            if leaked:
                acc.items_leaked += 1
            if item.tier == "clean":
                acc.clean_total += 1
                if out != item.text:
                    acc.clean_modified += 1

        for span in item.spans:
            etype = span.type
            overall.by_entity[etype][1] += 1
            if span.value in out:
                overall.by_entity[etype][0] += 1
            if etype in HIGH_SENSITIVITY:
                high_sens.spans_total += 1
                if span.value in out:
                    high_sens.spans_leaked += 1

    return {
        "overall": overall.summary(),
        "high_sensitivity_leakage": overall.rate(high_sens.spans_leaked, high_sens.spans_total),
        "by_lang": {k: v.summary() for k, v in sorted(by_lang.items())},
        "by_tier": {k: v.summary() for k, v in sorted(by_tier.items())},
        "by_entity": {
            k: {"leaked": v[0], "total": v[1], "leakage": round(v[0] / v[1], 4) if v[1] else None}
            for k, v in sorted(overall.by_entity.items())
        },
    }


def fmt_pct(v: Optional[float]) -> str:
    return "  n/a" if v is None else f"{v * 100:5.1f}%"


def print_report(results: Dict[str, Dict[str, object]]) -> None:
    arms = list(results.keys())

    print("\n=== Overall (leakage = ground-truth PII values surviving verbatim) ===\n")
    print(f"{'arm':<24}{'leakage':>9}{'item_leak':>11}{'high_sens':>11}{'over_redact':>13}{'p50 ms':>9}{'p95 ms':>9}")
    for arm in arms:
        o = results[arm]["overall"]
        print(
            f"{arm:<24}{fmt_pct(o['leakage']):>9}{fmt_pct(o['item_leakage']):>11}"
            f"{fmt_pct(results[arm]['high_sensitivity_leakage']):>11}"
            f"{fmt_pct(o['over_redact']):>13}"
            f"{str(o['latency_p50_ms']):>9}{str(o['latency_p95_ms']):>9}"
        )

    print("\n=== Leakage by language ===\n")
    langs = sorted({lang for arm in arms for lang in results[arm]["by_lang"]})
    print(f"{'arm':<24}" + "".join(f"{lang:>9}" for lang in langs))
    for arm in arms:
        row = "".join(fmt_pct(results[arm]["by_lang"].get(lang, {}).get("leakage")) for lang in langs)
        print(f"{arm:<24}{row}")

    print("\n=== Leakage by tier ===\n")
    tiers = sorted({t for arm in arms for t in results[arm]["by_tier"]})
    print(f"{'arm':<24}" + "".join(f"{t[:9]:>18}" for t in tiers))
    for arm in arms:
        row = "".join(
            f"{fmt_pct(results[arm]['by_tier'].get(t, {}).get('leakage')):>18}" for t in tiers
        )
        print(f"{arm:<24}{row}")

    print("\n=== Leakage by entity type ===\n")
    ents = sorted({e for arm in arms for e in results[arm]["by_entity"]})
    print(f"{'entity':<28}" + "".join(f"{a[:16]:>22}" for a in arms))
    for ent in ents:
        row = ""
        for arm in arms:
            cell = results[arm]["by_entity"].get(ent)
            row += f"{fmt_pct(cell['leakage']) if cell else '   n/a':>22}"
        print(f"{ent:<28}{row}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--arms", nargs="*", default=list(ARMS.keys()))
    ap.add_argument("--languages", nargs="*", default=None)
    ap.add_argument("--per-template", type=int, default=6)
    ap.add_argument("--json", dest="json_out", default=None)
    args = ap.parse_args()

    items = build(per_template=args.per_template, languages=args.languages)
    print(f"corpus: {len(items)} items, {sum(len(i.spans) for i in items)} annotated spans")

    results: Dict[str, Dict[str, object]] = {}
    for name in args.arms:
        if name not in ARMS:
            print(f"unknown arm: {name}", file=sys.stderr)
            return 2
        print(f"running arm: {name} ...", flush=True)
        results[name] = run_arm(name, ARMS[name], items)

    print_report(results)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
        print(f"\nwrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
