# PII detection benchmark

Measures what precheck's redaction path actually catches, as opposed to what
the detector it wraps scores in isolation. Published detector benchmarks
evaluate Presidio as a standalone model on text records; this one runs the
pipeline as deployed — entity allowlist, language configuration, false-positive
filter and all — because that is what decides whether a customer's SSN leaves
the building.

## Running it

```bash
# from precheck/
venv/bin/python -m bench.run                          # all arms, English only
PRESIDIO_LANGUAGES=en,es,fr,de,zh venv/bin/python -m bench.run --arms regex legacy fixed
venv/bin/python -m bench.run --json results.json      # machine-readable
venv/bin/python -m bench.corpus                       # write corpus.jsonl and print counts
```

Non-English arms need the matching spaCy models:

```bash
venv/bin/python -m spacy download es_core_news_sm   # and fr_, de_, zh_
```

## Corpus

438 items, 630 span-annotated entities, five languages, generated
deterministically from `SEED = 20260811`. Ground truth is recorded at
generation time — templates carry `{SLOT}` markers and the renderer stores each
filled value's exact offsets — so there is no annotation step and no ambiguity.
Every credit card is Luhn-valid, so a detector that gates on the checksum is not
penalised for rejecting a number that was never a card.

Tiers: `plain`, `high_sensitivity` (names, addresses, medical and national
identifiers), `partial` (last-4, initials, year-only DOB), `obfuscated` (spaced,
spelled-out), `structured` (PII nested in JSON tool arguments at depth 1–4), and
`clean` (no PII at all — the over-redaction control).

## Arms

| Arm | What it is |
|---|---|
| `regex` | `anonymize_text_regex` — the no-Presidio fallback |
| `legacy` | The pre-fix shipped path: English-only, 16-entity allowlist, whole-text false-positive filter. Entity list frozen in `run.py` so this keeps measuring what shipped |
| `presidio` | Current entry point, no caller hint |
| `fixed` | Current entry point with the corpus language as hint — what an SDK caller does via `tool_config.metadata.language` |
| `fixed_nohint` | Current entry point, no hint — exercises `PRESIDIO_LANGUAGE_MODE` |
| `presidio_unrestricted` | Diagnostic: same model, no entity allowlist. The gap to `legacy` is what the allowlist alone was discarding |

## Metrics

`leakage` is the headline: the fraction of ground-truth PII values that survive
verbatim in the output. Per value, not per span-overlap — an operator cares
whether the SSN left, not how many characters matched. `over_redact` is the
utility counterweight, measured on the clean tier: a layer that redacts
everything has zero leakage and zero value, and operators switch it off.

## Results

Five languages, `PRESIDIO_LANGUAGE_MODE=hint`, 438 items:

| Arm | leakage | high-sensitivity | over-redaction | p50 |
|---|---|---|---|---|
| `regex` | 52.2% | 89.1% | 0.0% | 0.01 ms |
| `legacy` | 51.3% | 89.1% | 0.0% | 2.46 ms |
| `fixed` | **8.2%** | **10.6%** | 0.0% | 2.48 ms |

PERSON and LOCATION went from 100% leakage to 11.6% and 11.7%. The
high-sensitivity figure is the one to watch: it covers the entity families that
regulated customers are buying redaction for, and 89.1% of them used to pass
through untouched.

## Known residual gaps

These are measured, not hypothetical, and none is fixed:

- **Obfuscated forms — 75% leakage.** `j dot smith at acme dot com`, digits
  spelled out, characters spaced. Pattern recognizers see nothing.
- **Partial disclosure — 83.3%.** "the card ending 0366", "initials M.G., born
  1982". Arguably identifying in combination; no detector in the pipeline
  models combinations.
- **Chinese — 32.1%**, well above the 1.8–4.5% of the European languages.
  `zh_core_web_sm` is the weakest NER model of the five.
- **US_SSN — 14.3%**, unchanged across every arm: the recognizer requires
  context words that some templates do not supply.
- **IBAN — 8.3%.**

The obfuscated and partial numbers match the published failure profile for
pattern-plus-NER detectors (REDACT, arXiv:2606.19881, reports 0.07 and 0.02
recall respectively for Presidio). Closing them needs a different class of
detector — an LLM pass or a purpose-built encoder — not a better regex.
