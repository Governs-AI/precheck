# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""
TEST-3.5a — Multilingual spaCy model smoke tests.

The precheck container ships with spaCy models for English plus Spanish,
French, German and Mandarin Chinese (TASKS.md §3.5a / GOV-585). These tests
assert each model can be loaded without error so we catch regressions in the
Dockerfile (e.g. a typo'd model name, or a spaCy major-version bump that drops
an old model) before the image reaches prod.

Outside the container the models may not be installed locally; in that case
the test is skipped rather than failed. CI should run `pytest -m multilingual`
inside the built precheck image (or invoke scripts/smoke_multilingual_pii.py)
to enforce the acceptance criteria.
"""

import importlib.util
import time

import pytest

MULTILINGUAL_MODELS = [
    "es_core_news_sm",
    "fr_core_news_sm",
    "de_core_news_sm",
    "zh_core_web_sm",
]


def _spacy_or_skip():
    if importlib.util.find_spec("spacy") is None:
        pytest.skip("spaCy not installed in this environment")
    import spacy

    return spacy


def _require_model(spacy_mod, model_name: str):
    if importlib.util.find_spec(model_name) is None:
        pytest.skip(f"{model_name} not installed locally; run inside precheck image")
    return spacy_mod.load(model_name)


@pytest.mark.multilingual
@pytest.mark.parametrize("model_name", MULTILINGUAL_MODELS)
def test_multilingual_model_loads(model_name):
    """Each configured multilingual spaCy model loads without raising."""
    spacy = _spacy_or_skip()
    nlp = _require_model(spacy, model_name)
    assert nlp is not None
    assert nlp.lang == model_name.split("_", 1)[0]


@pytest.mark.multilingual
@pytest.mark.parametrize(
    "model_name,text",
    [
        ("es_core_news_sm", "Juan vive en Madrid."),
        ("fr_core_news_sm", "Marie habite à Paris."),
        ("de_core_news_sm", "Hans wohnt in Berlin."),
        ("zh_core_web_sm", "李雷住在北京。"),
    ],
)
def test_multilingual_model_pipeline_runs(model_name, text):
    """Each model's pipeline executes on a short language-appropriate sample."""
    spacy = _spacy_or_skip()
    nlp = _require_model(spacy, model_name)
    doc = nlp(text)
    assert len(list(doc)) > 0


@pytest.mark.multilingual
def test_all_models_cold_load_under_budget():
    """Combined cold-load for all multilingual models stays under 10s budget.

    The budget is deliberately generous — we only want to catch a future
    regression where a model balloons in size or spaCy changes its load path.
    """
    spacy = _spacy_or_skip()

    total = 0.0
    for model in MULTILINGUAL_MODELS:
        _require_model(spacy, model)
        t0 = time.perf_counter()
        spacy.load(model)
        total += time.perf_counter() - t0
    assert total < 10.0, f"multilingual cold load took {total:.2f}s (budget 10s)"
