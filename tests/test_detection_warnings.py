# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""Reduced PII detection coverage is reported, never silent.

PRESIDIO_LANGUAGES defaults to English only, which keeps the service inside
small (512 MB) instances. Non-English text is then analysed with the English
model, which misses more PII and redacts clean text. These tests pin that
startup says so, that a configured language whose model is missing is
reported, and that a request hinting an unloaded language is logged once.
"""

import logging

import pytest

from app import policies
from app.settings import Settings


@pytest.fixture
def presidio_state(monkeypatch):
    """Pretend Presidio built for the given languages, with given skips."""
    monkeypatch.delenv("PRESIDIO_LANGUAGES", raising=False)

    def apply(languages, skipped=None, explicit=None, available=True):
        kwargs = {"debug": True}
        if explicit is not None:
            kwargs["presidio_languages"] = explicit
        monkeypatch.setattr(policies, "settings", Settings(**kwargs))
        monkeypatch.setattr(policies, "SUPPORTED_LANGUAGES", list(languages))
        monkeypatch.setattr(policies, "SKIPPED_LANGUAGES", dict(skipped or {}))
        monkeypatch.setattr(policies, "USE_PRESIDIO", available)
        monkeypatch.setattr(policies, "ANALYZER", object() if available else None)

    return apply


def test_default_english_only_warns(presidio_state):
    presidio_state(["en"])

    warnings = policies.detection_warnings()

    assert len(warnings) == 1
    assert "English-only" in warnings[0]
    assert "PRESIDIO_LANGUAGES=en,es,fr,de,zh" in warnings[0]


def test_explicit_english_only_is_a_recorded_choice(presidio_state):
    presidio_state(["en"], explicit="en")

    assert policies.detection_warnings() == []


def test_all_languages_loaded_is_quiet(presidio_state):
    presidio_state(["en", "es", "fr", "de", "zh"], explicit="en,es,fr,de,zh")

    assert policies.detection_warnings() == []


def test_missing_language_model_warns(presidio_state):
    presidio_state(
        ["en", "es"],
        skipped={"zh": "spaCy model zh_core_web_sm is not installed"},
        explicit="en,es,zh",
    )

    warnings = policies.detection_warnings()

    assert len(warnings) == 1
    assert "language zh is disabled" in warnings[0]
    assert "zh_core_web_sm" in warnings[0]


def test_regex_only_mode_warns(presidio_state):
    presidio_state(["en"], explicit="en", available=False)

    warnings = policies.detection_warnings()

    assert len(warnings) == 1
    assert "regex patterns only" in warnings[0]


def test_resolve_records_skipped_languages(monkeypatch):
    monkeypatch.setattr(
        policies, "settings", Settings(debug=True, presidio_languages="en,fr,pt")
    )
    monkeypatch.setattr(policies, "SKIPPED_LANGUAGES", {})
    monkeypatch.setattr(
        policies, "_model_available", lambda name: name != "fr_core_news_sm"
    )

    models = policies._resolve_language_models()

    assert [m["lang_code"] for m in models] == ["en"]
    assert set(policies.SKIPPED_LANGUAGES) == {"fr", "pt"}
    assert "fr_core_news_sm" in policies.SKIPPED_LANGUAGES["fr"]


def test_unloaded_hint_is_logged_once(presidio_state, monkeypatch, caplog):
    presidio_state(["en"], explicit="en")
    monkeypatch.setattr(policies, "_unloaded_hints_reported", set())

    with caplog.at_level(logging.WARNING, logger="app.policies"):
        assert policies._languages_to_analyze("fr") == ["en"]
        assert policies._languages_to_analyze("FR") == ["en"]
        # Unknown codes are caller text and are not echoed into logs.
        assert policies._languages_to_analyze("not-a-language") == ["en"]

    messages = [r.getMessage() for r in caplog.records]
    assert len(messages) == 1
    assert "hint language fr" in messages[0]


def test_startup_logs_detection_warnings(test_client_factory, monkeypatch):
    logged = []
    monkeypatch.setattr(policies, "detection_warnings", lambda: ["degraded"])
    from app import main

    monkeypatch.setattr(main.logger, "warning", lambda msg, *a: logged.append(msg))

    with test_client_factory():
        pass

    assert logged == ["degraded"]


@pytest.fixture
def test_client_factory():
    from fastapi.testclient import TestClient

    from app.main import create_app

    return lambda: TestClient(create_app())
