# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""TEST — language handling and entity coverage in the Presidio path.

Two defects these tests pin down:

1. `ANALYZER.analyze(..., language="en")` was hardcoded at every call site, so
   the es/fr/de/zh spaCy models the image installs were never reachable.
2. The entity allowlist passed to the analyzer omitted PERSON, LOCATION and
   NRP, so names and addresses were detected by the NER model and then dropped
   before redaction. `bench/` measured 100% leakage on both, in English too.

Tests that need non-English models are marked `multilingual` and skip when the
models are absent; run them inside the precheck image.
"""

import importlib.util

import pytest

from app import policies
from app.policies import (
    DETECT_ENTITIES,
    anonymize_text_presidio,
    language_hint,
)
from app.settings import Settings


def _has_model(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


requires_presidio = pytest.mark.skipif(
    policies.ANALYZER is None,
    reason="Presidio analyzer unavailable in this environment",
)


class TestEntityCoverage:
    """The allowlist must carry the entity types a redaction policy implies."""

    @pytest.mark.parametrize("entity", ["PERSON", "LOCATION", "NRP"])
    def test_identity_entities_are_requested(self, entity):
        assert entity in DETECT_ENTITIES

    @pytest.mark.parametrize("entity", ["ORGANIZATION", "DATE_TIME"])
    def test_low_precision_entities_excluded(self, entity):
        """Both wreck PII-free text: 'Acme Corporation', 'quarterly', 'UTC'."""
        assert entity not in DETECT_ENTITIES

    def test_default_is_not_an_entity_type(self):
        """The old code passed ANONYMIZE_OPERATORS keys, which include DEFAULT."""
        assert "DEFAULT" not in DETECT_ENTITIES


@requires_presidio
class TestPersonAndLocationRedaction:
    def test_person_name_redacted(self):
        out, reasons = anonymize_text_presidio(
            "Patient Maria Garcia is due for a follow-up.", language="en"
        )
        assert "Maria Garcia" not in out
        assert any("person" in r for r in reasons)

    def test_location_redacted(self):
        out, _ = anonymize_text_presidio(
            "Ship the cheque to 1600 Pennsylvania Avenue, Washington DC.", language="en"
        )
        assert "Washington DC" not in out

    def test_clean_text_survives(self):
        """Utility control: no PII in, nothing redacted out."""
        text = "Acme Corporation reported quarterly revenue above forecast."
        out, reasons = anonymize_text_presidio(text, language="en")
        assert out == text
        assert reasons == []


@requires_presidio
class TestLanguageResolution:
    def test_unknown_hint_falls_back_to_supported_language(self):
        out, _ = anonymize_text_presidio(
            "Patient Maria Garcia is due for a follow-up.", language="xx"
        )
        assert "Maria Garcia" not in out

    def test_supported_languages_populated(self):
        assert policies.SUPPORTED_LANGUAGES
        assert "en" in policies.SUPPORTED_LANGUAGES


class TestLanguageHint:
    def test_reads_tool_config_metadata(self):
        assert language_hint({"metadata": {"language": "es"}}, None) == "es"

    def test_falls_back_to_policy_config(self):
        assert language_hint(None, {"language": "fr"}) == "fr"

    def test_tool_config_wins(self):
        assert (
            language_hint({"metadata": {"language": "es"}}, {"language": "fr"}) == "es"
        )

    @pytest.mark.parametrize(
        "tool_config,policy_config",
        [
            (None, None),
            ({}, {}),
            ({"metadata": {}}, {}),
            ({"metadata": {"language": "   "}}, {}),
            ({"metadata": {"language": 42}}, {}),
            ("not-a-dict", None),
        ],
    )
    def test_absent_or_malformed_hint_is_none(self, tool_config, policy_config):
        assert language_hint(tool_config, policy_config) is None


class TestSettings:
    def test_language_list_parsed_and_deduped(self):
        s = Settings(presidio_languages="en, es ,EN,fr", debug=True)
        assert s.presidio_language_list() == ["en", "es", "fr"]

    def test_empty_language_list_defaults_to_english(self):
        assert Settings(
            presidio_languages="  ,  ", debug=True
        ).presidio_language_list() == ["en"]

    def test_invalid_language_mode_rejected(self):
        with pytest.raises(ValueError, match="PRESIDIO_LANGUAGE_MODE"):
            Settings(presidio_language_mode="sometimes", debug=True)

    @pytest.mark.parametrize("mode", ["hint", "union"])
    def test_valid_language_modes_accepted(self, mode):
        assert (
            Settings(presidio_language_mode=mode, debug=True).presidio_language_mode
            == mode
        )


@pytest.mark.multilingual
class TestNonEnglishRedaction:
    """Requires the es/fr/de spaCy models; run inside the precheck image."""

    @pytest.mark.parametrize(
        "lang,model,text,secret",
        [
            (
                "es",
                "es_core_news_sm",
                "El paciente Juan Martínez necesita revisión.",
                "Juan Martínez",
            ),
            (
                "fr",
                "fr_core_news_sm",
                "Le patient Jean Dupont doit être revu.",
                "Jean Dupont",
            ),
            (
                "de",
                "de_core_news_sm",
                "Der Patient Hans Müller braucht eine Untersuchung.",
                "Hans Müller",
            ),
        ],
    )
    def test_person_redacted_in_language(self, lang, model, text, secret):
        if not _has_model(model):
            pytest.skip(f"{model} not installed; run inside the precheck image")
        if lang not in policies.SUPPORTED_LANGUAGES:
            pytest.skip(f"analyzer not built for {lang}; set PRESIDIO_LANGUAGES")

        out, _ = anonymize_text_presidio(text, language=lang)
        assert secret not in out
