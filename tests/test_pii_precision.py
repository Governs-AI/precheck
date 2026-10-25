# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""V2.14 — PII precision: place names and command words are not PII.

spaCy's small models tagged every country and city as LOCATION and
sentence-initial words like "Email" as PERSON, so PII-free prompts were
redacted. These tests pin the fix from both sides: the clean sentences pass
through untouched, and the real PII next to the same words is still caught.
Full numbers: `python -m bench.run --arms fixed` (tiers clean_context/context).
"""

import pytest

from app import policies
from app.policies import anonymize_text_presidio

pytestmark = pytest.mark.skipif(
    not policies.USE_PRESIDIO or policies.ANALYZER is None,
    reason="needs Presidio + en_core_web_sm",
)


def redact(text: str) -> str:
    return anonymize_text_presidio(text, language="en")[0]


@pytest.mark.parametrize(
    "text",
    [
        "Summarise the release notes for France and Germany.",
        "Email the quarterly report to the team before Friday.",
        "Book a flight from New York to Tokyo for the offsite.",
        "Revenue in Brazil grew faster than in India this quarter.",
        "Our London office ships the Paris launch on Monday.",
        "Invoice 7 is due; Payment goes out from London next week.",
        "Draft a reply to Customer Support about the Berlin outage.",
        "Schedule the review with the Madrid and Lisbon teams.",
    ],
)
def test_place_names_and_command_words_are_left_alone(text):
    assert redact(text) == text


@pytest.mark.parametrize(
    "text, value",
    [
        ("Ship the cheque to 42 Baker Street, London.", "42 Baker Street"),
        ("Deliver to 500 Market St, San Francisco by noon.", "500 Market St"),
        ("Send it to 1600 Pennsylvania Avenue, Washington DC.", "1600 Pennsylvania"),
        ("Envíen el cheque a Calle Gran Vía 28, Madrid.", "Gran Vía 28"),
        ("Envoyez le chèque au 12 Rue de Rivoli, Paris.", "Rue de Rivoli"),
        (
            "Senden Sie den Scheck an Maximilianstraße 13, München.",
            "Maximilianstraße 13",
        ),
        ("请把支票寄到北京市朝阳区建国路88号。", "建国路88号"),
    ],
)
def test_street_addresses_are_redacted(text, value):
    assert value not in redact(text)


@pytest.mark.parametrize(
    "text, city",
    [
        (
            "Patient Maria Garcia lives in Springfield and works in London.",
            "Springfield",
        ),
        ("The applicant was born in Leeds.", "Leeds"),
        ("The customer moved to Austin last year.", "Austin"),
    ],
)
def test_a_place_that_says_where_someone_lives_is_redacted(text, city):
    out = redact(text)
    assert city not in out
    # ...but an unrelated place in the same sentence is not.
    if "London" in text:
        assert "London" in out


@pytest.mark.parametrize(
    "text, name",
    [
        ("Email John Smith the France launch plan.", "John Smith"),
        ("Remind Sarah Chen that the Berlin summit starts Monday.", "Sarah Chen"),
        ("Hello Maria Garcia, your Paris booking is confirmed.", "Maria Garcia"),
    ],
)
def test_names_next_to_command_words_are_still_redacted(text, name):
    out = redact(text)
    assert name not in out
    # The command word itself survives.
    assert out.split()[0] == text.split()[0]


def test_other_pii_is_unaffected():
    out = redact("Email jane.doe@example.com about SSN 123-45-6789")
    assert out == "Email <USER_EMAIL> about SSN <USER_SSN>"


def test_trim_keeps_names_that_are_also_words():
    # Words that double as given names are not in NOT_A_NAME.
    for name in ("bill", "mark", "will", "grace", "may", "chase"):
        assert name not in policies.NOT_A_NAME


def test_bench_regression_tiers_english():
    """The bench's clean_context/context tiers, English slice."""
    from bench.corpus import CLEAN_TIERS, build

    items = [i for i in build(languages=["en"]) if i.tier in CLEAN_TIERS | {"context"}]
    clean = [i for i in items if i.tier in CLEAN_TIERS]
    modified = [i.text for i in clean if redact(i.text) != i.text]
    assert modified == []

    leaked = [
        (i.text, s.value)
        for i in items
        if i.tier == "context"
        for s in i.spans
        if s.value in redact(i.text)
    ]
    assert leaked == []


# --- V2.18: languages, and given names that are also places ------------------


@pytest.mark.parametrize(
    "text",
    [
        "Translate the onboarding guide into Spanish and Italian.",
        "Reply to the customer in French.",
        "Translate this from Japanese to Korean.",
        "Write the summary in German and Portuguese.",
        "Revenue in Jordan grew four percent last year.",
        "Our Austin office closes at five on Fridays.",
        "France announced new tariffs on steel.",
        "Florence is beautiful in spring.",
    ],
)
def test_languages_and_places_used_as_such_are_left_alone(text):
    assert redact(text) == text


@pytest.mark.parametrize(
    "text",
    ["The Italian team ships Monday.", "She is a devout Catholic."],
)
def test_nationality_and_religion_are_still_redacted(text):
    assert "<USER_NRP>" in redact(text)


@pytest.mark.parametrize(
    "text, name",
    [
        ("Jordan approved the budget.", "Jordan"),
        ("Georgia signed the contract yesterday.", "Georgia"),
        ("Charlotte signed the NDA yesterday.", "Charlotte"),
        ("Ask Victoria to review the Berlin contract.", "Victoria"),
        ("Hi Charlotte, the Tokyo deck is attached.", "Charlotte"),
        ("Jordan will approve the plan on Monday.", "Jordan"),
    ],
)
def test_given_names_read_as_places_are_redacted(text, name):
    out = redact(text)
    assert name not in out
    assert "<USER_NAME>" in out
