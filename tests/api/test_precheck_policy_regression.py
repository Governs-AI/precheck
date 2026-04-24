# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""Regression coverage for precheck policy behavior at the API layer."""

from pathlib import Path

import pytest
import yaml

PRECHECK_URL = "/api/v1/precheck"
POLICY_PATH = Path(__file__).resolve().parents[2] / "policy.tool_access.yaml"
POLICY = yaml.safe_load(POLICY_PATH.read_text())

TOOL_CASES = {
    "verify_identity": {
        "raw_text": "Verify jane@example.com against SSN 123-45-6789.",
        "decision": "transform",
        "policy_id": "tool-access",
        "contains": ["jane@example.com", "pii_"],
        "not_contains": ["123-45-6789"],
        "reasons": {
            "pii.allowed:PII:email_address",
            "pii.tokenized:PII:us_ssn",
        },
    },
    "send_marketing_email": {
        "raw_text": "Send the launch note to jane@example.com.",
        "decision": "transform",
        "policy_id": "tool-access",
        "contains": ["jane@example.com"],
        "not_contains": [],
        "reasons": {
            "pii.allowed:PII:email_address",
        },
    },
    "data_export": {
        "raw_text": "Export jane@example.com to the reporting system.",
        "decision": "transform",
        "policy_id": "strict-fallback",
        "contains": ["<USER_EMAIL>"],
        "not_contains": ["jane@example.com"],
        "reasons": {
            "pii.redacted:email_address",
        },
    },
    "audit_log": {
        "raw_text": "Audit record for jane@example.com.",
        "decision": "transform",
        "policy_id": "strict-fallback",
        "contains": ["<USER_EMAIL>"],
        "not_contains": ["jane@example.com"],
        "reasons": {
            "pii.redacted:email_address",
        },
    },
}


@pytest.fixture(autouse=True)
def _force_regex_fallback(monkeypatch):
    monkeypatch.setattr("app.policies.USE_PRESIDIO", False)
    monkeypatch.setattr("app.policies.ANALYZER", None)


def _precheck(test_client, active_api_key, tool, raw_text):
    return test_client.post(
        PRECHECK_URL,
        headers={"X-Governs-Key": active_api_key.key},
        json={"tool": tool, "raw_text": raw_text},
    )


def test_tool_cases_cover_every_declared_policy_tool():
    assert set(TOOL_CASES) == set(POLICY["tool_access"])


@pytest.mark.parametrize("tool_name", sorted(TOOL_CASES))
def test_precheck_enforces_expected_policy_per_declared_tool(
    tool_name, test_client, active_api_key
):
    case = TOOL_CASES[tool_name]

    response = _precheck(
        test_client=test_client,
        active_api_key=active_api_key,
        tool=tool_name,
        raw_text=case["raw_text"],
    )

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == case["decision"]
    assert body["policy_id"] == case["policy_id"]

    for needle in case["contains"]:
        assert needle in body["raw_text_out"]

    for needle in case["not_contains"]:
        assert needle not in body["raw_text_out"]

    assert set(body.get("reasons") or []) == case["reasons"]


def test_clean_text_allows_known_ingress_tool(test_client, active_api_key):
    raw_text = "Plain operational status update with no PII."

    response = _precheck(
        test_client=test_client,
        active_api_key=active_api_key,
        tool="verify_identity",
        raw_text=raw_text,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "allow"
    assert body["policy_id"] == "tool-access"
    assert body["raw_text_out"] == raw_text


def test_unknown_tool_uses_default_redaction(test_client, active_api_key):
    response = _precheck(
        test_client=test_client,
        active_api_key=active_api_key,
        tool="unknown.tool",
        raw_text="Unknown tool sent jane@example.com to a third party.",
    )

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "transform"
    assert body["policy_id"] == "strict-fallback"
    assert "<USER_EMAIL>" in body["raw_text_out"]
    assert "jane@example.com" not in body["raw_text_out"]
    assert "pii.redacted:email_address" in (body.get("reasons") or [])
