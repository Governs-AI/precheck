# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""Regression coverage for precheck policy behavior at the API layer."""

from copy import deepcopy
from pathlib import Path

import pytest
import yaml

PRECHECK_URL = "/api/v1/precheck"
POLICY_PATH = Path(__file__).resolve().parents[2] / "policy.tool_access.yaml"
POLICY = yaml.safe_load(POLICY_PATH.read_text())


def _tool_reason_codes(action, pii_type):
    return {f"{action}:{pii_type}", f"pii.{action}:{pii_type}"}


TOOL_CASES = {
    "verify_identity": {
        "raw_text": "Verify jane@example.com against SSN: 123-45-6789.",
        "decision": "transform",
        "policy_id": "tool-access",
        "contains": ["jane@example.com", "pii_"],
        "not_contains": ["123-45-6789"],
        "reasons": _tool_reason_codes("allowed", "PII:email_address")
        | _tool_reason_codes("tokenized", "PII:us_ssn"),
    },
    "send_marketing_email": {
        "raw_text": "Send the launch note to jane@example.com.",
        "decision": "transform",
        "policy_id": "tool-access",
        "contains": ["jane@example.com"],
        "not_contains": [],
        "reasons": _tool_reason_codes("allowed", "PII:email_address"),
    },
    "data_export": {
        "raw_text": "Export jane@example.com to the reporting system.",
        "decision": "transform",
        "policy_id": "strict-fallback",
        "contains": ["<USER_EMAIL>"],
        "not_contains": ["jane@example.com"],
        "reasons": {"pii.redacted:email_address"},
    },
    "audit_log": {
        "raw_text": "Audit record for jane@example.com.",
        "decision": "transform",
        "policy_id": "strict-fallback",
        "contains": ["<USER_EMAIL>"],
        "not_contains": ["jane@example.com"],
        "reasons": {"pii.redacted:email_address"},
    },
}


@pytest.fixture(autouse=True)
def _force_regex_fallback(monkeypatch):
    monkeypatch.setattr("app.policies.USE_PRESIDIO", False)
    monkeypatch.setattr("app.policies.ANALYZER", None)


def _precheck(
    test_client,
    active_api_key,
    tool,
    raw_text,
    *,
    dynamic_policy=False,
    tool_config=None,
    budget_context=None,
    user_id=None,
):
    payload = {"tool": tool, "raw_text": raw_text}
    if dynamic_policy:
        payload["policy_config"] = deepcopy(POLICY)
    if tool_config is not None:
        payload["tool_config"] = tool_config
    if budget_context is not None:
        payload["budget_context"] = budget_context
    if user_id is not None:
        payload["user_id"] = user_id

    return test_client.post(
        PRECHECK_URL,
        headers={"X-Governs-Key": active_api_key.key},
        json=payload,
    )


def _assert_reason_set(body, expected_reasons):
    # Order is not audit-significant here; we only care that both contracts exist.
    assert set(body.get("reasons") or []) == expected_reasons


def test_tool_cases_cover_every_declared_policy_tool():
    assert set(TOOL_CASES) == set(POLICY["tool_access"])


@pytest.mark.parametrize("tool_name", sorted(TOOL_CASES))
def test_precheck_static_yaml_matches_expected_policy_per_declared_tool(
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

    _assert_reason_set(body, case["reasons"])


@pytest.mark.parametrize("tool_name", sorted(TOOL_CASES))
def test_declared_tools_match_between_static_and_dynamic_policy_paths(
    tool_name, test_client, active_api_key
):
    case = TOOL_CASES[tool_name]

    static_response = _precheck(
        test_client=test_client,
        active_api_key=active_api_key,
        tool=tool_name,
        raw_text=case["raw_text"],
    )
    dynamic_response = _precheck(
        test_client=test_client,
        active_api_key=active_api_key,
        tool=tool_name,
        raw_text=case["raw_text"],
        dynamic_policy=True,
    )

    assert static_response.status_code == 200
    assert dynamic_response.status_code == 200
    static_body = static_response.json()
    dynamic_body = dynamic_response.json()

    assert static_body["decision"] == dynamic_body["decision"] == case["decision"]
    assert static_body["policy_id"] == dynamic_body["policy_id"] == case["policy_id"]
    assert static_body["raw_text_out"] == dynamic_body["raw_text_out"]
    _assert_reason_set(static_body, case["reasons"])
    _assert_reason_set(dynamic_body, case["reasons"])


@pytest.mark.parametrize("dynamic_policy", [False, True])
def test_clean_text_allows_known_ingress_tool(
    dynamic_policy, test_client, active_api_key
):
    raw_text = "Plain operational status update with no PII."

    response = _precheck(
        test_client=test_client,
        active_api_key=active_api_key,
        tool="verify_identity",
        raw_text=raw_text,
        dynamic_policy=dynamic_policy,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "allow"
    assert body["policy_id"] == "tool-access"
    assert body["raw_text_out"] == raw_text


@pytest.mark.parametrize("dynamic_policy", [False, True])
def test_unknown_tool_uses_documented_default_redaction_reasons(
    dynamic_policy, test_client, active_api_key
):
    response = _precheck(
        test_client=test_client,
        active_api_key=active_api_key,
        tool="unknown.tool",
        raw_text="Unknown tool sent jane@example.com to a third party.",
        dynamic_policy=dynamic_policy,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "transform"
    assert body["policy_id"] == "strict-fallback"
    assert body["reasons"] == ["pii.redacted:email_address"]
    assert "<USER_EMAIL>" in body["raw_text_out"]
    assert "jane@example.com" not in body["raw_text_out"]


def test_static_yaml_budget_enforcement_matches_dynamic_payload(
    test_client, active_api_key
):
    raw_text = "Budget gate this purchase request."
    tool_config = {
        "tool_name": "verify_identity",
        "direction": "ingress",
        "metadata": {"purchase_amount": 25.0},
    }
    budget_context = {
        "monthly_limit": 10.0,
        "current_spend": 9.0,
        "llm_spend": 9.0,
        "purchase_spend": 0.0,
        "remaining_budget": 1.0,
        "budget_type": "user",
    }

    static_response = _precheck(
        test_client=test_client,
        active_api_key=active_api_key,
        tool="verify_identity",
        raw_text=raw_text,
        tool_config=tool_config,
        budget_context=budget_context,
        user_id="user-budget-1",
    )
    dynamic_response = _precheck(
        test_client=test_client,
        active_api_key=active_api_key,
        tool="verify_identity",
        raw_text=raw_text,
        dynamic_policy=True,
        tool_config=tool_config,
        budget_context=budget_context,
        user_id="user-budget-1",
    )

    assert static_response.status_code == 200
    assert dynamic_response.status_code == 200

    for body in (static_response.json(), dynamic_response.json()):
        assert body["decision"] == "deny"
        assert body["policy_id"] == "budget-check"
        assert body["reasons"] == ["budget_exceeded"]
        assert body["raw_text_out"] == raw_text


@pytest.mark.parametrize(
    "raw_text",
    [
        "Verify jane@example.com against SSN: 123-45-6789.",
        "Verify jane@example.com against SSN 123456789.",
    ],
)
def test_verify_identity_tokenizes_ssn_shapes_on_both_paths(
    raw_text, test_client, active_api_key
):
    static_response = _precheck(
        test_client=test_client,
        active_api_key=active_api_key,
        tool="verify_identity",
        raw_text=raw_text,
    )
    dynamic_response = _precheck(
        test_client=test_client,
        active_api_key=active_api_key,
        tool="verify_identity",
        raw_text=raw_text,
        dynamic_policy=True,
    )

    assert static_response.status_code == 200
    assert dynamic_response.status_code == 200
    static_body = static_response.json()
    dynamic_body = dynamic_response.json()
    expected_reasons = _tool_reason_codes("allowed", "PII:email_address") | _tool_reason_codes(
        "tokenized", "PII:us_ssn"
    )

    assert static_body["raw_text_out"] == dynamic_body["raw_text_out"]
    for body in (static_body, dynamic_body):
        assert body["decision"] == "transform"
        assert "jane@example.com" in body["raw_text_out"]
        assert "pii_" in body["raw_text_out"]
        assert "123-45-6789" not in body["raw_text_out"]
        assert "123456789" not in body["raw_text_out"]
        _assert_reason_set(body, expected_reasons)
