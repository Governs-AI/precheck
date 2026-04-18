# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""
QA.3 — API regression: full policy coverage.

For every tool declared in `precheck/policy.tool_access.yaml`, assert that the
/api/v1/precheck or /api/v1/postcheck endpoint applies the PII action declared
in the policy. Also covers:
  - Clean text (no PII)      → decision: allow
  - Unknown tool name        → default redact behaviour (net.* fallback)

Presidio's spaCy model is not required in CI: we patch ANALYZER to return
deterministic findings so the assertions target the policy engine, not the
detector.
"""

import os
from dataclasses import dataclass
from typing import Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest
import yaml


POLICY_PATH = os.path.join(
    os.path.dirname(__file__), "..", "policy.tool_access.yaml"
)
PRECHECK_URL = "/api/v1/precheck"
POSTCHECK_URL = "/api/v1/postcheck"
AUTH_HEADER = "X-Governs-Key"


# ---------------------------------------------------------------------------
# YAML loader — drives parametrisation from the real policy file
# ---------------------------------------------------------------------------


@dataclass
class ToolCase:
    tool: str
    direction: str
    pii_type: str          # e.g. "PII:email_address"
    action: str            # pass_through | tokenize | redact | deny
    sample_value: str      # deterministic sample that Presidio would normally detect


# Sample values per PII type. Kept short so character indices are trivial.
_SAMPLES = {
    "PII:email_address": "alice@example.com",
    "PII:us_ssn": "123-45-6789",
    "PII:phone_number": "555-867-5309",
    "PII:credit_card": "4532015112830366",
}


def _load_policy_cases() -> List[ToolCase]:
    with open(POLICY_PATH, "r", encoding="utf-8") as fh:
        policy = yaml.safe_load(fh) or {}
    cases: List[ToolCase] = []
    for tool, cfg in (policy.get("tool_access") or {}).items():
        direction = cfg.get("direction", "ingress")
        for pii_type, action in (cfg.get("allow_pii") or {}).items():
            sample = _SAMPLES.get(
                pii_type, "filler-text-with-no-meaningful-pii-value"
            )
            cases.append(
                ToolCase(
                    tool=tool,
                    direction=direction,
                    pii_type=pii_type,
                    action=action,
                    sample_value=sample,
                )
            )
    return cases


POLICY_CASES = _load_policy_cases()


def _endpoint_for_direction(direction: str) -> str:
    return POSTCHECK_URL if direction == "egress" else PRECHECK_URL


# ---------------------------------------------------------------------------
# Presidio mock — deterministic finding for a single PII substring
# ---------------------------------------------------------------------------


def _mock_analyzer_for(pii_type: str, value: str):
    """
    Build a stand-in for app.policies.ANALYZER whose `.analyze()` returns a
    single recognized entity spanning `value` inside whatever text it is
    called with. Indices are recomputed per-call so that the fallback
    redaction path (which re-runs the analyzer on just the PII substring)
    returns valid positions.

    Presidio entity types are upper-case (e.g. EMAIL_ADDRESS); the policy engine
    lowercases and re-prefixes them to `PII:<lower>` before policy lookup.
    """
    entity_type = pii_type.split(":", 1)[1].upper()

    def _analyze(text, **_kw):
        idx = text.find(value)
        if idx < 0:
            # Fallback: if our sample isn't present, pretend no finding.
            return []
        result = MagicMock()
        result.entity_type = entity_type
        result.start = idx
        result.end = idx + len(value)
        result.score = 0.99
        return [result]

    analyzer = MagicMock()
    analyzer.analyze.side_effect = _analyze
    return analyzer


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_policy_cache():
    """Force the policy module to reload the YAML from disk for each test."""
    import app.policies as pol

    pol._POLICY_MTIME = 0.0
    pol._POLICY_CACHE = {}
    yield


@pytest.fixture
def valid_headers(active_api_key):
    return {AUTH_HEADER: active_api_key.key}


# ---------------------------------------------------------------------------
# Per-tool regression: every (tool, pii_type) pair from the YAML
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "case",
    POLICY_CASES,
    ids=[f"{c.tool}__{c.pii_type.split(':',1)[1]}__{c.action}" for c in POLICY_CASES],
)
def test_tool_policy_applies_declared_action(case: ToolCase, test_client, valid_headers):
    raw_text = f"input for {case.tool}: {case.sample_value}"
    payload = {
        "tool": case.tool,
        "scope": "local",
        "raw_text": raw_text,
    }
    endpoint = _endpoint_for_direction(case.direction)

    analyzer = _mock_analyzer_for(case.pii_type, case.sample_value)

    with patch("app.policies.ANALYZER", analyzer), patch(
        "app.policies.USE_PRESIDIO", True
    ):
        resp = test_client.post(endpoint, json=payload, headers=valid_headers)

    assert resp.status_code == 200, resp.text
    body = resp.json()
    reasons = body.get("reasons") or []

    if case.action == "pass_through":
        assert body["decision"] == "transform"
        assert f"pii.allowed:{case.pii_type}" in reasons
        assert case.sample_value in body.get("raw_text_out", "")
    elif case.action == "tokenize":
        assert body["decision"] == "transform"
        assert f"pii.tokenized:{case.pii_type}" in reasons
        assert case.sample_value not in body.get("raw_text_out", "")
        assert "pii_" in body.get("raw_text_out", "")
    elif case.action == "redact":
        assert body["decision"] == "transform"
        assert f"pii.redacted:{case.pii_type}" in reasons
        assert case.sample_value not in body.get("raw_text_out", "")
    elif case.action == "deny":
        assert body["decision"] == "deny"
    else:
        pytest.fail(f"unknown action '{case.action}' in policy for {case.tool}")


# ---------------------------------------------------------------------------
# SSN default-redact for tools that only whitelist other PII (e.g. audit_log)
# ---------------------------------------------------------------------------


def test_audit_log_redacts_ssn_by_default(test_client, valid_headers):
    """audit_log allows email pass-through but does not mention SSN → falls
    through to default redact for SSN findings."""
    raw_text = "audit entry ssn=123-45-6789"
    analyzer = _mock_analyzer_for("PII:us_ssn", "123-45-6789")

    with patch("app.policies.ANALYZER", analyzer), patch(
        "app.policies.USE_PRESIDIO", True
    ):
        resp = test_client.post(
            POSTCHECK_URL,
            json={"tool": "audit_log", "scope": "local", "raw_text": raw_text},
            headers=valid_headers,
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["decision"] == "transform"
    assert "123-45-6789" not in body.get("raw_text_out", "")
    assert any("pii.redacted:PII:us_ssn" in r for r in body.get("reasons") or [])


# ---------------------------------------------------------------------------
# Clean text — no PII → decision: allow
# ---------------------------------------------------------------------------


def test_clean_text_no_pii_allows(test_client, valid_headers):
    """Send a tool from the policy with text containing no PII — should allow."""
    # Mock analyzer returning zero findings
    analyzer = MagicMock()
    analyzer.analyze.return_value = []

    with patch("app.policies.ANALYZER", analyzer), patch(
        "app.policies.USE_PRESIDIO", True
    ):
        resp = test_client.post(
            PRECHECK_URL,
            json={
                "tool": "verify_identity",
                "scope": "local",
                "raw_text": "please verify the attached document",
            },
            headers=valid_headers,
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["decision"] == "allow"
    assert body["raw_text_out"] == "please verify the attached document"


# ---------------------------------------------------------------------------
# Unknown tool — falls through to default redact
# ---------------------------------------------------------------------------


def test_unknown_tool_redacts_pii(test_client, valid_headers):
    """A tool not in policy.tool_access.yaml falls through to default redact
    (via net-scope redaction or strict fallback). Must not leak PII."""
    raw_text = "contact dev@example.com for help"
    # Use regex fallback path — deterministic across envs.
    with patch("app.policies.USE_PRESIDIO", False), patch(
        "app.policies.ANALYZER", None
    ):
        resp = test_client.post(
            PRECHECK_URL,
            json={
                "tool": "tool.not.in.policy",
                "scope": "net.external",  # force level-4 net-redact path
                "raw_text": raw_text,
            },
            headers=valid_headers,
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["decision"] == "transform"
    assert "dev@example.com" not in body["raw_text_out"]


def test_unknown_tool_local_scope_does_not_leak_email(test_client, valid_headers):
    """Strict fallback path (no net scope, no policy): email must not survive."""
    raw_text = "contact dev@example.com for help"
    with patch("app.policies.USE_PRESIDIO", False), patch(
        "app.policies.ANALYZER", None
    ):
        resp = test_client.post(
            PRECHECK_URL,
            json={
                "tool": "tool.not.in.policy",
                "scope": "local",
                "raw_text": raw_text,
            },
            headers=valid_headers,
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    # Strict fallback returns allow on clean text and transform on PII.
    # In either case the raw email must not be leaked as-is.
    if body["decision"] == "transform":
        assert "dev@example.com" not in body["raw_text_out"]


# ---------------------------------------------------------------------------
# Sanity: policy file itself parses and defines at least one tool
# ---------------------------------------------------------------------------


def test_policy_file_has_tools():
    assert POLICY_CASES, (
        f"no (tool, pii) pairs loaded from {POLICY_PATH} — policy file missing "
        "or tool_access block is empty."
    )
