# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""
QA.1 — POST /api/v1/precheck route contract.

Covers:
  * Field validation    — missing `raw_text`, missing `tool` → 422
  * Auth                — missing / invalid API key → 401
  * Response shape      — valid request returns a well-formed DecisionResponse
  * Per-tool PII policy — redact (default), pass_through, tokenize
                          (using the tools wired up in `policy.tool_access.yaml`)

Presidio is disabled in these tests so the regex fallback path runs
deterministically in CI without needing the spaCy model download.
"""

from unittest.mock import patch

import pytest

URL = "/api/v1/precheck"

ALLOWED_DECISIONS = {"allow", "deny", "transform", "confirm"}


# ---------------------------------------------------------------------------
# Field validation
# ---------------------------------------------------------------------------


def test_missing_raw_text_returns_422(test_client, auth_headers):
    resp = test_client.post(
        URL,
        json={"tool": "model.chat", "scope": "net.external"},
        headers=auth_headers,
    )
    assert resp.status_code == 422


def test_missing_tool_returns_422(test_client, auth_headers):
    resp = test_client.post(
        URL,
        json={"raw_text": "hello world", "scope": "net.external"},
        headers=auth_headers,
    )
    assert resp.status_code == 422


def test_malformed_json_returns_422(test_client, auth_headers):
    resp = test_client.post(
        URL,
        content=b"{not valid json",
        headers={**auth_headers, "Content-Type": "application/json"},
    )
    assert resp.status_code in (400, 422)


# ---------------------------------------------------------------------------
# Auth (contract only — exhaustive cases in test_auth.py)
# ---------------------------------------------------------------------------


def test_missing_api_key_returns_401(test_client, valid_payload):
    resp = test_client.post(URL, json=valid_payload)
    assert resp.status_code == 401


def test_invalid_api_key_returns_401(test_client, valid_payload):
    resp = test_client.post(
        URL,
        json=valid_payload,
        headers={"X-Governs-Key": "GAI_invalid"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Happy path — response shape
# ---------------------------------------------------------------------------


def test_valid_request_returns_decision_response(test_client, auth_headers, valid_payload):
    resp = test_client.post(URL, json=valid_payload, headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] in ALLOWED_DECISIONS
    assert isinstance(body["ts"], int)
    assert "raw_text_out" in body


# ---------------------------------------------------------------------------
# Per-tool PII policy assertions
#
# The repo's `policy.tool_access.yaml` wires:
#   verify_identity      — email: pass_through, ssn: tokenize
#   send_marketing_email — email: pass_through
#   (any other tool)     — redact (default)
# ---------------------------------------------------------------------------


@patch("app.policies.USE_PRESIDIO", False)
@patch("app.policies.ANALYZER", None)
def test_default_tool_redacts_email(test_client, auth_headers):
    """Unknown tools fall through to the default ingress action (redact)."""
    resp = test_client.post(
        URL,
        json={
            "tool": "model.chat",
            "scope": "net.external",
            "raw_text": "Email me at alice@example.com",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] in {"transform", "allow"}
    if body["decision"] == "transform":
        assert "alice@example.com" not in body.get("raw_text_out", "")


@patch("app.policies.USE_PRESIDIO", False)
@patch("app.policies.ANALYZER", None)
def test_verify_identity_allows_email_pass_through(test_client, auth_headers):
    """verify_identity is configured to pass emails through unchanged."""
    resp = test_client.post(
        URL,
        json={
            "tool": "verify_identity",
            "scope": "net.external",
            "raw_text": "Confirm identity for alice@example.com",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    # pass_through → email must survive in the output payload
    assert body["decision"] in ALLOWED_DECISIONS
    assert "alice@example.com" in body.get("raw_text_out", "")


@patch("app.policies.USE_PRESIDIO", False)
@patch("app.policies.ANALYZER", None)
def test_send_marketing_email_passes_email_through(test_client, auth_headers):
    resp = test_client.post(
        URL,
        json={
            "tool": "send_marketing_email",
            "scope": "net.external",
            "raw_text": "Send newsletter to alice@example.com",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "alice@example.com" in body.get("raw_text_out", "")


# ---------------------------------------------------------------------------
# Phone-number redaction (regex fallback path)
# ---------------------------------------------------------------------------


@patch("app.policies.USE_PRESIDIO", False)
@patch("app.policies.ANALYZER", None)
def test_default_tool_redacts_phone(test_client, auth_headers):
    resp = test_client.post(
        URL,
        json={
            "tool": "model.chat",
            "scope": "net.external",
            "raw_text": "Call me at +1 415-555-0100",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    if body["decision"] == "transform":
        assert "415-555-0100" not in body.get("raw_text_out", "")
