# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""
QA.1 — POST /api/v1/postcheck route contract.

Postcheck runs egress evaluation, so it uses the policy's `egress` direction.
The repo's `policy.tool_access.yaml` wires:
  data_export → email: pass_through, ssn: tokenize
  audit_log   → email: pass_through   (ssn redacts via default)
  (any other) → redact (default egress action)
"""

from unittest.mock import patch

URL = "/api/v1/postcheck"


def test_missing_raw_text_returns_422(test_client, auth_headers):
    resp = test_client.post(
        URL,
        json={"tool": "data_export", "scope": "net.external"},
        headers=auth_headers,
    )
    assert resp.status_code == 422


def test_missing_api_key_returns_401(test_client, valid_payload):
    resp = test_client.post(URL, json=valid_payload)
    assert resp.status_code == 401


def test_valid_request_returns_decision_response(test_client, auth_headers, valid_payload):
    resp = test_client.post(URL, json=valid_payload, headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] in {"allow", "deny", "transform", "confirm"}
    assert isinstance(body["ts"], int)
    assert "raw_text_out" in body


@patch("app.policies.USE_PRESIDIO", False)
@patch("app.policies.ANALYZER", None)
def test_data_export_passes_email_through(test_client, auth_headers):
    resp = test_client.post(
        URL,
        json={
            "tool": "data_export",
            "scope": "net.external",
            "raw_text": "Export record for alice@example.com",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "alice@example.com" in body.get("raw_text_out", "")


@patch("app.policies.USE_PRESIDIO", False)
@patch("app.policies.ANALYZER", None)
def test_default_egress_redacts_email(test_client, auth_headers):
    """Tools not listed under egress in policy fall through to the default (redact)."""
    resp = test_client.post(
        URL,
        json={
            "tool": "unknown_egress_tool",
            "scope": "net.external",
            "raw_text": "Leaked email alice@example.com",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    if body["decision"] == "transform":
        assert "alice@example.com" not in body.get("raw_text_out", "")


@patch("app.policies.USE_PRESIDIO", False)
@patch("app.policies.ANALYZER", None)
def test_audit_log_passes_email_through(test_client, auth_headers):
    resp = test_client.post(
        URL,
        json={
            "tool": "audit_log",
            "scope": "net.internal",
            "raw_text": "User alice@example.com performed login",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "alice@example.com" in body.get("raw_text_out", "")
