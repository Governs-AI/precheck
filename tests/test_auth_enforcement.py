# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""
TEST-3.3 — Auth enforcement tests.

Verifies that require_api_key (wired into /api/v1/precheck and /api/v1/postcheck)
correctly gates requests:
  - Missing header   → 401
  - Invalid key      → 401 (not in DB)
  - Inactive key     → 401 (is_active=False)
  - Expired key      → 401 (expires_at in the past)
  - Valid key        → request proceeds (200 or policy-based response)
"""

import pytest

PRECHECK_URL = "/api/v1/precheck"
HEALTH_URL = "/api/v1/health"

VALID_PAYLOAD = {
    "tool": "model.chat",
    "scope": "net.external",
    "raw_text": "Hello, this is a test message.",
}


# ---------------------------------------------------------------------------
# Health endpoint should be reachable without auth
# ---------------------------------------------------------------------------


def test_health_endpoint_no_auth_required(test_client):
    resp = test_client.get(HEALTH_URL)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Missing API key
# ---------------------------------------------------------------------------


def test_missing_api_key_returns_401(test_client):
    resp = test_client.post(PRECHECK_URL, json=VALID_PAYLOAD)
    assert resp.status_code == 401


def test_empty_api_key_header_returns_401(test_client):
    resp = test_client.post(
        PRECHECK_URL,
        json=VALID_PAYLOAD,
        headers={"X-Governs-Key": ""},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Invalid (unknown) API key
# ---------------------------------------------------------------------------


def test_unknown_api_key_returns_401(test_client):
    resp = test_client.post(
        PRECHECK_URL,
        json=VALID_PAYLOAD,
        headers={"X-Governs-Key": "GAI_not_in_database"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Inactive (revoked) API key
# ---------------------------------------------------------------------------


def test_inactive_key_returns_401(test_client, inactive_api_key):
    resp = test_client.post(
        PRECHECK_URL,
        json=VALID_PAYLOAD,
        headers={"X-Governs-Key": inactive_api_key.key},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Expired API key
# ---------------------------------------------------------------------------


def test_expired_key_returns_401(test_client, expired_api_key):
    resp = test_client.post(
        PRECHECK_URL,
        json=VALID_PAYLOAD,
        headers={"X-Governs-Key": expired_api_key.key},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Valid API key — request proceeds to policy engine
# ---------------------------------------------------------------------------


def test_valid_key_proceeds(test_client, active_api_key):
    resp = test_client.post(
        PRECHECK_URL,
        json=VALID_PAYLOAD,
        headers={"X-Governs-Key": active_api_key.key},
    )
    # Auth passed — policy engine ran and returned a decision
    assert resp.status_code == 200
    body = resp.json()
    assert "decision" in body


def test_valid_key_decision_is_known_type(test_client, active_api_key):
    resp = test_client.post(
        PRECHECK_URL,
        json=VALID_PAYLOAD,
        headers={"X-Governs-Key": active_api_key.key},
    )
    assert resp.status_code == 200
    decision = resp.json()["decision"]
    assert decision in {"allow", "deny", "transform", "confirm", "pass_through"}


# ---------------------------------------------------------------------------
# Error messages — 401 responses should include a detail field
# ---------------------------------------------------------------------------


def test_missing_key_error_body(test_client):
    resp = test_client.post(PRECHECK_URL, json=VALID_PAYLOAD)
    assert resp.status_code == 401
    body = resp.json()
    assert "detail" in body or "error" in body


def test_invalid_key_error_body(test_client):
    resp = test_client.post(
        PRECHECK_URL,
        json=VALID_PAYLOAD,
        headers={"X-Governs-Key": "bad_key"},
    )
    assert resp.status_code == 401
    body = resp.json()
    assert "detail" in body or "error" in body


# ---------------------------------------------------------------------------
# Rotation and revocation endpoints also require auth
# ---------------------------------------------------------------------------


def test_rotate_endpoint_requires_auth(test_client):
    resp = test_client.post("/api/v1/keys/rotate")
    assert resp.status_code == 401


def test_revoke_endpoint_requires_auth(test_client):
    resp = test_client.post("/api/v1/keys/revoke")
    assert resp.status_code == 401
