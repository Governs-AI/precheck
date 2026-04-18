# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""
QA.1 — Health & readiness endpoints.

Contract:
  * GET /api/v1/health → 200 and `{"ok": true, "service": "governsai-precheck", ...}`
  * GET /api/v1/ready  → 200 and `{"ready": bool, "checks": {...}, ...}`

Neither endpoint requires authentication.
"""

HEALTH_URL = "/api/v1/health"
READY_URL = "/api/v1/ready"


def test_health_returns_ok(test_client):
    resp = test_client.get(HEALTH_URL)
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["service"] == "governsai-precheck"
    assert "version" in body


def test_health_does_not_require_api_key(test_client):
    resp = test_client.get(HEALTH_URL)
    assert resp.status_code == 200


def test_ready_returns_structured_checks(test_client):
    resp = test_client.get(READY_URL)
    assert resp.status_code == 200
    body = resp.json()
    assert "ready" in body
    assert isinstance(body["ready"], bool)
    assert "checks" in body
    assert isinstance(body["checks"], dict)
    # Readiness should at least report on policy + environment
    assert "policy" in body["checks"]
    assert "environment" in body["checks"]


def test_ready_does_not_require_api_key(test_client):
    resp = test_client.get(READY_URL)
    assert resp.status_code == 200
