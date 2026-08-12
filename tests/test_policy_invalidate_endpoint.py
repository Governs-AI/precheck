# SPDX-License-Identifier: MIT
"""HMAC-gated /api/v1/internal/policy/invalidate endpoint tests (ADR-005)."""

from __future__ import annotations

import hashlib
import hmac

from app import policy_source
from app.settings import settings


def _hmac(org_id: str) -> str:
    return hmac.new(
        settings.key_hmac_secret.encode(), org_id.encode(), hashlib.sha256
    ).hexdigest()


def test_invalidate_with_valid_hmac_drops_cache(test_client, monkeypatch):
    # seed a cache entry
    monkeypatch.setattr(policy_source, "_fetch_from_db", lambda _oid: {"x": 1})
    policy_source.get_active_policy("org-z")
    assert policy_source.cache_stats()["entries"] >= 1

    r = test_client.post(
        "/api/v1/internal/policy/invalidate",
        json={"org_id": "org-z"},
        headers={"x-govs-invalidate-hmac": _hmac("org-z")},
    )
    assert r.status_code == 200, r.text
    assert r.json() == {"invalidated": "org-z"}


def test_invalidate_rejects_bad_hmac(test_client):
    r = test_client.post(
        "/api/v1/internal/policy/invalidate",
        json={"org_id": "org-z"},
        headers={"x-govs-invalidate-hmac": "not-a-real-hmac"},
    )
    assert r.status_code == 401


def test_invalidate_rejects_missing_hmac(test_client):
    r = test_client.post(
        "/api/v1/internal/policy/invalidate",
        json={"org_id": "org-z"},
    )
    assert r.status_code == 401


def test_invalidate_requires_org_id(test_client):
    r = test_client.post(
        "/api/v1/internal/policy/invalidate",
        json={},
        headers={"x-govs-invalidate-hmac": _hmac("")},
    )
    assert r.status_code == 400


def test_invalidate_rejects_hmac_signed_for_different_org(test_client):
    r = test_client.post(
        "/api/v1/internal/policy/invalidate",
        json={"org_id": "org-a"},
        headers={"x-govs-invalidate-hmac": _hmac("org-b")},
    )
    assert r.status_code == 401
