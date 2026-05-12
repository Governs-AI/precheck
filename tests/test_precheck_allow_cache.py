# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""HTTP-level tests for cached allow decisions on /api/v1/precheck."""

import pytest

from app.decision_cache import allow_decision_cache
from app.rate_limit import rate_limiter

PRECHECK_URL = "/api/v1/precheck"
VALID_PAYLOAD = {
    "tool": "model.chat",
    "scope": "net.external",
    "raw_text": "Cache this exact message.",
    "policy_config": {"version": "policy-v1"},
}


@pytest.fixture(autouse=True)
def _reset_runtime_state():
    allow_decision_cache.clear()
    rate_limiter.clear()
    yield
    allow_decision_cache.clear()
    rate_limiter.clear()


@pytest.fixture(autouse=True)
def _stub_side_effects(monkeypatch):
    async def _noop_emit_event(*_args, **_kwargs):
        return None

    monkeypatch.setattr("app.api.emit_event", _noop_emit_event)
    monkeypatch.setattr("app.api.audit_log", lambda *_args, **_kwargs: None)


def test_identical_allow_request_hits_cache_within_ttl(
    test_client, active_api_key, monkeypatch
):
    calls = {"count": 0}

    def fake_evaluate_with_payload_policy(**_kwargs):
        calls["count"] += 1
        return {
            "decision": "allow",
            "raw_text_out": VALID_PAYLOAD["raw_text"],
            "reasons": ["policy.allow"],
            "policy_id": "tool-access",
            "ts": 1000,
        }

    monkeypatch.setattr(
        "app.api.evaluate_with_payload_policy", fake_evaluate_with_payload_policy
    )

    headers = {"X-Governs-Key": active_api_key.key}
    first = test_client.post(PRECHECK_URL, json=VALID_PAYLOAD, headers=headers)
    second = test_client.post(PRECHECK_URL, json=VALID_PAYLOAD, headers=headers)

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.headers["x-cache"] == "MISS"
    assert second.headers["x-cache"] == "HIT"
    assert first.json() == second.json()
    assert calls["count"] == 1


def test_transform_decisions_are_never_cached(test_client, active_api_key, monkeypatch):
    calls = {"count": 0}

    def fake_evaluate_with_payload_policy(**_kwargs):
        calls["count"] += 1
        return {
            "decision": "transform",
            "raw_text_out": "[REDACTED]",
            "reasons": ["pii.redacted:PII:email_address"],
            "policy_id": "tool-access",
            "ts": 1000 + calls["count"],
        }

    monkeypatch.setattr(
        "app.api.evaluate_with_payload_policy", fake_evaluate_with_payload_policy
    )

    headers = {"X-Governs-Key": active_api_key.key}
    first = test_client.post(PRECHECK_URL, json=VALID_PAYLOAD, headers=headers)
    second = test_client.post(PRECHECK_URL, json=VALID_PAYLOAD, headers=headers)

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.headers["x-cache"] == "MISS"
    assert second.headers["x-cache"] == "MISS"
    assert calls["count"] == 2


def test_allow_cache_expires_after_ttl(test_client, active_api_key, monkeypatch):
    calls = {"count": 0}
    now = [1000.0]

    def fake_evaluate_with_payload_policy(**_kwargs):
        calls["count"] += 1
        return {
            "decision": "allow",
            "raw_text_out": VALID_PAYLOAD["raw_text"],
            "reasons": ["policy.allow"],
            "policy_id": "tool-access",
            "ts": 1000 + calls["count"],
        }

    monkeypatch.setattr(
        "app.api.evaluate_with_payload_policy", fake_evaluate_with_payload_policy
    )
    monkeypatch.setattr("app.decision_cache.time.time", lambda: now[0])

    headers = {"X-Governs-Key": active_api_key.key}
    first = test_client.post(PRECHECK_URL, json=VALID_PAYLOAD, headers=headers)
    second = test_client.post(PRECHECK_URL, json=VALID_PAYLOAD, headers=headers)
    now[0] = 1061.0
    third = test_client.post(PRECHECK_URL, json=VALID_PAYLOAD, headers=headers)

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 200
    assert first.headers["x-cache"] == "MISS"
    assert second.headers["x-cache"] == "HIT"
    assert third.headers["x-cache"] == "MISS"
    assert calls["count"] == 2
