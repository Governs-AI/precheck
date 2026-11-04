# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""Precheck fails closed when the policy store is unreachable.

A store error used to look exactly like "this org has no policy", so the
evaluator fell back to the caller's `policy_config` — a caller could send
`pass_through` and have card numbers go out unredacted during an outage.
These tests pin the store raising PolicyStoreUnavailable, failures not being
cached, the last known org policy being served when one is cached, and the
evaluator using a server-side redacting (or denying) policy otherwise.
"""

from datetime import datetime

import pytest

from app import policy_source
from app.decision_cache import allow_decision_cache
from app.key_utils import hash_api_key
from app.policies import (
    STORE_UNAVAILABLE_REASON,
    evaluate_with_payload_policy,
)
from app.rate_limit import rate_limiter
from app.settings import Settings, settings
from app.storage import APIKey, DashboardPolicy

ORG = "org-outage"
CARD = "4111 1111 1111 1111"
CARD_TEXT = f"Charge card {CARD} for jane.doe@example.com"
PERMISSIVE = {
    "defaults": {"ingress": {"action": "pass_through"}},
    "tool_access": {"email_send": {"action": "allow", "direction": "both"}},
    "deny_tools": [],
}


class _SessionAdapter:
    """Hand the shared test session to policy_source without closing it."""

    def __init__(self, sess):
        self._sess = sess

    def __getattr__(self, name):
        return getattr(self._sess, name)

    def close(self):
        return None


class _BrokenSession:
    def query(self, *_args, **_kwargs):
        raise RuntimeError("connection refused")

    def close(self):
        return None


@pytest.fixture
def store(monkeypatch, db_session):
    """Switch policy_source between a working and an unreachable store."""
    state = {"up": True, "connect_fails": False}

    def session_local():
        if state["up"]:
            return _SessionAdapter(db_session)
        if state["connect_fails"]:
            raise RuntimeError("could not connect to server")
        return _BrokenSession()

    monkeypatch.setattr(policy_source, "SessionLocal", session_local)
    policy_source._clear_for_tests()
    yield state
    policy_source._clear_for_tests()


def _add_policy(db_session, **overrides):
    fields = dict(
        id="pol-outage",
        org_id=ORG,
        name="org policy",
        version="v1",
        defaults={"ingress": {"action": "block"}, "egress": {"action": "block"}},
        tool_access={},
        deny_tools=[],
        allow_tools=[],
        network_scopes=[],
        network_tools=[],
        on_error="block",
        is_active=True,
        priority=0,
        updated_at=datetime(2026, 11, 1, 8, 0, 0),
    )
    fields.update(overrides)
    db_session.add(DashboardPolicy(**fields))
    db_session.commit()


def _eval(tool="email_send", scope="net.external", text=CARD_TEXT, **kw):
    return evaluate_with_payload_policy(
        tool=tool, scope=scope, raw_text=text, now=1000, org_id=ORG, **kw
    )


# ─── policy_source ────────────────────────────────────────────────────────
@pytest.mark.parametrize("connect_fails", [False, True])
def test_store_error_raises_instead_of_reporting_no_policy(store, connect_fails):
    store.update(up=False, connect_fails=connect_fails)

    with pytest.raises(policy_source.PolicyStoreUnavailable):
        policy_source.get_active_policy(ORG)
    assert policy_source.cache_stats()["unavailable"] == 1


def test_store_failure_is_not_cached(store, db_session):
    _add_policy(db_session)
    store["up"] = False
    with pytest.raises(policy_source.PolicyStoreUnavailable):
        policy_source.get_active_policy(ORG)

    store["up"] = True
    cfg = policy_source.get_active_policy(ORG)

    assert cfg is not None
    assert cfg["_policy_id"] == "pol-outage"


def test_last_known_policy_is_served_past_ttl_during_outage(
    store, db_session, monkeypatch
):
    _add_policy(db_session)
    clock = [1000.0]
    monkeypatch.setattr(policy_source.time, "monotonic", lambda: clock[0])
    policy_source.get_active_policy(ORG)

    clock[0] += 3600
    store["up"] = False
    cfg = policy_source.get_active_policy(ORG)

    assert cfg["_policy_id"] == "pol-outage"
    assert policy_source.cache_stats()["stale"] == 1


def test_cached_no_policy_is_not_reused_during_outage(store, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(policy_source.time, "monotonic", lambda: clock[0])
    assert policy_source.get_active_policy(ORG) is None

    clock[0] += 3600
    store["up"] = False

    with pytest.raises(policy_source.PolicyStoreUnavailable):
        policy_source.get_active_policy(ORG)


# ─── evaluator ────────────────────────────────────────────────────────────
@pytest.mark.parametrize("scope", ["net.external", "local"])
def test_outage_ignores_permissive_caller_policy_and_redacts(store, scope):
    store["up"] = False

    result = _eval(scope=scope, policy_config=PERMISSIVE)

    assert result["decision"] == "transform"
    assert CARD not in result["raw_text_out"]
    assert "jane.doe@example.com" not in result["raw_text_out"]
    assert result["reasons"][0] == STORE_UNAVAILABLE_REASON
    assert any("credit_card" in r for r in result["reasons"])


def test_outage_still_denies_code_execution_tools(store):
    store["up"] = False

    result = _eval(tool="bash.exec", scope="local", text="ls", policy_config=PERMISSIVE)

    assert result["decision"] == "deny"
    assert result["policy_id"] == "deny-exec"


def test_outage_deny_mode_rejects_the_request(store, monkeypatch):
    monkeypatch.setattr(settings, "policy_store_fail_mode", "deny")
    store["up"] = False

    result = _eval(policy_config=PERMISSIVE)

    assert result["decision"] == "deny"
    assert result["reasons"] == [STORE_UNAVAILABLE_REASON, "default.ingress.deny"]


def test_outage_with_cached_org_policy_uses_the_org_policy(
    store, db_session, monkeypatch
):
    _add_policy(db_session)
    clock = [1000.0]
    monkeypatch.setattr(policy_source.time, "monotonic", lambda: clock[0])
    policy_source.get_active_policy(ORG)
    clock[0] += 3600
    store["up"] = False

    result = _eval(text="Summarise the notes.", policy_config=PERMISSIVE)

    # The org's block default still applies; nothing about the outage leaks.
    assert result["decision"] == "deny"
    assert result["reasons"] == ["default.ingress.deny"]


def test_org_without_policy_still_uses_caller_policy_when_store_is_up(store):
    result = _eval(text="Summarise the notes.", policy_config=PERMISSIVE)

    assert result["decision"] == "allow"
    assert STORE_UNAVAILABLE_REASON not in (result.get("reasons") or [])


def test_policy_store_fail_mode_is_validated():
    with pytest.raises(ValueError, match="POLICY_STORE_FAIL_MODE"):
        Settings(debug=True, policy_store_fail_mode="pass")


# ─── HTTP ─────────────────────────────────────────────────────────────────
@pytest.fixture
def org_api_key(db_session):
    raw = "GAI_test_outage_org_key_42"
    db_session.add(
        APIKey(
            key_hash=hash_api_key(raw),
            key_prefix=raw[:8],
            user_id="user-outage",
            org_id=ORG,
            is_active=True,
            expires_at=None,
        )
    )
    db_session.commit()
    return raw


@pytest.fixture
def _quiet_runtime(monkeypatch):
    async def _noop_emit_event(*_args, **_kwargs):
        return None

    monkeypatch.setattr("app.api.emit_event", _noop_emit_event)
    monkeypatch.setattr("app.api.audit_log", lambda *_args, **_kwargs: None)
    allow_decision_cache.clear()
    rate_limiter.clear()
    yield
    allow_decision_cache.clear()
    rate_limiter.clear()


def test_precheck_redacts_card_when_store_is_down(
    test_client, org_api_key, store, _quiet_runtime
):
    store["up"] = False
    payload = {
        "tool": "email_send",
        "scope": "net.external",
        "raw_text": CARD_TEXT,
        "policy_config": PERMISSIVE,
    }

    response = test_client.post(
        "/api/v1/precheck", json=payload, headers={"X-Governs-Key": org_api_key}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "transform"
    assert CARD not in body["raw_text_out"]
    assert STORE_UNAVAILABLE_REASON in body["reasons"]


def test_fail_closed_allows_are_not_cached(
    test_client, org_api_key, store, _quiet_runtime
):
    store["up"] = False
    payload = {
        "tool": "model.chat",
        "scope": "net.external",
        "raw_text": "Summarise the release notes.",
        "policy_config": PERMISSIVE,
    }
    headers = {"X-Governs-Key": org_api_key}

    first = test_client.post("/api/v1/precheck", json=payload, headers=headers)
    second = test_client.post("/api/v1/precheck", json=payload, headers=headers)

    assert first.json()["decision"] == "allow"
    assert first.headers["x-cache"] == "MISS"
    assert second.headers["x-cache"] == "MISS"
