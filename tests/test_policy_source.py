# SPDX-License-Identifier: MIT
"""Unit tests for app.policy_source — the TTL-cached org-scoped policy fetcher.

See ADR-005 for design. Tests cover cache hit/miss/expiry, missing-org, priority
ordering, the dashboard-shape → precheck-shape translation, and invalidate().
"""

from __future__ import annotations

import time

import pytest

from app import policy_source
from app.storage import DashboardPolicy


@pytest.fixture(autouse=True)
def _patch_session_local(monkeypatch, db_session):
    """Make policy_source.SessionLocal yield the in-memory test session.

    The fetcher opens its own session each call (and closes it in `finally`),
    so we hand it a callable that returns the shared test session and stub
    out .close() to avoid killing the suite-wide session.
    """

    class _SessionAdapter:
        def __init__(self, sess):
            self._sess = sess

        def __getattr__(self, name):
            return getattr(self._sess, name)

        def close(self):
            # The autouse `_reset_db` fixture in conftest handles teardown.
            return None

    monkeypatch.setattr(
        policy_source, "SessionLocal", lambda: _SessionAdapter(db_session)
    )
    policy_source._clear_for_tests()
    yield
    policy_source._clear_for_tests()


def _make_policy(
    db_session,
    *,
    org_id: str,
    name: str = "p",
    defaults: dict | None = None,
    priority: int = 0,
    is_active: bool = True,
    on_error: str = "block",
    deny_tools=None,
    allow_tools=None,
):
    row = DashboardPolicy(
        id=f"{org_id}-{name}",
        org_id=org_id,
        name=name,
        version="v1",
        defaults=defaults if defaults is not None else {"pii": "redact"},
        tool_access={},
        deny_tools=deny_tools or [],
        allow_tools=allow_tools or [],
        network_scopes=[],
        network_tools=[],
        on_error=on_error,
        is_active=is_active,
        priority=priority,
    )
    db_session.add(row)
    db_session.commit()
    return row


# ─── cache miss + DB fetch ────────────────────────────────────────────────
def test_get_active_policy_returns_none_for_missing_org():
    assert policy_source.get_active_policy("does-not-exist") is None


def test_get_active_policy_fetches_from_db(db_session):
    _make_policy(db_session, org_id="org-1", defaults={"pii": "redact"})
    cfg = policy_source.get_active_policy("org-1")

    assert cfg is not None
    assert cfg["defaults"]["ingress"]["action"] == "redact"
    assert cfg["defaults"]["egress"]["action"] == "redact"
    assert cfg["on_error"] == "block"
    assert cfg["_policy_id"] == "org-1-p"


def test_pii_block_maps_to_deny(db_session):
    _make_policy(db_session, org_id="org-2", defaults={"pii": "block"})
    cfg = policy_source.get_active_policy("org-2")
    assert cfg["defaults"]["ingress"]["action"] == "deny"
    assert cfg["defaults"]["egress"]["action"] == "deny"


def test_pii_tokenize_maps_through(db_session):
    _make_policy(db_session, org_id="org-3", defaults={"pii": "tokenize"})
    cfg = policy_source.get_active_policy("org-3")
    assert cfg["defaults"]["ingress"]["action"] == "tokenize"


def test_pii_allow_maps_to_pass_through(db_session):
    _make_policy(db_session, org_id="org-4", defaults={"pii": "allow"})
    cfg = policy_source.get_active_policy("org-4")
    assert cfg["defaults"]["ingress"]["action"] == "pass_through"


def test_unknown_pii_action_falls_back_to_redact(db_session):
    _make_policy(db_session, org_id="org-5", defaults={"pii": "shrug"})
    cfg = policy_source.get_active_policy("org-5")
    assert cfg["defaults"]["ingress"]["action"] == "redact"


# ─── priority order ───────────────────────────────────────────────────────
def test_highest_priority_active_policy_wins(db_session):
    _make_policy(
        db_session, org_id="org-9", name="lo", defaults={"pii": "redact"}, priority=1
    )
    _make_policy(
        db_session, org_id="org-9", name="hi", defaults={"pii": "block"}, priority=10
    )
    cfg = policy_source.get_active_policy("org-9")
    # priority=10 ("block") must beat priority=1 ("redact")
    assert cfg["defaults"]["ingress"]["action"] == "deny"
    assert cfg["_policy_name"] == "hi"


def test_inactive_policy_ignored(db_session):
    _make_policy(
        db_session,
        org_id="org-10",
        name="dead",
        defaults={"pii": "block"},
        priority=999,
        is_active=False,
    )
    _make_policy(
        db_session,
        org_id="org-10",
        name="live",
        defaults={"pii": "redact"},
        priority=1,
        is_active=True,
    )
    cfg = policy_source.get_active_policy("org-10")
    assert cfg["_policy_name"] == "live"


# ─── cache behavior ───────────────────────────────────────────────────────
def test_cache_hit_does_not_requery_db(db_session, monkeypatch):
    _make_policy(db_session, org_id="org-h", defaults={"pii": "redact"})
    # first call → miss
    policy_source.get_active_policy("org-h")

    calls = {"n": 0}
    real_fetch = policy_source._fetch_from_db

    def spy(org_id):
        calls["n"] += 1
        return real_fetch(org_id)

    monkeypatch.setattr(policy_source, "_fetch_from_db", spy)

    # second + third calls within TTL → must NOT hit the spy
    policy_source.get_active_policy("org-h")
    policy_source.get_active_policy("org-h")
    assert calls["n"] == 0


def test_invalidate_forces_refetch(db_session):
    _make_policy(db_session, org_id="org-i", defaults={"pii": "redact"})
    first = policy_source.get_active_policy("org-i")
    assert first["defaults"]["ingress"]["action"] == "redact"

    # mutate the underlying row
    row = (
        db_session.query(DashboardPolicy)
        .filter(DashboardPolicy.org_id == "org-i")
        .one()
    )
    row.defaults = {"pii": "block"}
    db_session.commit()

    # without invalidation, the cache should still serve the old value
    cached = policy_source.get_active_policy("org-i")
    assert (
        cached["defaults"]["ingress"]["action"] == "redact"
    ), "cache should still hold stale entry"

    # invalidate → next call refetches and reflects the change
    policy_source.invalidate("org-i")
    refreshed = policy_source.get_active_policy("org-i")
    assert refreshed["defaults"]["ingress"]["action"] == "deny"


def test_invalidate_unknown_org_is_noop():
    # Must not raise.
    policy_source.invalidate("never-cached")
    policy_source.invalidate(None)


def test_ttl_expiry_forces_refetch(db_session, monkeypatch):
    monkeypatch.setenv("POLICY_CACHE_TTL_S", "1")
    _make_policy(db_session, org_id="org-t", defaults={"pii": "redact"})

    policy_source.get_active_policy("org-t")
    # advance the clock past TTL
    base = time.monotonic()
    monkeypatch.setattr(time, "monotonic", lambda: base + 5)

    # mutate the row; without a hit-spy, the new value proves a refetch happened
    row = (
        db_session.query(DashboardPolicy)
        .filter(DashboardPolicy.org_id == "org-t")
        .one()
    )
    row.defaults = {"pii": "block"}
    db_session.commit()

    refreshed = policy_source.get_active_policy("org-t")
    assert refreshed["defaults"]["ingress"]["action"] == "deny"


# ─── translation surface ──────────────────────────────────────────────────
def test_translation_preserves_arrays_and_on_error(db_session):
    _make_policy(
        db_session,
        org_id="org-x",
        deny_tools=["python.exec"],
        allow_tools=["chat"],
        defaults={"pii": "redact"},
        on_error="pass",
    )
    cfg = policy_source.get_active_policy("org-x")
    assert cfg["deny_tools"] == ["python.exec"]
    assert cfg["allow_tools"] == ["chat"]
    assert cfg["on_error"] == "pass"


def test_translation_forwards_unknown_default_keys(db_session):
    _make_policy(
        db_session,
        org_id="org-y",
        defaults={"pii": "redact", "future_knob": "value"},
    )
    cfg = policy_source.get_active_policy("org-y")
    assert cfg["defaults"]["future_knob"] == "value"


# ─── observability ────────────────────────────────────────────────────────
def test_cache_stats_increments(db_session):
    _make_policy(db_session, org_id="org-s", defaults={"pii": "redact"})
    s0 = policy_source.cache_stats()
    policy_source.get_active_policy("org-s")  # miss
    policy_source.get_active_policy("org-s")  # hit
    policy_source.invalidate("org-s")
    s1 = policy_source.cache_stats()

    assert s1["miss"] >= s0["miss"] + 1
    assert s1["hit"] >= s0["hit"] + 1
    assert s1["invalidate"] >= s0["invalidate"] + 1
