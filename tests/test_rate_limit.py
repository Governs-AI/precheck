# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""Unit tests for the minute-bucket sliding-window rate limiter.

Covers the §1.5c requirements directly on ``RateLimiter`` — the HTTP-level
behavior (429, X-RateLimit-* headers) is exercised in test_rate_limit_http.py.
"""

import pytest

from app.rate_limit import (
    LimitSpec,
    RateLimiter,
    WINDOW_SECONDS,
    specs_for_request,
)


def _specs(*, limit: int, cost: int = 1, key: str = "req:key:k1", name: str = "req-key"):
    return [LimitSpec(name=name, key=key, limit=limit, cost=cost)]


# ---------------------------------------------------------------- bucketing


def test_counter_increments_per_request(monkeypatch):
    limiter = RateLimiter(redis_url=None)
    monkeypatch.setattr("app.rate_limit.time.time", lambda: 1000.0)

    r1 = limiter.check(_specs(limit=3))
    r2 = limiter.check(_specs(limit=3))
    r3 = limiter.check(_specs(limit=3))
    r4 = limiter.check(_specs(limit=3))

    assert [r.allowed for r in (r1, r2, r3, r4)] == [True, True, True, False]
    assert [r.states["req-key"].remaining for r in (r1, r2, r3)] == [2, 1, 0]


def test_counter_resets_after_minute_window(monkeypatch):
    limiter = RateLimiter(redis_url=None)
    now = [1000.0]
    monkeypatch.setattr("app.rate_limit.time.time", lambda: now[0])

    assert limiter.check(_specs(limit=1)).allowed is True
    assert limiter.check(_specs(limit=1)).allowed is False

    # Advance exactly one full window — previous bucket's weight drops to
    # zero because elapsed_in_current == 0 gives ratio 1, but we are now in
    # the next bucket entirely.
    now[0] = 1000.0 + WINDOW_SECONDS * 2  # skip prev-bucket entirely

    assert limiter.check(_specs(limit=1)).allowed is True


def test_partial_window_applies_sliding_weight(monkeypatch):
    """A full previous bucket halves its contribution after 30s into the next.

    At t=1000 bucket=16 (1000%60=40, elapsed=40). Fill it completely.
    At t=1060 bucket=17, elapsed=20; previous weight = 50 * (1 - 20/60) ≈ 33.
    Admitting 67 more requests (33 + 67 = 100) should succeed; 68th denies.
    """
    limiter = RateLimiter(redis_url=None)
    now = [960.0]  # bucket 16 start; elapsed_in_current=0
    monkeypatch.setattr("app.rate_limit.time.time", lambda: now[0])

    for _ in range(50):
        assert limiter.check(_specs(limit=50)).allowed is True

    # bucket 17, 20s in — previous contribution ≈ 50 * (40/60) = 33.33
    now[0] = 1040.0
    allowed = 0
    for _ in range(200):
        if limiter.check(_specs(limit=50)).allowed:
            allowed += 1
        else:
            break
    # 50 - 33.33 = 16.67 → floor allows 16 more this bucket.
    assert allowed == 16


# ---------------------------------------------------------------- dimensions


def test_per_key_and_per_org_counters_are_independent(monkeypatch):
    """Same org, different API keys — per-key is cheap, per-org shared."""
    limiter = RateLimiter(redis_url=None)
    monkeypatch.setattr("app.rate_limit.time.time", lambda: 1000.0)

    def specs(key_id: str, org_id: str, req_limit: int, org_limit: int):
        return [
            LimitSpec(
                name="req-key", key=f"req:key:{key_id}", limit=req_limit, cost=1
            ),
            LimitSpec(
                name="req-org", key=f"req:org:{org_id}", limit=org_limit, cost=1
            ),
        ]

    # Key A exhausts its per-key limit (2) but stays under the per-org limit (10).
    assert limiter.check(specs("A", "org1", 2, 10)).allowed is True
    assert limiter.check(specs("A", "org1", 2, 10)).allowed is True
    denied = limiter.check(specs("A", "org1", 2, 10))
    assert denied.allowed is False
    assert denied.states["req-key"].remaining == 0
    # Per-org dim is not the blocker — the blocker is per-key.
    assert denied.states["req-org"].remaining > 0

    # Key B in the same org can still proceed on its own per-key counter.
    assert limiter.check(specs("B", "org1", 2, 10)).allowed is True


def test_org_limit_denies_even_when_per_key_allows(monkeypatch):
    limiter = RateLimiter(redis_url=None)
    monkeypatch.setattr("app.rate_limit.time.time", lambda: 1000.0)

    # Saturate the per-org counter via key A (per-key limit is generous).
    org_specs = lambda key_id: [  # noqa: E731
        LimitSpec(name="req-key", key=f"req:key:{key_id}", limit=10, cost=1),
        LimitSpec(name="req-org", key="req:org:org1", limit=2, cost=1),
    ]
    assert limiter.check(org_specs("A")).allowed is True
    assert limiter.check(org_specs("A")).allowed is True

    # Key B is fresh on per-key but blocked by shared per-org counter.
    result = limiter.check(org_specs("B"))
    assert result.allowed is False
    assert result.states["req-org"].remaining == 0
    assert result.states["req-key"].remaining > 0


def test_token_cost_applied_to_token_counters(monkeypatch):
    limiter = RateLimiter(redis_url=None)
    monkeypatch.setattr("app.rate_limit.time.time", lambda: 1000.0)

    specs = lambda cost: [  # noqa: E731
        LimitSpec(name="tokens-key", key="tokens:key:x", limit=100, cost=cost),
    ]
    assert limiter.check(specs(60)).allowed is True
    # Second request at cost=60 would push to 120, over the 100 limit.
    result = limiter.check(specs(60))
    assert result.allowed is False


# ------------------------------------------------------ specs_for_request


def test_specs_for_request_omits_org_when_none():
    specs = specs_for_request(key_id="kh", org_id=None, token_cost=10)
    names = {s.name for s in specs}
    assert names == {"req-key", "tokens-key"}


def test_specs_for_request_includes_org_when_provided():
    specs = specs_for_request(key_id="kh", org_id="org1", token_cost=10)
    names = {s.name for s in specs}
    assert names == {"req-key", "tokens-key", "req-org", "tokens-org"}


# ----------------------------------------------------------- fail modes


class _FailingPipeline:
    def get(self, *_a, **_kw):
        return self

    def incrby(self, *_a, **_kw):
        return self

    def expire(self, *_a, **_kw):
        return self

    def execute(self):
        raise RuntimeError("redis unavailable")


class _FailingRedis:
    def pipeline(self):
        return _FailingPipeline()


def _install_failing_redis(limiter: RateLimiter) -> None:
    limiter._redis_url_configured = True
    limiter.redis_client = _FailingRedis()


def test_fail_closed_on_redis_outage_returns_fail_closed_reason(monkeypatch):
    limiter = RateLimiter(redis_url=None, fail_mode="closed")
    _install_failing_redis(limiter)
    monkeypatch.setattr("app.rate_limit.time.time", lambda: 1000.0)

    result = limiter.check(_specs(limit=10))
    assert result.allowed is False
    assert result.fail_closed_reason is not None
    assert "redis-error" in result.fail_closed_reason


def test_fail_open_on_redis_outage_allows_request(monkeypatch):
    limiter = RateLimiter(redis_url=None, fail_mode="open")
    _install_failing_redis(limiter)
    monkeypatch.setattr("app.rate_limit.time.time", lambda: 1000.0)

    result = limiter.check(_specs(limit=1))
    assert result.allowed is True
    assert result.fail_closed_reason is None


def test_fail_local_on_redis_outage_uses_in_memory(monkeypatch):
    limiter = RateLimiter(redis_url=None, fail_mode="local")
    _install_failing_redis(limiter)
    monkeypatch.setattr("app.rate_limit.time.time", lambda: 1000.0)

    assert limiter.check(_specs(limit=1)).allowed is True
    assert limiter.check(_specs(limit=1)).allowed is False


def test_no_redis_url_configured_uses_local_regardless_of_fail_mode(monkeypatch):
    """When REDIS_URL was never configured (dev/tests) the limiter runs
    locally and never takes the fail-closed path."""
    limiter = RateLimiter(redis_url=None, fail_mode="closed")
    monkeypatch.setattr("app.rate_limit.time.time", lambda: 1000.0)

    assert limiter.check(_specs(limit=1)).allowed is True


def test_clear_resets_in_memory_state(monkeypatch):
    limiter = RateLimiter(redis_url=None)
    monkeypatch.setattr("app.rate_limit.time.time", lambda: 1000.0)

    assert limiter.check(_specs(limit=1)).allowed is True
    assert limiter.check(_specs(limit=1)).allowed is False
    limiter.clear()
    assert limiter.check(_specs(limit=1)).allowed is True


# --------------------------------------------------------- rejected configs


def test_invalid_fail_mode_rejected():
    with pytest.raises(ValueError, match="rate_limit_fail_mode"):
        RateLimiter(redis_url=None, fail_mode="nonsense")
