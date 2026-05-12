# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""HTTP-level tests for the rate-limit middleware (§1.5c).

Verifies:
  * 429 fires when the minute-bucket limit is exceeded
  * Retry-After + X-RateLimit-* headers populate correctly
  * Counter resets after the minute window rolls
  * Token-count limit denies requests independently of the req/min counter
"""

import pytest

from app.rate_limit import rate_limiter
from app.settings import settings

PRECHECK_URL = "/api/v1/precheck"
POSTCHECK_URL = "/api/v1/postcheck"
RATE_LIMITED_ENDPOINTS = [PRECHECK_URL, POSTCHECK_URL]

VALID_PAYLOAD = {
    "tool": "model.chat",
    "scope": "net.external",
    "raw_text": "Rate limit integration test message.",
}


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """The rate limiter is a module-level singleton; clear bucket state
    around each test so counts from other tests don't leak across."""
    rate_limiter.clear()
    yield
    rate_limiter.clear()


@pytest.mark.parametrize("endpoint", RATE_LIMITED_ENDPOINTS)
def test_rate_limit_returns_429_after_100_requests(
    endpoint, test_client, active_api_key, monkeypatch
):
    """First 100 requests in a minute bucket succeed; the 101st returns 429."""
    monkeypatch.setattr("app.rate_limit.time.time", lambda: 1000.0)
    headers = {"X-Governs-Key": active_api_key.key}

    for i in range(1, 101):
        resp = test_client.post(endpoint, json=VALID_PAYLOAD, headers=headers)
        assert (
            resp.status_code == 200
        ), f"Expected 200 on request {i}, got {resp.status_code}: {resp.text}"

    resp = test_client.post(endpoint, json=VALID_PAYLOAD, headers=headers)
    assert resp.status_code == 429, f"Expected 429, got {resp.status_code}"


@pytest.mark.parametrize("endpoint", RATE_LIMITED_ENDPOINTS)
def test_rate_limit_response_has_retry_after_header(
    endpoint, test_client, active_api_key, monkeypatch
):
    monkeypatch.setattr("app.rate_limit.time.time", lambda: 1000.0)
    headers = {"X-Governs-Key": active_api_key.key}

    for _ in range(100):
        test_client.post(endpoint, json=VALID_PAYLOAD, headers=headers)

    resp = test_client.post(endpoint, json=VALID_PAYLOAD, headers=headers)
    assert resp.status_code == 429
    assert "retry-after" in {k.lower() for k in resp.headers}
    assert int(resp.headers["retry-after"]) >= 1


@pytest.mark.parametrize("endpoint", RATE_LIMITED_ENDPOINTS)
def test_successful_response_carries_x_ratelimit_headers(
    endpoint, test_client, active_api_key, monkeypatch
):
    monkeypatch.setattr("app.rate_limit.time.time", lambda: 1000.0)
    headers = {"X-Governs-Key": active_api_key.key}

    resp = test_client.post(endpoint, json=VALID_PAYLOAD, headers=headers)
    assert resp.status_code == 200
    assert "x-ratelimit-limit" in {k.lower() for k in resp.headers}
    assert "x-ratelimit-remaining" in {k.lower() for k in resp.headers}
    assert "x-ratelimit-reset" in {k.lower() for k in resp.headers}


@pytest.mark.parametrize("endpoint", RATE_LIMITED_ENDPOINTS)
def test_x_ratelimit_remaining_decreases_across_requests(
    endpoint, test_client, active_api_key, monkeypatch
):
    monkeypatch.setattr("app.rate_limit.time.time", lambda: 1000.0)
    headers = {"X-Governs-Key": active_api_key.key}

    r1 = test_client.post(endpoint, json=VALID_PAYLOAD, headers=headers)
    r2 = test_client.post(endpoint, json=VALID_PAYLOAD, headers=headers)
    rem1 = int(r1.headers["x-ratelimit-remaining"])
    rem2 = int(r2.headers["x-ratelimit-remaining"])
    assert rem2 < rem1


@pytest.mark.parametrize("endpoint", RATE_LIMITED_ENDPOINTS)
def test_429_when_minute_bucket_rolls_admits_new_requests(
    endpoint, test_client, active_api_key, monkeypatch
):
    """After two full minutes the previous bucket's contribution is gone, so
    fresh requests are admitted again."""
    now = [1000.0]
    monkeypatch.setattr("app.rate_limit.time.time", lambda: now[0])
    headers = {"X-Governs-Key": active_api_key.key}

    # Fill the current bucket to the limit.
    for _ in range(100):
        test_client.post(endpoint, json=VALID_PAYLOAD, headers=headers)
    resp = test_client.post(endpoint, json=VALID_PAYLOAD, headers=headers)
    assert resp.status_code == 429

    # Jump past two full windows — previous bucket is gone entirely.
    now[0] = 1000.0 + 120.0
    resp = test_client.post(endpoint, json=VALID_PAYLOAD, headers=headers)
    assert resp.status_code == 200


def test_token_limit_triggers_429(test_client, active_api_key, monkeypatch):
    """A single large-content request exceeds the configured token limit."""
    monkeypatch.setattr("app.rate_limit.time.time", lambda: 1000.0)
    # Shrink the token budget so one request trips it; content_length gives
    # the estimate so we don't need a huge body.
    monkeypatch.setattr(settings, "rate_limit_tokens_per_minute", 10)

    headers = {"X-Governs-Key": active_api_key.key}
    big_payload = {**VALID_PAYLOAD, "raw_text": "x" * 2000}  # ~500 tokens
    resp = test_client.post(PRECHECK_URL, json=big_payload, headers=headers)
    assert resp.status_code == 429
    assert "retry-after" in {k.lower() for k in resp.headers}


def test_rate_limit_skipped_for_health_endpoint(
    test_client, active_api_key, monkeypatch
):
    """Health probes must not interact with the counter."""
    monkeypatch.setattr("app.rate_limit.time.time", lambda: 1000.0)
    # Fill the key's per-key counter via a precheck endpoint, then confirm
    # /api/v1/health still returns 200.
    headers = {"X-Governs-Key": active_api_key.key}
    for _ in range(100):
        test_client.post(PRECHECK_URL, json=VALID_PAYLOAD, headers=headers)
    assert (
        test_client.post(PRECHECK_URL, json=VALID_PAYLOAD, headers=headers).status_code
        == 429
    )

    health = test_client.get("/api/v1/health")
    assert health.status_code == 200
