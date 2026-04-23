# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""T-3 HTTP-level 429 integration tests for rate limiting."""

import pytest

from app.rate_limit import rate_limiter

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
    """Clear the in-memory rate limiter state before each test.

    The rate limiter is a module-level singleton.  Without this, request
    counts from other tests in the same process accumulate and trip the
    limit before the 100-request mark.
    """
    rate_limiter.clear()
    yield
    rate_limiter.clear()


@pytest.mark.parametrize("endpoint", RATE_LIMITED_ENDPOINTS)
def test_rate_limit_returns_429_after_100_requests(
    endpoint, test_client, active_api_key
):
    """First 100 requests must succeed; the 101st must return 429."""
    headers = {"X-Governs-Key": active_api_key.key}

    for i in range(1, 101):
        resp = test_client.post(endpoint, json=VALID_PAYLOAD, headers=headers)
        assert (
            resp.status_code == 200
        ), f"Expected 200 on request {i}, got {resp.status_code}: {resp.text}"

    # 101st request must be rate-limited
    resp = test_client.post(endpoint, json=VALID_PAYLOAD, headers=headers)
    assert (
        resp.status_code == 429
    ), f"Expected 429 on request 101, got {resp.status_code}: {resp.text}"


@pytest.mark.parametrize("endpoint", RATE_LIMITED_ENDPOINTS)
def test_rate_limit_response_has_retry_after_header(
    endpoint, test_client, active_api_key
):
    """The 429 response must include a Retry-After header."""
    headers = {"X-Governs-Key": active_api_key.key}

    for _ in range(100):
        test_client.post(endpoint, json=VALID_PAYLOAD, headers=headers)

    resp = test_client.post(endpoint, json=VALID_PAYLOAD, headers=headers)
    assert resp.status_code == 429
    assert "retry-after" in {
        k.lower() for k in resp.headers
    }, f"Retry-After header missing from 429 response. Headers: {dict(resp.headers)}"


@pytest.mark.parametrize("endpoint", RATE_LIMITED_ENDPOINTS)
def test_rate_limit_retry_after_matches_sliding_window(
    endpoint, test_client, active_api_key, monkeypatch
):
    """Retry-After should reflect when the oldest in-window request expires."""
    headers = {"X-Governs-Key": active_api_key.key}
    now = [1000.0]
    monkeypatch.setattr("app.rate_limit.time.time", lambda: now[0])

    for _ in range(50):
        resp = test_client.post(endpoint, json=VALID_PAYLOAD, headers=headers)
        assert resp.status_code == 200

    now[0] = 1030.0
    for _ in range(50):
        resp = test_client.post(endpoint, json=VALID_PAYLOAD, headers=headers)
        assert resp.status_code == 200

    resp = test_client.post(endpoint, json=VALID_PAYLOAD, headers=headers)
    assert resp.status_code == 429
    assert (
        resp.headers["retry-after"] == "30"
    ), f"Expected Retry-After: 30, got: {resp.headers.get('retry-after')}"
