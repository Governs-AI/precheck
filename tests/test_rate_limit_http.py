# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""
T-3 — HTTP-level 429 integration test for rate limiting.

Verifies that the /api/v1/precheck endpoint enforces the 100 req/60 s
sliding-window rate limit at the HTTP layer:
  - Requests 1-100   → 200
  - Request 101      → 429 with Retry-After header
"""

import pytest

from app.rate_limit import rate_limiter

PRECHECK_URL = "/api/v1/precheck"

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
    with rate_limiter._local_lock:
        rate_limiter._local_windows.clear()
        rate_limiter._local_last_seen.clear()
    yield


def test_precheck_rate_limit_returns_429_after_100_requests(
    test_client, active_api_key
):
    """First 100 requests must succeed; the 101st must return 429."""
    headers = {"X-Governs-Key": active_api_key.key}

    for i in range(1, 101):
        resp = test_client.post(PRECHECK_URL, json=VALID_PAYLOAD, headers=headers)
        assert (
            resp.status_code == 200
        ), f"Expected 200 on request {i}, got {resp.status_code}: {resp.text}"

    # 101st request must be rate-limited
    resp = test_client.post(PRECHECK_URL, json=VALID_PAYLOAD, headers=headers)
    assert (
        resp.status_code == 429
    ), f"Expected 429 on request 101, got {resp.status_code}: {resp.text}"


def test_precheck_rate_limit_response_has_retry_after_header(
    test_client, active_api_key
):
    """The 429 response must include a Retry-After header set to the window (60 s)."""
    headers = {"X-Governs-Key": active_api_key.key}

    for _ in range(100):
        test_client.post(PRECHECK_URL, json=VALID_PAYLOAD, headers=headers)

    resp = test_client.post(PRECHECK_URL, json=VALID_PAYLOAD, headers=headers)
    assert resp.status_code == 429
    assert "retry-after" in {
        k.lower() for k in resp.headers
    }, f"Retry-After header missing from 429 response. Headers: {dict(resp.headers)}"
    assert (
        resp.headers["retry-after"] == "60"
    ), f"Expected Retry-After: 60, got: {resp.headers.get('retry-after')}"
