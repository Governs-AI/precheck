# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""
QA.1 — API-key gating on /api/v1/precheck and /api/v1/postcheck.

Contract:
  * Missing X-Governs-Key header   → 401
  * Unknown key                    → 401
  * Revoked (inactive) key         → 401
  * Expired key                    → 401
  * Valid key                      → request proceeds (2xx)

Deep auth enforcement lives in `tests/test_auth_enforcement.py`; this file is
the route-contract surface used by QA.1 and read by CI to confirm the two
primary endpoints are always gated.
"""

import pytest

PRECHECK_URL = "/api/v1/precheck"
POSTCHECK_URL = "/api/v1/postcheck"

PAYLOAD = {
    "tool": "model.chat",
    "scope": "net.external",
    "raw_text": "Hello, this is a test message.",
}


@pytest.mark.parametrize("url", [PRECHECK_URL, POSTCHECK_URL])
def test_missing_key_returns_401(test_client, url):
    resp = test_client.post(url, json=PAYLOAD)
    assert resp.status_code == 401


@pytest.mark.parametrize("url", [PRECHECK_URL, POSTCHECK_URL])
def test_unknown_key_returns_401(test_client, url):
    resp = test_client.post(
        url,
        json=PAYLOAD,
        headers={"X-Governs-Key": "GAI_does_not_exist"},
    )
    assert resp.status_code == 401


@pytest.mark.parametrize("url", [PRECHECK_URL, POSTCHECK_URL])
def test_inactive_key_returns_401(test_client, inactive_api_key, url):
    resp = test_client.post(
        url,
        json=PAYLOAD,
        headers={"X-Governs-Key": inactive_api_key.key},
    )
    assert resp.status_code == 401


@pytest.mark.parametrize("url", [PRECHECK_URL, POSTCHECK_URL])
def test_expired_key_returns_401(test_client, expired_api_key, url):
    resp = test_client.post(
        url,
        json=PAYLOAD,
        headers={"X-Governs-Key": expired_api_key.key},
    )
    assert resp.status_code == 401


@pytest.mark.parametrize("url", [PRECHECK_URL, POSTCHECK_URL])
def test_valid_key_proceeds(test_client, auth_headers, url):
    resp = test_client.post(url, json=PAYLOAD, headers=auth_headers)
    # Auth succeeded; the route returns either 200 with a decision or 429
    # from the rate limiter — anything outside 2xx/4xx would be a regression.
    assert resp.status_code != 401
    assert resp.status_code < 500
