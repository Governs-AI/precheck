# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""
QA.1 — Per-endpoint API test suite scaffold.

Shared fixtures for `tests/api/`. The parent `tests/conftest.py` already sets
the test-safe environment variables, builds the in-memory SQLite engine, and
exposes `test_client`, `db_session`, `active_api_key`, `expired_api_key`, and
`inactive_api_key`. This module adds helpers specific to the API-level suite:

  * `auth_headers`  — returns a dict with the `X-Governs-Key` header populated
                      from a valid, DB-backed key
  * `valid_payload` — a minimal, passing request body that does not trigger
                      PII redaction (useful for health/auth contract tests)
"""

from typing import Dict

import pytest


@pytest.fixture
def auth_headers(active_api_key) -> Dict[str, str]:
    """Return HTTP headers carrying a valid API key for authenticated routes."""
    return {"X-Governs-Key": active_api_key.key}


@pytest.fixture
def valid_payload() -> Dict[str, str]:
    """A minimal precheck/postcheck body with no PII markers."""
    return {
        "tool": "model.chat",
        "scope": "net.external",
        "raw_text": "This message has no sensitive data.",
    }
