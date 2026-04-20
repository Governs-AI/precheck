# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""
Shared test fixtures for precheck test suite.

Environment variables are set BEFORE any app imports so that pydantic-settings
and SQLAlchemy pick up the test-safe values at module-load time.
"""

import os

# --- env vars must be set before any app.* import ---
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("DEBUG", "true")  # bypasses secret-validator
os.environ.setdefault("PII_TOKEN_SALT", "test-salt-for-ci-only")
os.environ.setdefault("WEBHOOK_SECRET", "test-webhook-secret-ci")
os.environ.setdefault("REDIS_URL", "")  # disable Redis in rate-limiter
os.environ.setdefault("WEBHOOK_BASE_URL", "")
os.environ.setdefault("WEBHOOK_CONN_KEY", "")
# KEY_HMAC_SECRET must be set before key_utils is imported
os.environ.setdefault("KEY_HMAC_SECRET", "test-hmac-secret-for-ci-only")

import pytest
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Optional
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.storage import Base, APIKey, get_db
from app.key_utils import hash_api_key


@dataclass
class _APIKeyWithRaw:
    """Wraps a stored APIKey and exposes .key so test code can use it in headers."""

    _record: APIKey
    key: str  # the raw plaintext key (never stored in DB)

    @property
    def is_active(self) -> bool:
        return bool(self._record.is_active)

    @property
    def expires_at(self) -> Optional[datetime]:
        return self._record.expires_at  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# In-memory SQLite engine shared across the session.
# StaticPool ensures all connections share the same in-memory DB so that
# tables created by create_all() are visible to every subsequent query.
# ---------------------------------------------------------------------------
SQLITE_URL = "sqlite:///:memory:"
_engine = create_engine(
    SQLITE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
_TestSession = sessionmaker(autocommit=False, autoflush=False, bind=_engine)


@pytest.fixture(autouse=True)
def _reset_db():
    """Recreate all tables before each test and drop them after."""
    Base.metadata.create_all(bind=_engine)
    yield
    Base.metadata.drop_all(bind=_engine)


@pytest.fixture
def db_session():
    """Provide a SQLAlchemy session backed by the in-memory SQLite DB."""
    session = _TestSession()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def active_api_key(db_session):
    """Insert and return an active, non-expired API key."""
    raw = "GAI_test_valid_key_12345"
    record = APIKey(
        key_hash=hash_api_key(raw),
        key_prefix=raw[:8],
        user_id="user-test-001",
        is_active=True,
        expires_at=None,
    )
    db_session.add(record)
    db_session.commit()
    return _APIKeyWithRaw(_record=record, key=raw)


@pytest.fixture
def expired_api_key(db_session):
    """Insert and return an expired API key."""
    raw = "GAI_test_expired_key_99"
    record = APIKey(
        key_hash=hash_api_key(raw),
        key_prefix=raw[:8],
        user_id="user-test-002",
        is_active=True,
        expires_at=datetime.utcnow() - timedelta(hours=1),
    )
    db_session.add(record)
    db_session.commit()
    return _APIKeyWithRaw(_record=record, key=raw)


@pytest.fixture
def inactive_api_key(db_session):
    """Insert and return a revoked (inactive) API key."""
    raw = "GAI_test_inactive_key_00"
    record = APIKey(
        key_hash=hash_api_key(raw),
        key_prefix=raw[:8],
        user_id="user-test-003",
        is_active=False,
        expires_at=None,
    )
    db_session.add(record)
    db_session.commit()
    return _APIKeyWithRaw(_record=record, key=raw)


@pytest.fixture
def test_client(db_session):
    """FastAPI TestClient with the in-memory DB injected."""
    from fastapi.testclient import TestClient
    from app.main import create_app

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
