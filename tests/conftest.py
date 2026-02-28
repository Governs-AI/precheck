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
os.environ.setdefault("DEBUG", "true")           # bypasses secret-validator
os.environ.setdefault("PII_TOKEN_SALT", "test-salt-for-ci-only")
os.environ.setdefault("WEBHOOK_SECRET", "test-webhook-secret-ci")
os.environ.setdefault("REDIS_URL", "")           # disable Redis in rate-limiter
os.environ.setdefault("WEBHOOK_URL", "")

import pytest
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.storage import Base, APIKey, get_db

# ---------------------------------------------------------------------------
# In-memory SQLite engine shared across the session
# ---------------------------------------------------------------------------
SQLITE_URL = "sqlite:///:memory:"
_engine = create_engine(SQLITE_URL, connect_args={"check_same_thread": False})
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
    key = APIKey(
        key="GAI_test_valid_key_12345",
        user_id="user-test-001",
        is_active=True,
        expires_at=None,
    )
    db_session.add(key)
    db_session.commit()
    return key


@pytest.fixture
def expired_api_key(db_session):
    """Insert and return an expired API key."""
    key = APIKey(
        key="GAI_test_expired_key_99",
        user_id="user-test-002",
        is_active=True,
        expires_at=datetime.utcnow() - timedelta(hours=1),
    )
    db_session.add(key)
    db_session.commit()
    return key


@pytest.fixture
def inactive_api_key(db_session):
    """Insert and return a revoked (inactive) API key."""
    key = APIKey(
        key="GAI_test_inactive_key_00",
        user_id="user-test-003",
        is_active=False,
        expires_at=None,
    )
    db_session.add(key)
    db_session.commit()
    return key


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
