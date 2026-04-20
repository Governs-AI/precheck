# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""
DL-1 — Unit tests for org_id propagation through require_api_key.

Verifies:
  - APIKey model exposes org_id
  - require_api_key returns AuthContext(raw_key, org_id) with the correct org_id
  - Missing org_id (nullable) is surfaced as None rather than raising
"""

import os

os.environ.setdefault("KEY_HMAC_SECRET", "test-hmac-secret-for-ci-only")

from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.auth import AuthContext, require_api_key
from app.key_utils import generate_api_key, hash_api_key
from app.storage import APIKey, Base


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


def _insert_key(session, *, org_id, is_active=True, expires_at=None):
    raw_key, key_hash, key_prefix = generate_api_key()
    session.add(
        APIKey(
            key_hash=key_hash,
            key_prefix=key_prefix,
            user_id="user-001",
            org_id=org_id,
            is_active=is_active,
            expires_at=expires_at,
        )
    )
    session.commit()
    return raw_key


def test_api_key_model_has_org_id_column():
    assert "org_id" in APIKey.__table__.columns
    assert APIKey.__table__.columns["org_id"].nullable is True


@pytest.mark.asyncio
async def test_require_api_key_returns_auth_context_with_org_id(db_session):
    raw_key = _insert_key(db_session, org_id="org-acme-001")

    auth = await require_api_key(x_governs_key=raw_key, db=db_session)

    assert isinstance(auth, AuthContext)
    assert auth.raw_key == raw_key
    assert auth.org_id == "org-acme-001"


@pytest.mark.asyncio
async def test_require_api_key_returns_none_org_id_when_null(db_session):
    raw_key = _insert_key(db_session, org_id=None)

    auth = await require_api_key(x_governs_key=raw_key, db=db_session)

    assert auth.raw_key == raw_key
    assert auth.org_id is None


@pytest.mark.asyncio
async def test_require_api_key_isolates_orgs_by_key(db_session):
    key_a = _insert_key(db_session, org_id="org-a")
    key_b = _insert_key(db_session, org_id="org-b")

    auth_a = await require_api_key(x_governs_key=key_a, db=db_session)
    auth_b = await require_api_key(x_governs_key=key_b, db=db_session)

    assert auth_a.org_id == "org-a"
    assert auth_b.org_id == "org-b"


@pytest.mark.asyncio
async def test_require_api_key_rejects_unknown_key(db_session):
    with pytest.raises(HTTPException) as exc:
        await require_api_key(x_governs_key="GAI_unknown", db=db_session)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_require_api_key_rejects_inactive_key(db_session):
    raw_key = _insert_key(db_session, org_id="org-x", is_active=False)
    with pytest.raises(HTTPException) as exc:
        await require_api_key(x_governs_key=raw_key, db=db_session)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_require_api_key_rejects_expired_key(db_session):
    raw_key = _insert_key(
        db_session,
        org_id="org-x",
        expires_at=datetime.utcnow() - timedelta(hours=1),
    )
    with pytest.raises(HTTPException) as exc:
        await require_api_key(x_governs_key=raw_key, db=db_session)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_require_api_key_rejects_missing_header(db_session):
    with pytest.raises(HTTPException) as exc:
        await require_api_key(x_governs_key=None, db=db_session)
    assert exc.value.status_code == 401
