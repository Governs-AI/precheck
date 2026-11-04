# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""V2.12 — precheck authenticates dashboard keys against the dashboard's
`APIKey` table, which stores only a SHA-256 hash and a display prefix.

The dashboard row is authoritative: deactivating or expiring it there takes
effect here immediately, even if an old copy still sits in `api_keys`.
"""

import hashlib
import os

os.environ.setdefault("KEY_HMAC_SECRET", "test-hmac-secret-for-ci-only")

from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import inspect

from app.auth import require_api_key
from app.key_lookup import dashboard_key_hash, find_key
from app.key_utils import hash_api_key
from app.storage import DASHBOARD_TABLES, APIKey, DashboardAPIKey

RAW = "gai_" + "ab" * 32


def _dashboard_key(db, raw=RAW, *, org_id="org-dash", is_active=True, expires_at=None):
    db.add(
        DashboardAPIKey(
            id=f"k-{raw[-6:]}",
            key_hash=dashboard_key_hash(raw),
            key_prefix=raw[:12],
            user_id="user-dash",
            org_id=org_id,
            is_active=is_active,
            expires_at=expires_at,
        )
    )
    db.commit()


def _legacy_copy(db, raw=RAW, *, org_id="org-dash"):
    """The HMAC copy the dashboard used to sync into api_keys."""
    db.add(
        APIKey(
            key_hash=hash_api_key(raw),
            key_prefix=raw[:8],
            user_id="user-dash",
            org_id=org_id,
            is_active=True,
        )
    )
    db.commit()


def test_dashboard_hash_matches_the_dashboard_helper():
    # apps/platform/lib/api-keys.ts: createHash('sha256').update(key).digest('hex')
    assert dashboard_key_hash(RAW) == hashlib.sha256(RAW.encode()).hexdigest()


def test_dashboard_tables_are_not_created_by_precheck():
    assert {"Policy", "APIKey"} <= DASHBOARD_TABLES


@pytest.mark.asyncio
async def test_dashboard_key_authenticates_with_its_org(db_session):
    _dashboard_key(db_session)
    auth = await require_api_key(x_governs_key=RAW, db=db_session)
    assert auth.org_id == "org-dash"
    assert find_key(db_session, RAW).source == "dashboard"


@pytest.mark.asyncio
async def test_deactivated_dashboard_key_is_refused_despite_a_stale_copy(db_session):
    _dashboard_key(db_session, is_active=False)
    _legacy_copy(db_session)
    with pytest.raises(HTTPException) as exc:
        await require_api_key(x_governs_key=RAW, db=db_session)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_expired_dashboard_key_is_refused(db_session):
    _dashboard_key(db_session, expires_at=datetime.utcnow() - timedelta(minutes=1))
    with pytest.raises(HTTPException) as exc:
        await require_api_key(x_governs_key=RAW, db=db_session)
    assert exc.value.status_code == 401
    assert exc.value.detail == "api key expired"


@pytest.mark.asyncio
async def test_rotated_dashboard_key_stops_working(db_session):
    _dashboard_key(db_session)
    new_raw = "gai_" + "cd" * 32
    row = db_session.query(DashboardAPIKey).one()
    row.key_hash = dashboard_key_hash(new_raw)
    db_session.commit()

    with pytest.raises(HTTPException):
        await require_api_key(x_governs_key=RAW, db=db_session)
    assert (
        await require_api_key(x_governs_key=new_raw, db=db_session)
    ).org_id == "org-dash"


@pytest.mark.asyncio
async def test_precheck_native_keys_still_work(db_session):
    raw = "GAI_native_key_123"
    _legacy_copy(db_session, raw=raw, org_id="org-native")
    auth = await require_api_key(x_governs_key=raw, db=db_session)
    assert auth.org_id == "org-native"
    assert find_key(db_session, raw).source == "precheck"


def test_neither_table_stores_the_key(db_session):
    _dashboard_key(db_session)
    _legacy_copy(db_session)
    for model in (DashboardAPIKey, APIKey):
        for row in db_session.query(model).all():
            values = [getattr(row, attr.key) for attr in inspect(model).column_attrs]
            assert RAW not in [v for v in values if isinstance(v, str)]
