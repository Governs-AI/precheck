# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""
DL-5 — API tests: decision events carry correct org_id and orgs are isolated.

Verifies:
  1. /v1/precheck emits event with org_id from the authenticating key
  2. event.data.orgId and event.channel are set correctly
  3. Two keys from different orgs produce events for their respective orgs (no bleed)
  4. A key with no org_id causes the event to be DLQed rather than routed
  5. /v1/postcheck also emits with the correct org_id
"""

import asyncio
import json
import pathlib
from typing import List, Tuple
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.key_utils import generate_api_key
from app.storage import APIKey, get_db


def _insert_org_key(session, *, org_id, is_active=True):
    raw_key, key_hash, key_prefix = generate_api_key()
    session.add(
        APIKey(
            key_hash=key_hash,
            key_prefix=key_prefix,
            user_id="user-dl5-test",
            org_id=org_id,
            is_active=is_active,
        )
    )
    session.commit()
    return raw_key


def _make_app(db_session):
    from app.main import create_app

    app = create_app()
    app.dependency_overrides[get_db] = lambda: db_session
    return app


@pytest.mark.asyncio
async def test_precheck_emits_org_id_from_key(db_session):
    """emit_event is called with the org_id that belongs to the authenticating key."""
    raw_key = _insert_org_key(db_session, org_id="org-acme-001")
    captured: List[Tuple] = []

    async def mock_emit(event, org_id=None, correlation_id=None):
        captured.append((event, org_id))

    app = _make_app(db_session)
    with patch("app.api.emit_event", side_effect=mock_emit):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/v1/precheck",
                json={"tool": "model.chat", "scope": "tool_call", "raw_text": "Hello"},
                headers={"X-Governs-Key": raw_key},
            )

    await asyncio.sleep(0)

    assert resp.status_code == 200
    assert len(captured) == 1
    _, emitted_org_id = captured[0]
    assert emitted_org_id == "org-acme-001"


@pytest.mark.asyncio
async def test_precheck_event_data_org_id_and_channel(db_session):
    """event.data.orgId and event.channel reflect the key's org_id."""
    raw_key = _insert_org_key(db_session, org_id="org-beta-002")
    captured: List[dict] = []

    async def mock_emit(event, org_id=None, correlation_id=None):
        captured.append(event)

    app = _make_app(db_session)
    with patch("app.api.emit_event", side_effect=mock_emit):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/v1/precheck",
                json={"tool": "model.chat", "scope": "tool_call", "raw_text": "Test"},
                headers={"X-Governs-Key": raw_key},
            )

    await asyncio.sleep(0)

    assert resp.status_code == 200
    assert len(captured) == 1
    event = captured[0]
    assert event["data"]["orgId"] == "org-beta-002"
    assert event["channel"] == "org:org-beta-002:decisions"


@pytest.mark.asyncio
async def test_two_org_keys_emit_to_distinct_orgs(db_session):
    """Org-A key and Org-B key produce events routed to their own orgs — no cross-contamination."""
    key_a = _insert_org_key(db_session, org_id="org-a")
    key_b = _insert_org_key(db_session, org_id="org-b")
    captured: List[Tuple] = []

    async def mock_emit(event, org_id=None, correlation_id=None):
        captured.append((event["data"]["orgId"], org_id))

    app = _make_app(db_session)
    with patch("app.api.emit_event", side_effect=mock_emit):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp_a = await client.post(
                "/api/v1/precheck",
                json={"tool": "model.chat", "scope": "tool_call", "raw_text": "Org A"},
                headers={"X-Governs-Key": key_a},
            )
            resp_b = await client.post(
                "/api/v1/precheck",
                json={"tool": "model.chat", "scope": "tool_call", "raw_text": "Org B"},
                headers={"X-Governs-Key": key_b},
            )

    await asyncio.sleep(0)

    assert resp_a.status_code == 200
    assert resp_b.status_code == 200
    assert len(captured) == 2

    data_org_a, call_org_a = captured[0]
    data_org_b, call_org_b = captured[1]

    assert data_org_a == "org-a" and call_org_a == "org-a"
    assert data_org_b == "org-b" and call_org_b == "org-b"
    assert call_org_a != call_org_b


@pytest.mark.asyncio
async def test_key_without_org_id_dlqs_event(db_session, tmp_path, monkeypatch):
    """A key with no org_id causes the event to be written to DLQ, not routed."""
    from app import events as ev_module

    raw_key = _insert_org_key(db_session, org_id=None)
    dlq_path = str(tmp_path / "dl5.dlq.jsonl")
    monkeypatch.setattr(ev_module.settings, "webhook_base_url", "ws://gw/ws")
    monkeypatch.setattr(ev_module.settings, "precheck_dlq", dlq_path)

    app = _make_app(db_session)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/api/v1/precheck",
            json={"tool": "model.chat", "scope": "tool_call", "raw_text": "No org"},
            headers={"X-Governs-Key": raw_key},
        )

    await asyncio.sleep(0.05)

    assert resp.status_code == 200
    dlq_file = pathlib.Path(dlq_path)
    assert dlq_file.exists(), "DLQ file must exist when org_id is missing"
    record = json.loads(dlq_file.read_text().strip().splitlines()[0])
    assert "missing_org_id" in record["err"]


@pytest.mark.asyncio
async def test_postcheck_emits_org_id_from_key(db_session):
    """/v1/postcheck emits with the org_id from the authenticating key."""
    raw_key = _insert_org_key(db_session, org_id="org-gamma-003")
    captured: List[Tuple] = []

    async def mock_emit(event, org_id=None, correlation_id=None):
        captured.append((event, org_id))

    app = _make_app(db_session)
    with patch("app.api.emit_event", side_effect=mock_emit):
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/v1/postcheck",
                json={
                    "tool": "model.chat",
                    "scope": "tool_call",
                    "raw_text": "Response",
                },
                headers={"X-Governs-Key": raw_key},
            )

    await asyncio.sleep(0)

    assert resp.status_code == 200
    assert len(captured) == 1
    event, emitted_org_id = captured[0]
    assert emitted_org_id == "org-gamma-003"
    assert event["data"]["orgId"] == "org-gamma-003"
    assert event["data"]["direction"] == "postcheck"
