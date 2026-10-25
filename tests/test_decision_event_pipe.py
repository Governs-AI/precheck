# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""precheck → websocket gateway → Decision row (v2).

Pins the gateway handshake (READY greeting, AUTH_SUCCESS, ACK), that the
request's own key authenticates the connection, and that the decision event
carries the policy id and redacted output but never the raw input.
"""

import json
from unittest.mock import AsyncMock

import pytest

from app import events as ev_module
from app.decision_cache import allow_decision_cache
from app.rate_limit import rate_limiter


class _FakeSocket:
    def __init__(self, frames):
        self._frames = [json.dumps(f) for f in frames]
        self.sent = []

    async def send(self, msg):
        self.sent.append(json.loads(msg))

    async def recv(self):
        if not self._frames:
            raise AssertionError("gateway sent nothing more")
        return self._frames.pop(0)


def _patch_connect(monkeypatch, sock):
    class _Ctx:
        async def __aenter__(self):
            return sock

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(ev_module.websockets, "connect", lambda *a, **k: _Ctx())


@pytest.mark.asyncio
async def test_handshake_skips_ready_and_waits_for_ack(monkeypatch):
    sock = _FakeSocket(
        [
            {"type": "READY", "connectionId": "c1"},
            {"type": "AUTH_SUCCESS", "orgId": "org-a"},
            {"type": "ACK", "id": "x", "decisionId": "d1"},
        ]
    )
    _patch_connect(monkeypatch, sock)
    await ev_module._send_via_websocket("ws://gw/ws", '{"type":"INGEST"}', "gai_k")
    assert sock.sent[0] == {"type": "AUTH", "apiKey": "gai_k"}
    assert sock.sent[1] == {"type": "INGEST"}


@pytest.mark.asyncio
async def test_auth_error_frame_raises(monkeypatch):
    sock = _FakeSocket(
        [
            {"type": "READY"},
            {"type": "ERROR", "error": "AUTH_ERROR", "message": "Invalid API key"},
        ]
    )
    _patch_connect(monkeypatch, sock)
    with pytest.raises(ValueError, match="auth_failed"):
        await ev_module._send_via_websocket("ws://gw/ws", "{}", "bad")


@pytest.mark.asyncio
async def test_ingest_error_frame_raises(monkeypatch):
    sock = _FakeSocket(
        [
            {"type": "READY"},
            {"type": "AUTH_SUCCESS"},
            {"type": "ERROR", "error": "INGEST_ERROR", "message": "Invalid decision"},
        ]
    )
    _patch_connect(monkeypatch, sock)
    with pytest.raises(ValueError, match="INGEST_ERROR"):
        await ev_module._send_via_websocket("ws://gw/ws", "{}", "k")


@pytest.mark.asyncio
async def test_request_key_preferred_over_connection_key(monkeypatch):
    monkeypatch.setattr(ev_module.settings, "webhook_base_url", "ws://gw/ws")
    monkeypatch.setattr(ev_module.settings, "webhook_conn_key", "conn")
    monkeypatch.setattr(ev_module.settings, "webhook_max_retries", 1)
    send = AsyncMock()
    monkeypatch.setattr(ev_module, "_send_via_websocket", send)

    await ev_module.emit_event({"x": 1}, org_id="org-a", auth_key="request-key")
    assert send.call_args[0][2] == "request-key"


# ─── event shape from the HTTP handler ───────────────────────────────────
@pytest.fixture
def captured_events(monkeypatch):
    allow_decision_cache.clear()
    rate_limiter.clear()
    captured = []

    async def fake_emit(event, org_id=None, correlation_id=None, auth_key=None):
        captured.append({"event": event, "auth_key": auth_key})

    monkeypatch.setattr("app.api.emit_event", fake_emit)
    monkeypatch.setattr("app.api.audit_log", lambda *_a, **_k: None)
    yield captured
    allow_decision_cache.clear()
    rate_limiter.clear()


def test_event_omits_raw_text_and_carries_policy_and_redaction(
    test_client, active_api_key, captured_events
):
    raw = "Reach me at jane.doe@example.com tomorrow"
    res = test_client.post(
        "/api/v1/precheck",
        json={"tool": "model.chat", "scope": "net.external", "raw_text": raw},
        headers={"X-Governs-Key": active_api_key.key},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["decision"] == "transform"

    [captured] = captured_events
    assert captured["auth_key"] == active_api_key.key
    data = captured["event"]["data"]
    serialized = json.dumps(captured["event"])
    assert "jane.doe@example.com" not in serialized
    assert "rawText" not in data
    assert data["policyId"] == body["policy_id"]
    assert data["payloadOut"] == {"raw_text_out": body["raw_text_out"]}
    assert data["payloadHash"].startswith("sha256:")
    assert data["direction"] == "precheck"


def test_allow_event_has_no_payload_out(test_client, active_api_key, captured_events):
    test_client.post(
        "/api/v1/precheck",
        json={"tool": "model.chat", "raw_text": "Summarise the release notes."},
        headers={"X-Governs-Key": active_api_key.key},
    )
    [captured] = captured_events
    assert captured["event"]["data"]["decision"] == "allow"
    assert captured["event"]["data"]["payloadOut"] is None
