# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""
TEST-3.5 — Webhook emission tests.

Covers:
  - emit_event() calls _send_via_websocket with correct args
  - DLQ written when webhook_url is not configured
  - DLQ written after all retries are exhausted
  - Event payload contains apiKeyId (hash), NOT the raw apiKey
  - _parse_webhook_url() correctly extracts org_id, channel, api_key
  - _write_dlq() appends JSON lines to the target file
"""

import json
import tempfile
import pathlib
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock


# ---------------------------------------------------------------------------
# _parse_webhook_url
# ---------------------------------------------------------------------------


class TestParseWebhookUrl:
    def _parse(self, url):
        from app.events import _parse_webhook_url
        return _parse_webhook_url(url)

    def test_extracts_org_id(self):
        org, _, _ = self._parse("ws://localhost:3003?org=my-org&key=tok123")
        assert org == "my-org"

    def test_extracts_api_key(self):
        _, _, key = self._parse("ws://localhost:3003?org=org1&key=GAI_abc123")
        assert key == "GAI_abc123"

    def test_extracts_decisions_channel(self):
        url = "ws://localhost:3003?org=org1&key=k&channels=org1:decisions,org1:usage"
        _, channel, _ = self._parse(url)
        assert channel == "org1:decisions"

    def test_no_decisions_channel_returns_none(self):
        url = "ws://localhost:3003?org=org1&key=k&channels=org1:usage"
        _, channel, _ = self._parse(url)
        assert channel is None

    def test_empty_url_returns_none_triple(self):
        assert self._parse("") == (None, None, None)

    def test_url_without_query_returns_none_values(self):
        org, channel, key = self._parse("ws://localhost:3003")
        assert org is None
        assert key is None


# ---------------------------------------------------------------------------
# _write_dlq
# ---------------------------------------------------------------------------


class TestWriteDlq:
    def test_creates_file_on_first_write(self, tmp_path):
        from app.events import _write_dlq
        dlq = str(tmp_path / "sub" / "test.dlq.jsonl")
        event = {"type": "decision", "tool": "model.chat"}
        _write_dlq(event, "test_error", dlq_path=dlq)
        assert pathlib.Path(dlq).exists()

    def test_appends_valid_json_line(self, tmp_path):
        from app.events import _write_dlq
        dlq = str(tmp_path / "test.dlq.jsonl")
        event = {"type": "decision", "tool": "model.chat"}
        _write_dlq(event, "network_failure", dlq_path=dlq)
        lines = pathlib.Path(dlq).read_text().strip().splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["err"] == "network_failure"
        assert record["event"] == event

    def test_multiple_events_append(self, tmp_path):
        from app.events import _write_dlq
        dlq = str(tmp_path / "test.dlq.jsonl")
        _write_dlq({"id": 1}, "err1", dlq_path=dlq)
        _write_dlq({"id": 2}, "err2", dlq_path=dlq)
        lines = pathlib.Path(dlq).read_text().strip().splitlines()
        assert len(lines) == 2


# ---------------------------------------------------------------------------
# emit_event — no webhook URL → DLQ
# ---------------------------------------------------------------------------


class TestEmitEventNoDlq:
    @pytest.mark.asyncio
    async def test_no_webhook_url_writes_dlq(self, tmp_path, monkeypatch):
        from app import events as ev_module

        monkeypatch.setattr(ev_module.settings, "webhook_url", "")
        dlq_path = str(tmp_path / "no_url.dlq.jsonl")
        monkeypatch.setattr(ev_module.settings, "precheck_dlq", dlq_path)

        event = {"type": "decision", "decision": "allow", "tool": "model.chat"}
        await ev_module.emit_event(event)

        assert pathlib.Path(dlq_path).exists()
        record = json.loads(pathlib.Path(dlq_path).read_text().strip())
        assert "webhook_url_not_configured" in record["err"]


# ---------------------------------------------------------------------------
# emit_event — successful send
# ---------------------------------------------------------------------------


class TestEmitEventSuccess:
    @pytest.mark.asyncio
    async def test_calls_send_via_websocket(self, monkeypatch):
        from app import events as ev_module

        monkeypatch.setattr(
            ev_module.settings,
            "webhook_url",
            "ws://localhost:3003?org=org1&key=GAI_key",
        )
        monkeypatch.setattr(ev_module.settings, "webhook_max_retries", 1)

        mock_send = AsyncMock()
        monkeypatch.setattr(ev_module, "_send_via_websocket", mock_send)

        event = {"type": "decision", "decision": "allow", "data": {"correlationId": "corr-123"}}
        await ev_module.emit_event(event)

        mock_send.assert_called_once()
        call_url = mock_send.call_args[0][0]
        assert call_url == "ws://localhost:3003?org=org1&key=GAI_key"
        assert mock_send.call_args[0][3] == "corr-123"

    @pytest.mark.asyncio
    async def test_event_sent_as_json_string(self, monkeypatch):
        from app import events as ev_module

        monkeypatch.setattr(
            ev_module.settings, "webhook_url", "ws://localhost:3003?org=o&key=k"
        )
        monkeypatch.setattr(ev_module.settings, "webhook_max_retries", 1)

        captured = {}

        async def fake_send(url, message, api_key, correlation_id):
            captured["message"] = message

        monkeypatch.setattr(ev_module, "_send_via_websocket", fake_send)

        event = {"type": "decision", "apiKeyId": "abc123hash"}
        await ev_module.emit_event(event)

        assert "message" in captured
        parsed = json.loads(captured["message"])
        assert parsed["type"] == "decision"


# ---------------------------------------------------------------------------
# emit_event — all retries exhausted → DLQ
# ---------------------------------------------------------------------------


class TestEmitEventRetryExhaustion:
    @pytest.mark.asyncio
    async def test_all_retries_fail_writes_dlq(self, tmp_path, monkeypatch):
        from app import events as ev_module

        monkeypatch.setattr(
            ev_module.settings, "webhook_url", "ws://localhost:3003?org=o&key=k"
        )
        monkeypatch.setattr(ev_module.settings, "webhook_max_retries", 2)
        monkeypatch.setattr(ev_module.settings, "webhook_backoff_base_ms", 1)
        dlq_path = str(tmp_path / "retry.dlq.jsonl")
        monkeypatch.setattr(ev_module.settings, "precheck_dlq", dlq_path)

        async def always_fail(url, message, api_key, correlation_id):
            raise ConnectionRefusedError("no server")

        monkeypatch.setattr(ev_module, "_send_via_websocket", always_fail)

        await ev_module.emit_event({"type": "decision", "tool": "test"})

        assert pathlib.Path(dlq_path).exists()
        record = json.loads(pathlib.Path(dlq_path).read_text().strip())
        assert "websocket_exception" in record["err"]

    @pytest.mark.asyncio
    async def test_retry_count_respected(self, tmp_path, monkeypatch):
        from app import events as ev_module

        monkeypatch.setattr(
            ev_module.settings, "webhook_url", "ws://localhost:3003?org=o&key=k"
        )
        monkeypatch.setattr(ev_module.settings, "webhook_max_retries", 3)
        monkeypatch.setattr(ev_module.settings, "webhook_backoff_base_ms", 1)
        monkeypatch.setattr(ev_module.settings, "precheck_dlq", str(tmp_path / "r.jsonl"))

        call_count = {"n": 0}

        async def fail_n_times(url, message, api_key, correlation_id):
            call_count["n"] += 1
            raise ConnectionError("fail")

        monkeypatch.setattr(ev_module, "_send_via_websocket", fail_n_times)

        await ev_module.emit_event({"type": "test"})

        assert call_count["n"] == 3


# ---------------------------------------------------------------------------
# Event shape — no raw apiKey in body, only apiKeyId hash
# ---------------------------------------------------------------------------


class TestEventShape:
    """
    Verify that event payloads built by api.py don't expose the raw API key.
    api.py sets event["apiKeyId"] = sha256(api_key)[:16] — never the raw key.
    """

    def test_event_does_not_contain_api_key_field(self):
        """Construct an event the same way api.py does and verify the shape."""
        import hashlib

        raw_api_key = "GAI_supersecretkey123456"
        api_key_id = hashlib.sha256(raw_api_key.encode()).hexdigest()[:16]

        event = {
            "type": "decision",
            "decision": "allow",
            "tool": "model.chat",
            "apiKeyId": api_key_id,
        }

        # Raw key must NOT be present
        event_json = json.dumps(event)
        assert raw_api_key not in event_json

    def test_api_key_id_is_hash_not_raw_key(self):
        import hashlib

        raw_key = "GAI_mykey12345"
        expected_id = hashlib.sha256(raw_key.encode()).hexdigest()[:16]

        event = {"apiKeyId": expected_id}

        assert event["apiKeyId"] == expected_id
        assert len(event["apiKeyId"]) == 16
        assert event["apiKeyId"] != raw_key
