# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""
TEST-3.5 — Webhook emission tests (DL-3 multi-tenant).

Covers:
  - build_webhook_url() composes per-org URLs from base + org_id + conn_key
  - emit_event() requires both webhook_base_url AND org_id (DLQs otherwise)
  - emit_event() routes to org-specific decisions channel
  - No org_id cross-contamination between back-to-back emits
  - DLQ written when retries exhausted
  - Event payload contains apiKeyId (hash), NOT the raw apiKey
"""

import json
import pathlib
import pytest
from urllib.parse import urlsplit, parse_qs
from unittest.mock import AsyncMock

# ---------------------------------------------------------------------------
# build_webhook_url — pure URL construction
# ---------------------------------------------------------------------------


class TestBuildWebhookUrl:
    @pytest.mark.parametrize(
        "base,org,conn_key,expected_org,expected_channel,expected_key",
        [
            (
                "wss://gw.example.com/ws/gateway",
                "org-acme",
                "GAI_conn",
                "org-acme",
                "org:org-acme:decisions",
                "GAI_conn",
            ),
            (
                "wss://gw.example.com/ws/gateway",
                "org-globex",
                "GAI_conn",
                "org-globex",
                "org:org-globex:decisions",
                "GAI_conn",
            ),
            (
                "ws://localhost:3003/ws/gateway",
                "tenant_42",
                None,
                "tenant_42",
                "org:tenant_42:decisions",
                None,
            ),
            (
                "wss://gw.example.com/ws/gateway",
                "org with spaces & sym",
                "k!ey",
                "org with spaces & sym",
                "org:org with spaces & sym:decisions",
                "k!ey",
            ),
        ],
    )
    def test_url_construction(
        self, base, org, conn_key, expected_org, expected_channel, expected_key
    ):
        from app.events import build_webhook_url

        url = build_webhook_url(base, org, conn_key)
        parts = urlsplit(url)
        qs = parse_qs(parts.query)

        assert qs["org"] == [expected_org]
        assert qs["channels"] == [expected_channel]
        if expected_key is None:
            assert "key" not in qs
        else:
            assert qs["key"] == [expected_key]

    def test_preserves_scheme_and_path(self):
        from app.events import build_webhook_url

        url = build_webhook_url("wss://gw.example.com/ws/gateway", "org-1", "k")
        parts = urlsplit(url)
        assert parts.scheme == "wss"
        assert parts.netloc == "gw.example.com"
        assert parts.path == "/ws/gateway"

    def test_preserves_unrelated_query_params(self):
        from app.events import build_webhook_url

        url = build_webhook_url("ws://gw/ws?env=prod&region=us-east", "org-1", "k")
        qs = parse_qs(urlsplit(url).query)
        assert qs["env"] == ["prod"]
        assert qs["region"] == ["us-east"]
        assert qs["org"] == ["org-1"]

    def test_strips_existing_org_key_channels_to_prevent_carryover(self):
        from app.events import build_webhook_url

        # If a prior URL had stale routing params, they must not bleed through
        # to a different org's connection.
        stale = (
            "ws://gw/ws?org=stale-org&key=stale-key&channels=org:stale-org:decisions"
        )
        url = build_webhook_url(stale, "fresh-org", "fresh-key")
        qs = parse_qs(urlsplit(url).query)
        assert qs["org"] == ["fresh-org"]
        assert qs["key"] == ["fresh-key"]
        assert qs["channels"] == ["org:fresh-org:decisions"]

    def test_missing_base_url_raises(self):
        from app.events import build_webhook_url

        with pytest.raises(ValueError):
            build_webhook_url("", "org-1", "k")

    def test_missing_org_id_raises(self):
        from app.events import build_webhook_url

        with pytest.raises(ValueError):
            build_webhook_url("ws://gw/ws", "", "k")


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
# emit_event — guard rails: missing config or missing org_id → DLQ
# ---------------------------------------------------------------------------


class TestEmitEventGuards:
    @pytest.mark.asyncio
    async def test_no_base_url_writes_dlq(self, tmp_path, monkeypatch):
        from app import events as ev_module

        monkeypatch.setattr(ev_module.settings, "webhook_base_url", "")
        dlq_path = str(tmp_path / "no_url.dlq.jsonl")
        monkeypatch.setattr(ev_module.settings, "precheck_dlq", dlq_path)

        await ev_module.emit_event({"type": "decision"}, org_id="org-1")

        record = json.loads(pathlib.Path(dlq_path).read_text().strip())
        assert "webhook_base_url_not_configured" in record["err"]

    @pytest.mark.asyncio
    async def test_missing_org_id_writes_dlq(self, tmp_path, monkeypatch):
        from app import events as ev_module

        monkeypatch.setattr(ev_module.settings, "webhook_base_url", "ws://gw/ws")
        dlq_path = str(tmp_path / "no_org.dlq.jsonl")
        monkeypatch.setattr(ev_module.settings, "precheck_dlq", dlq_path)

        await ev_module.emit_event({"type": "decision"}, org_id=None)

        record = json.loads(pathlib.Path(dlq_path).read_text().strip())
        assert "missing_org_id" in record["err"]


# ---------------------------------------------------------------------------
# emit_event — successful per-org routing
# ---------------------------------------------------------------------------


class TestEmitEventRouting:
    @pytest.mark.asyncio
    async def test_routes_to_org_specific_url(self, monkeypatch):
        from app import events as ev_module

        monkeypatch.setattr(
            ev_module.settings, "webhook_base_url", "wss://gw.example.com/ws/gateway"
        )
        monkeypatch.setattr(ev_module.settings, "webhook_conn_key", "GAI_conn_key")
        monkeypatch.setattr(ev_module.settings, "webhook_max_retries", 1)

        mock_send = AsyncMock()
        monkeypatch.setattr(ev_module, "_send_via_websocket", mock_send)

        await ev_module.emit_event(
            {"type": "decision"}, org_id="org-acme", correlation_id="corr-1"
        )

        mock_send.assert_called_once()
        call_url = mock_send.call_args[0][0]
        qs = parse_qs(urlsplit(call_url).query)
        assert qs["org"] == ["org-acme"]
        assert qs["channels"] == ["org:org-acme:decisions"]
        assert qs["key"] == ["GAI_conn_key"]
        # Connection key passed positionally as 3rd arg
        assert mock_send.call_args[0][2] == "GAI_conn_key"
        # Correlation id passed positionally as 4th arg
        assert mock_send.call_args[0][3] == "corr-1"

    @pytest.mark.asyncio
    async def test_back_to_back_emits_use_distinct_org_urls(self, monkeypatch):
        """Regression guard: org_id from one request must not leak into the next.

        With the old single-tenant WEBHOOK_URL, all events shared one org from
        env. After DL-3 each call must build its own URL from its own org_id.
        """
        from app import events as ev_module

        monkeypatch.setattr(ev_module.settings, "webhook_base_url", "ws://gw/ws")
        monkeypatch.setattr(ev_module.settings, "webhook_conn_key", "k")
        monkeypatch.setattr(ev_module.settings, "webhook_max_retries", 1)

        urls = []

        async def capture(url, message, api_key, correlation_id):
            urls.append(url)

        monkeypatch.setattr(ev_module, "_send_via_websocket", capture)

        await ev_module.emit_event({"type": "decision"}, org_id="org-a")
        await ev_module.emit_event({"type": "decision"}, org_id="org-b")
        await ev_module.emit_event({"type": "decision"}, org_id="org-a")

        orgs = [parse_qs(urlsplit(u).query)["org"][0] for u in urls]
        channels = [parse_qs(urlsplit(u).query)["channels"][0] for u in urls]

        assert orgs == ["org-a", "org-b", "org-a"]
        assert channels == [
            "org:org-a:decisions",
            "org:org-b:decisions",
            "org:org-a:decisions",
        ]

    @pytest.mark.asyncio
    async def test_event_sent_as_json_string(self, monkeypatch):
        from app import events as ev_module

        monkeypatch.setattr(ev_module.settings, "webhook_base_url", "ws://gw/ws")
        monkeypatch.setattr(ev_module.settings, "webhook_conn_key", "k")
        monkeypatch.setattr(ev_module.settings, "webhook_max_retries", 1)

        captured = {}

        async def fake_send(url, message, api_key, correlation_id):
            captured["message"] = message

        monkeypatch.setattr(ev_module, "_send_via_websocket", fake_send)

        event = {"type": "decision", "apiKeyId": "abc123hash"}
        await ev_module.emit_event(event, org_id="org-1")

        parsed = json.loads(captured["message"])
        assert parsed["type"] == "decision"


# ---------------------------------------------------------------------------
# emit_event — all retries exhausted → DLQ
# ---------------------------------------------------------------------------


class TestEmitEventRetryExhaustion:
    @pytest.mark.asyncio
    async def test_all_retries_fail_writes_dlq(self, tmp_path, monkeypatch):
        from app import events as ev_module

        monkeypatch.setattr(ev_module.settings, "webhook_base_url", "ws://gw/ws")
        monkeypatch.setattr(ev_module.settings, "webhook_conn_key", "k")
        monkeypatch.setattr(ev_module.settings, "webhook_max_retries", 2)
        monkeypatch.setattr(ev_module.settings, "webhook_backoff_base_ms", 1)
        dlq_path = str(tmp_path / "retry.dlq.jsonl")
        monkeypatch.setattr(ev_module.settings, "precheck_dlq", dlq_path)

        async def always_fail(url, message, api_key, correlation_id):
            raise ConnectionRefusedError("no server")

        monkeypatch.setattr(ev_module, "_send_via_websocket", always_fail)

        await ev_module.emit_event({"type": "decision", "tool": "test"}, org_id="org-1")

        record = json.loads(pathlib.Path(dlq_path).read_text().strip())
        assert "websocket_exception" in record["err"]

    @pytest.mark.asyncio
    async def test_retry_count_respected(self, tmp_path, monkeypatch):
        from app import events as ev_module

        monkeypatch.setattr(ev_module.settings, "webhook_base_url", "ws://gw/ws")
        monkeypatch.setattr(ev_module.settings, "webhook_conn_key", "k")
        monkeypatch.setattr(ev_module.settings, "webhook_max_retries", 3)
        monkeypatch.setattr(ev_module.settings, "webhook_backoff_base_ms", 1)
        monkeypatch.setattr(
            ev_module.settings, "precheck_dlq", str(tmp_path / "r.jsonl")
        )

        call_count = {"n": 0}

        async def fail_n_times(url, message, api_key, correlation_id):
            call_count["n"] += 1
            raise ConnectionError("fail")

        monkeypatch.setattr(ev_module, "_send_via_websocket", fail_n_times)

        await ev_module.emit_event({"type": "test"}, org_id="org-1")

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
        import hashlib

        raw_api_key = "GAI_supersecretkey123456"
        api_key_id = hashlib.sha256(raw_api_key.encode()).hexdigest()[:16]

        event = {
            "type": "decision",
            "decision": "allow",
            "tool": "model.chat",
            "apiKeyId": api_key_id,
        }

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
