import json
import time
import pathlib
import asyncio
import logging
import websockets
from urllib.parse import urlparse, parse_qs
from typing import Any, Dict, Optional, Tuple
from .settings import settings
from .metrics import record_webhook_event, record_dlq_event, set_dlq_size

logger = logging.getLogger(__name__)


def _parse_webhook_url(webhook_url: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Parse webhook URL to extract org ID, decisions channel, and API key"""
    if not webhook_url:
        return None, None, None

    try:
        parsed = urlparse(webhook_url)
        query_params = parse_qs(parsed.query)

        org_id = query_params.get('org', [None])[0]
        api_key = query_params.get('key', [None])[0]
        channels = query_params.get('channels', [None])[0]
        decisions_channel = None

        if channels:
            channel_list = [ch.strip() for ch in channels.split(',')]
            for channel in channel_list:
                if channel.endswith(':decisions'):
                    decisions_channel = channel
                    break

        return org_id, decisions_channel, api_key
    except Exception as e:
        logger.warning("Failed to parse webhook URL: %s", type(e).__name__)
        return None, None, None


def get_webhook_config() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Get organization ID, webhook channel, and API key from webhook URL"""
    webhook_url = settings.webhook_url
    if not webhook_url:
        return None, None, None
    return _parse_webhook_url(webhook_url)


def _write_dlq(event: Dict[str, Any], err: str, dlq_path: Optional[str] = None) -> None:
    """Write failed event to dead letter queue"""
    path = dlq_path or settings.precheck_dlq
    pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps({"err": err, "event": event}) + "\n")

    record_dlq_event(_error_type(err))
    _set_dlq_size(path)


def _error_type(err: str) -> str:
    """Normalize raw error strings to a stable error type label."""
    if not err:
        return "unknown"
    return err.split(":", 1)[0]


def _set_dlq_size(path: str) -> None:
    """Update DLQ size gauge from the current DLQ file line count."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            size = sum(1 for _ in f)
        set_dlq_size(size)
    except FileNotFoundError:
        set_dlq_size(0)
    except Exception as e:
        logger.warning("Failed to set DLQ size: %s", type(e).__name__)


async def _sleep_ms(ms: int):
    """Sleep for specified milliseconds"""
    await asyncio.sleep(ms / 1000.0)


async def _send_via_websocket(
    url: str, message: str, api_key: Optional[str], correlation_id: Optional[str] = None
) -> None:
    """Open a WebSocket connection, authenticate if key is available, then send message."""
    headers = {"X-Correlation-ID": correlation_id} if correlation_id else None
    async with websockets.connect(
        url,
        open_timeout=settings.webhook_timeout_s,
        close_timeout=settings.webhook_timeout_s,
        extra_headers=headers,
    ) as websocket:
        if api_key:
            auth_msg = json.dumps({"type": "AUTH", "apiKey": api_key})
            await websocket.send(auth_msg)
            try:
                auth_raw = await asyncio.wait_for(
                    websocket.recv(), timeout=settings.webhook_timeout_s
                )
                auth_resp = json.loads(auth_raw)
                if auth_resp.get("type") != "AUTH_SUCCESS":
                    raise ValueError(f"auth_failed:{auth_resp.get('error', 'unknown')}")
            except asyncio.TimeoutError:
                raise ValueError("auth_timeout")
        await websocket.send(message)


async def emit_event(event: Dict[str, Any], correlation_id: Optional[str] = None) -> None:
    """Sends the event via WebSocket to WEBHOOK_URL.
    Authenticates the connection before sending, so the raw API key never
    travels inside the INGEST payload.
    Falls back to DLQ (jsonl) after retries."""
    webhook_url = settings.webhook_url
    dlq_path = settings.precheck_dlq
    event_type = str(event.get("schema") or event.get("type") or "unknown")
    correlation = correlation_id or event.get("correlationId")
    if not correlation and isinstance(event.get("data"), dict):
        correlation = event["data"].get("correlationId")
    emit_started_at = time.time()

    if not webhook_url:
        _write_dlq(event, "webhook_url_not_configured", dlq_path)
        record_webhook_event(event_type, "failed", 0.0)
        return

    websocket_url = webhook_url
    # Extract key from URL for connection-level auth — never logged
    _, _, conn_api_key = _parse_webhook_url(webhook_url)

    message = json.dumps(event, separators=(",", ":"), ensure_ascii=False)

    delay_ms = settings.webhook_backoff_base_ms
    err = "no_attempts"
    for attempt in range(1, settings.webhook_max_retries + 1):
        try:
            await _send_via_websocket(websocket_url, message, conn_api_key, correlation)
            logger.debug("event emitted attempt=%d", attempt)
            record_webhook_event(event_type, "success", time.time() - emit_started_at)
            return
        except Exception as e:
            err = f"websocket_exception:{type(e).__name__}:{str(e)[:200]}"
            logger.warning(
                "websocket emit attempt %d/%d failed: %s",
                attempt, settings.webhook_max_retries, type(e).__name__,
            )

            if "SSL" in str(e) and websocket_url.startswith("wss://"):
                try:
                    fallback_url = websocket_url.replace("wss://", "ws://", 1)
                    await _send_via_websocket(fallback_url, message, conn_api_key, correlation)
                    logger.debug("event emitted via ssl fallback attempt=%d", attempt)
                    record_webhook_event(event_type, "success", time.time() - emit_started_at)
                    return
                except Exception as fallback_e:
                    err = f"websocket_fallback_exception:{type(fallback_e).__name__}:{str(fallback_e)[:200]}"
                    logger.warning(
                        "websocket ssl fallback attempt %d failed: %s",
                        attempt, type(fallback_e).__name__,
                    )

        if attempt == settings.webhook_max_retries:
            _write_dlq(event, err, dlq_path)
            record_webhook_event(event_type, "failed", time.time() - emit_started_at)
            return
        await _sleep_ms(delay_ms)
        delay_ms *= 2
