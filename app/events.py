import asyncio
import json
import logging
import pathlib
import time
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import websockets

from .metrics import record_dlq_event, record_webhook_event, set_dlq_size
from .settings import settings

logger = logging.getLogger(__name__)

# websockets 14 replaced the legacy client; its connect() takes
# `additional_headers` and rejects the old `extra_headers` keyword.
_HEADERS_KWARG = (
    "additional_headers"
    if int(websockets.__version__.split(".")[0]) >= 14
    else "extra_headers"
)


def build_webhook_url(
    base_url: str,
    org_id: str,
    conn_key: Optional[str] = None,
) -> str:
    """Build a per-org websocket URL by appending org/key/channels query params
    to the configured base URL.

    The dashboard websocket gateway expects:
      - org: tenant identifier — drives channel routing on the receiving side
      - key: connection-level API key the dashboard uses to authenticate the
        precheck service (NOT a per-request user key)
      - channels: comma-separated subscription list; we always include
        org:<id>:decisions so the dashboard delivers this org's decisions
    """
    if not base_url:
        raise ValueError("base_url is required")
    if not org_id:
        raise ValueError("org_id is required")

    parts = urlsplit(base_url)
    existing = [
        (k, v)
        for (k, v) in parse_qsl(parts.query, keep_blank_values=True)
        if k not in ("org", "key", "channels")
    ]
    new_params = [("org", org_id)]
    if conn_key:
        new_params.append(("key", conn_key))
    new_params.append(("channels", f"org:{org_id}:decisions"))

    query = urlencode(existing + new_params)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


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


async def _sleep_ms(ms: int) -> None:
    """Sleep for specified milliseconds"""
    await asyncio.sleep(ms / 1000.0)


async def _recv_until(websocket: Any, wanted: set, timeout_s: float) -> Dict[str, Any]:
    """Read frames until one whose `type` is in `wanted` (or an ERROR) arrives.

    The gateway greets every connection with a READY frame before anything
    else, so the first frame is not necessarily the reply we are waiting for.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_s
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise asyncio.TimeoutError()
        raw = await asyncio.wait_for(websocket.recv(), timeout=remaining)
        try:
            frame = json.loads(raw)
        except (TypeError, ValueError):
            continue
        frame_type = frame.get("type")
        if frame_type in wanted:
            return frame
        if frame_type == "ERROR":
            raise ValueError(
                f"{frame.get('error') or frame.get('code') or 'error'}:"
                f"{str(frame.get('message', ''))[:200]}"
            )


async def _send_via_websocket(
    url: str, message: str, api_key: Optional[str], correlation_id: Optional[str] = None
) -> None:
    """Open a WebSocket connection, authenticate, send, and wait for the ACK.

    Waiting for the ACK means a decision the gateway failed to persist ends up
    in the DLQ instead of being silently dropped on close.
    """
    headers = {"X-Correlation-ID": correlation_id} if correlation_id else None
    timeout_s = settings.webhook_timeout_s
    connect_kwargs: Dict[str, Any] = {_HEADERS_KWARG: headers}
    async with websockets.connect(
        url,
        open_timeout=timeout_s,
        close_timeout=timeout_s,
        **connect_kwargs,
    ) as websocket:
        if api_key:
            auth_msg = json.dumps({"type": "AUTH", "apiKey": api_key})
            await websocket.send(auth_msg)
            try:
                await _recv_until(websocket, {"AUTH_SUCCESS"}, timeout_s)
            except asyncio.TimeoutError:
                raise ValueError("auth_timeout")
            except ValueError as e:
                raise ValueError(f"auth_failed:{e}")
        await websocket.send(message)
        try:
            await _recv_until(websocket, {"ACK"}, timeout_s)
        except asyncio.TimeoutError:
            raise ValueError("ack_timeout")


async def emit_event(
    event: Dict[str, Any],
    org_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    auth_key: Optional[str] = None,
) -> None:
    """Send the event over WebSocket to the org-specific gateway URL.

    The connection URL is built from settings.webhook_base_url plus the caller-
    supplied org_id. The gateway attributes a decision to the org of the key
    that authenticated the connection, so the request's own API key
    (`auth_key`) is preferred; `webhook_conn_key` is the fallback. Keys are
    sent in the AUTH frame — a per-request key never travels as a URL param.

    Falls back to DLQ (jsonl) when:
      - webhook_base_url is not configured
      - org_id is missing (we cannot route without it)
      - all retries are exhausted
    """
    base_url = settings.webhook_base_url
    conn_key = settings.webhook_conn_key
    send_key = auth_key or conn_key
    dlq_path = settings.precheck_dlq
    event_type = str(event.get("schema") or event.get("type") or "unknown")
    correlation = correlation_id or event.get("correlationId")
    if not correlation and isinstance(event.get("data"), dict):
        correlation = event["data"].get("correlationId")
    emit_started_at = time.time()

    if not base_url:
        _write_dlq(event, "webhook_base_url_not_configured", dlq_path)
        record_webhook_event(event_type, "failed", 0.0)
        return

    if not org_id:
        _write_dlq(event, "missing_org_id", dlq_path)
        record_webhook_event(event_type, "failed", 0.0)
        return

    try:
        websocket_url = build_webhook_url(base_url, org_id, conn_key)
    except ValueError as e:
        _write_dlq(event, f"invalid_webhook_url:{type(e).__name__}", dlq_path)
        record_webhook_event(event_type, "failed", 0.0)
        return

    message = json.dumps(event, separators=(",", ":"), ensure_ascii=False)

    delay_ms = settings.webhook_backoff_base_ms
    err = "no_attempts"
    for attempt in range(1, settings.webhook_max_retries + 1):
        try:
            await _send_via_websocket(websocket_url, message, send_key, correlation)
            logger.debug("event emitted attempt=%d", attempt)
            record_webhook_event(event_type, "success", time.time() - emit_started_at)
            return
        except Exception as e:
            err = f"websocket_exception:{type(e).__name__}:{str(e)[:200]}"
            logger.warning(
                "websocket emit attempt %d/%d failed: %s",
                attempt,
                settings.webhook_max_retries,
                type(e).__name__,
            )

        if attempt == settings.webhook_max_retries:
            _write_dlq(event, err, dlq_path)
            record_webhook_event(event_type, "failed", time.time() - emit_started_at)
            return
        await _sleep_ms(delay_ms)
        delay_ms *= 2
