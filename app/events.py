import hmac
import hashlib
import json
import time
import httpx
import os
import pathlib
import asyncio
from typing import Any, Dict, Optional

WEBHOOK_URL = os.getenv("WEBHOOK_URL")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "dev-secret")
DLQ_PATH = os.getenv("PRECHECK_DLQ", "/tmp/precheck.dlq.jsonl")
TIMEOUT_S = float(os.getenv("WEBHOOK_TIMEOUT_S", "2.5"))
MAX_RETRIES = int(os.getenv("WEBHOOK_MAX_RETRIES", "3"))
BACKOFF_BASE_MS = int(os.getenv("WEBHOOK_BACKOFF_BASE_MS", "150"))

def _sign(body: bytes, ts: int) -> str:
    """Create HMAC signature for webhook authentication"""
    msg = f"{ts}.".encode() + body
    sig = hmac.new(WEBHOOK_SECRET.encode(), msg, hashlib.sha256).hexdigest()
    return f"v1,t={ts},s={sig}"

def _write_dlq(event: Dict[str, Any], err: str, dlq_path: Optional[str] = None) -> None:
    """Write failed event to dead letter queue"""
    path = dlq_path or DLQ_PATH
    pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps({"err": err, "event": event}) + "\n")

async def _sleep_ms(ms: int):
    """Sleep for specified milliseconds"""
    await asyncio.sleep(ms / 1000.0)

async def emit_event(event: Dict[str, Any]) -> None:
    """POSTs the event to WEBHOOK_URL with HMAC signature header.
    Falls back to DLQ (jsonl) after retries."""
    webhook_url = os.getenv("WEBHOOK_URL")
    dlq_path = os.getenv("PRECHECK_DLQ", "/tmp/precheck.dlq.jsonl")
    
    if not webhook_url:
        _write_dlq(event, "webhook_url_not_configured", dlq_path)
        return

    body = json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode()
    ts = int(time.time())

    headers = {
        "Content-Type": "application/json",
        "X-Governs-Signature": _sign(body, ts),
        "X-Governs-Event-Type": event.get("event_type", "policy.decision.v1"),
        "X-Governs-Corr-Id": event.get("corr_id", "-"),
    }

    # Retry with exponential backoff (jitter optional)
    delay_ms = BACKOFF_BASE_MS
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=TIMEOUT_S) as client:
                resp = await client.post(WEBHOOK_URL, content=body, headers=headers)
                if 200 <= resp.status_code < 300:
                    return
                err = f"http_{resp.status_code}"
        except Exception as e:
            err = f"exception:{type(e).__name__}:{str(e)[:200]}"

        if attempt == MAX_RETRIES:
            _write_dlq(event, err, dlq_path)
            return
        await _sleep_ms(delay_ms)
        delay_ms *= 2  # backoff
