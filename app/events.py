import json
import time
import pathlib
import asyncio
import websockets
from urllib.parse import urlparse, parse_qs
from typing import Any, Dict, Optional, Tuple
from .settings import settings

def _parse_webhook_url(webhook_url: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Parse webhook URL to extract org ID, decisions channel, and API key"""
    if not webhook_url:
        return None, None, None
    
    try:
        parsed = urlparse(webhook_url)
        query_params = parse_qs(parsed.query)
        
        # Extract org ID from 'org' parameter
        org_id = query_params.get('org', [None])[0]
        
        # Extract API key from 'key' parameter
        api_key = query_params.get('key', [None])[0]
        
        # Extract decisions channel from 'channels' parameter
        channels = query_params.get('channels', [None])[0]
        decisions_channel = None
        
        if channels:
            # Split channels by comma and find the decisions channel
            channel_list = [ch.strip() for ch in channels.split(',')]
            for channel in channel_list:
                if channel.endswith(':decisions'):
                    decisions_channel = channel
                    break
        
        return org_id, decisions_channel, api_key
    except Exception as e:
        print(f"Error parsing webhook URL: {e}")
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

async def _sleep_ms(ms: int):
    """Sleep for specified milliseconds"""
    await asyncio.sleep(ms / 1000.0)

async def emit_event(event: Dict[str, Any]) -> None:
    """Sends the event via WebSocket to WEBHOOK_URL.
    Falls back to DLQ (jsonl) after retries."""
    webhook_url = settings.webhook_url
    print(f"WEBHOOK_URL: {webhook_url}")
    dlq_path = settings.precheck_dlq
    
    if not webhook_url:
        _write_dlq(event, "webhook_url_not_configured", dlq_path)
        return

    # Use the WebSocket URL as-is (don't force SSL conversion)
    websocket_url = webhook_url
    print(f"WebSocket URL: {websocket_url}")

    # Prepare the message as JSON
    message = json.dumps(event, separators=(",", ":"), ensure_ascii=False)
    print(f"WebSocket message: {message}")

    # Retry with exponential backoff
    delay_ms = settings.webhook_backoff_base_ms
    for attempt in range(1, settings.webhook_max_retries + 1):
        try:
            # Use open_timeout and close_timeout instead of timeout
            async with websockets.connect(
                websocket_url, 
                open_timeout=settings.webhook_timeout_s,
                close_timeout=settings.webhook_timeout_s
            ) as websocket:
                await websocket.send(message)
                print(f"WebSocket message sent successfully")
                return
        except Exception as e:
            err = f"websocket_exception:{type(e).__name__}:{str(e)[:200]}"
            print(f"WebSocket attempt {attempt} failed: {err}")
            
            # If it's an SSL error and we're using wss://, try ws:// instead
            if "SSL" in str(e) and websocket_url.startswith("wss://"):
                try:
                    fallback_url = websocket_url.replace("wss://", "ws://", 1)
                    print(f"Trying fallback URL: {fallback_url}")
                    async with websockets.connect(
                        fallback_url, 
                        open_timeout=settings.webhook_timeout_s,
                        close_timeout=settings.webhook_timeout_s
                    ) as websocket:
                        await websocket.send(message)
                        print(f"WebSocket message sent successfully via fallback")
                        return
                except Exception as fallback_e:
                    err = f"websocket_fallback_exception:{type(fallback_e).__name__}:{str(fallback_e)[:200]}"
                    print(f"WebSocket fallback attempt failed: {err}")

        if attempt == settings.webhook_max_retries:
            _write_dlq(event, err, dlq_path)
            return
        await _sleep_ms(delay_ms)
        delay_ms *= 2  # backoff