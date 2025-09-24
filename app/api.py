from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from .models import PrecheckReq, PrecheckRes
from .auth import require_api_key
from .policies import evaluate
from .rate_limit import rate_limiter
import time
import hashlib
import os
import json
import asyncio
import httpx

router = APIRouter()

WEBHOOK_URL = os.getenv("NEXT_WEBHOOK_URL", "")
DLQ_PATH = os.getenv("PRECHECK_DLQ", "/tmp/precheck.dlq.jsonl")

async def _post_event(event: dict) -> bool:
    """Post event to webhook with retry logic and DLQ fallback"""
    if not WEBHOOK_URL:
        return False
    
    async with httpx.AsyncClient(timeout=3.0) as client:
        for delay in (0.5, 1.0, 2.0):  # tiny backoff
            try:
                r = await client.post(WEBHOOK_URL, json=event)
                if r.status_code < 300:
                    return True
            except Exception:
                pass
            await asyncio.sleep(delay)
    
    # DLQ fallback
    try:
        with open(DLQ_PATH, "a") as f:
            f.write(json.dumps({"ts": int(time.time()), "event": event}) + "\n")
    except Exception:
        pass
    return False

@router.get("/v1/health")
async def health():
    """Health check endpoint"""
    return {
        "ok": True,
        "service": "governsai-precheck",
        "version": "0.0.1"
    }

@router.post("/v1/u/{user_id}/precheck", response_model=PrecheckRes)
async def precheck(
    user_id: str,
    body: PrecheckReq,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(require_api_key)
):
    """Precheck endpoint for policy evaluation and PII redaction"""
    # Rate limiting (100 requests per minute per user)
    if not rate_limiter.is_allowed(f"precheck:{user_id}", limit=100, window=60):
        raise HTTPException(status_code=429, detail="rate limit exceeded")
    
    start_time = time.time()
    now = int(start_time)
    res = evaluate(body.tool, body.scope, body.payload, now, direction="ingress")
    
    # Emit webhook event (fire-and-forget)
    if WEBHOOK_URL:
        payload_str = json.dumps(body.payload, sort_keys=True)
        payload_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
        
        event = {
            "userId": user_id,
            "tool": body.tool,
            "scope": body.scope,
            "decision": res["decision"],
            "policyId": res.get("policy_id"),
            "reasons": res.get("reasons", []),
            "payloadHash": payload_hash,
            "latencyMs": int((time.time() - start_time) * 1000),
            "timestamp": now,
            "correlationId": body.corr_id,
            "tags": body.tags or []
        }
        background_tasks.add_task(_post_event, event)
    
    return PrecheckRes(**res)

@router.post("/v1/u/{user_id}/postcheck", response_model=PrecheckRes)
async def postcheck(
    user_id: str,
    body: PrecheckReq,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(require_api_key)
):
    """Postcheck endpoint for post-execution validation"""
    # Rate limiting (100 requests per minute per user)
    if not rate_limiter.is_allowed(f"postcheck:{user_id}", limit=100, window=60):
        raise HTTPException(status_code=429, detail="rate limit exceeded")
    
    start_time = time.time()
    now = int(start_time)
    res = evaluate(body.tool, body.scope, body.payload, now, direction="egress")
    
    # Emit webhook event (fire-and-forget)
    if WEBHOOK_URL:
        payload_str = json.dumps(body.payload, sort_keys=True)
        payload_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
        
        event = {
            "userId": user_id,
            "tool": body.tool,
            "scope": body.scope,
            "decision": res["decision"],
            "policyId": res.get("policy_id"),
            "reasons": res.get("reasons", []),
            "payloadHash": payload_hash,
            "latencyMs": int((time.time() - start_time) * 1000),
            "timestamp": now,
            "correlationId": body.corr_id,
            "tags": body.tags or [],
            "direction": "postcheck"
        }
        background_tasks.add_task(_post_event, event)
    
    return PrecheckRes(**res)
