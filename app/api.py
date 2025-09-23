from fastapi import APIRouter, Depends, HTTPException
from .models import PrecheckReq, PrecheckRes
from .auth import require_api_key
from .policies import evaluate
from .rate_limit import rate_limiter
import time
import hashlib

router = APIRouter()

@router.get("/v1/health")
async def health():
    """Health check endpoint"""
    return {
        "ok": True,
        "service": "governsai-precheck",
        "version": "0.0.1"
    }

@router.post("/u/{user_id}/v1/precheck", response_model=PrecheckRes)
async def precheck(
    user_id: str,
    body: PrecheckReq,
    api_key: str = Depends(require_api_key)
):
    """Precheck endpoint for policy evaluation and PII redaction"""
    # Rate limiting (100 requests per minute per user)
    if not rate_limiter.is_allowed(f"precheck:{user_id}", limit=100, window=60):
        raise HTTPException(status_code=429, detail="rate limit exceeded")
    
    now = int(time.time())
    res = evaluate(body.tool, body.scope, body.payload, now)
    
    # TODO: Emit usage_event asynchronously (no payloads, hashes only)
    # TODO: Log to database for audit trail
    # TODO: Hash payload for deduplication: hashlib.sha256(str(body.payload).encode()).hexdigest()
    
    return PrecheckRes(**res)

@router.post("/u/{user_id}/v1/postcheck", response_model=PrecheckRes)
async def postcheck(
    user_id: str,
    body: PrecheckReq,
    api_key: str = Depends(require_api_key)
):
    """Postcheck endpoint for post-execution validation"""
    # Rate limiting (100 requests per minute per user)
    if not rate_limiter.is_allowed(f"postcheck:{user_id}", limit=100, window=60):
        raise HTTPException(status_code=429, detail="rate limit exceeded")
    
    # For now, same as precheck - can be extended later
    now = int(time.time())
    res = evaluate(body.tool, body.scope, body.payload, now)
    
    return PrecheckRes(**res)
