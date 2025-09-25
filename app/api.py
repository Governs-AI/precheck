from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from .models import PrePostCheckRequest, DecisionResponse
from .auth import require_api_key
from .policies import evaluate
from .rate_limit import rate_limiter
from .events import emit_event
from .log import audit_log
import time
import asyncio

router = APIRouter()

@router.get("/v1/health")
async def health():
    """Health check endpoint"""
    return {
        "ok": True,
        "service": "governsai-precheck",
        "version": "0.0.1"
    }

@router.post("/v1/u/{user_id}/precheck", response_model=DecisionResponse)
async def precheck(
    user_id: str,
    req: PrePostCheckRequest,
    api_key: str = Depends(require_api_key)
):
    """Precheck endpoint for policy evaluation and PII redaction"""
    # Rate limiting (100 requests per minute per user)
    if not rate_limiter.is_allowed(f"precheck:{user_id}", limit=100, window=60):
        raise HTTPException(status_code=429, detail="rate limit exceeded")
    
    start_ts = int(time.time())
    result = evaluate(req.tool, req.scope, req.payload, start_ts, direction="ingress")
    
    # Build event
    event = {
        "event_type": "policy.decision.v1",
        "direction": "ingress",
        "user_id": user_id,
        "tool": req.tool,
        "scope": req.scope,
        "corr_id": req.corr_id,
        "decision": result["decision"],
        "policy_id": result.get("policy_id"),
        "reasons": result.get("reasons", []),
        "payload_before": req.payload,
        "payload_after": result.get("payload_out"),
        "ts": start_ts,
    }
    
    # Fire and forget (don't block response path)
    try:
        asyncio.create_task(emit_event(event))
    except RuntimeError:
        # If no running loop (tests), do it inline once
        await emit_event(event)
    
    # Audit log before response
    audit_log("precheck", 
              user_id=user_id, 
              tool=req.tool, 
              decision=result["decision"], 
              corr_id=req.corr_id,
              policy_id=result.get("policy_id"),
              reasons=result.get("reasons", []))
    
    return DecisionResponse(**result)

@router.post("/v1/u/{user_id}/postcheck", response_model=DecisionResponse)
async def postcheck(
    user_id: str,
    req: PrePostCheckRequest,
    api_key: str = Depends(require_api_key)
):
    """Postcheck endpoint for post-execution validation"""
    # Rate limiting (100 requests per minute per user)
    if not rate_limiter.is_allowed(f"postcheck:{user_id}", limit=100, window=60):
        raise HTTPException(status_code=429, detail="rate limit exceeded")
    
    start_ts = int(time.time())
    result = evaluate(req.tool, req.scope, req.payload, start_ts, direction="egress")
    
    # Build event
    event = {
        "event_type": "policy.decision.v1",
        "direction": "egress",
        "user_id": user_id,
        "tool": req.tool,
        "scope": req.scope,
        "corr_id": req.corr_id,
        "decision": result["decision"],
        "policy_id": result.get("policy_id"),
        "reasons": result.get("reasons", []),
        "payload_before": req.payload,
        "payload_after": result.get("payload_out"),
        "ts": start_ts,
    }
    
    # Fire and forget (don't block response path)
    try:
        asyncio.create_task(emit_event(event))
    except RuntimeError:
        # If no running loop (tests), do it inline once
        await emit_event(event)
    
    # Audit log before response
    audit_log("postcheck", 
              user_id=user_id, 
              tool=req.tool, 
              decision=result["decision"], 
              corr_id=req.corr_id,
              policy_id=result.get("policy_id"),
              reasons=result.get("reasons", []))
    
    return DecisionResponse(**result)
