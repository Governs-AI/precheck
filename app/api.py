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

@router.get("/v1/ready")
async def ready():
    """
    Readiness check endpoint
    
    Performs comprehensive checks to ensure the service is ready to handle requests:
    - Presidio analyzer and anonymizer initialization
    - Policy file parsing and validation
    - Core dependencies availability
    """
    from .policies import ANALYZER, ANONYMIZER, USE_PRESIDIO, get_policy
    from .settings import settings
    import os
    
    checks = {}
    overall_ready = True
    
    # Check Presidio initialization
    if USE_PRESIDIO:
        if ANALYZER is not None and ANONYMIZER is not None:
            checks["presidio"] = {"status": "ok", "message": "Presidio analyzer and anonymizer initialized"}
        else:
            checks["presidio"] = {"status": "error", "message": "Presidio failed to initialize"}
            overall_ready = False
    else:
        checks["presidio"] = {"status": "disabled", "message": "Presidio disabled, using regex fallback"}
    
    # Check policy file parsing
    try:
        policy = get_policy()
        if policy and ("version" in policy or "tool_access" in policy or "defaults" in policy):
            checks["policy"] = {"status": "ok", "message": f"Policy loaded with {len(policy)} sections"}
        else:
            checks["policy"] = {"status": "warning", "message": "Policy loaded but appears empty"}
    except Exception as e:
        checks["policy"] = {"status": "error", "message": f"Policy parsing failed: {str(e)}"}
        overall_ready = False
    
    # Check policy file exists
    policy_file = getattr(settings, 'policy_file', 'policy.tool_access.yaml')
    if not os.path.exists(policy_file):
        policy_file = os.path.join(os.path.dirname(__file__), "..", "policy.tool_access.yaml")
    
    if os.path.exists(policy_file):
        checks["policy_file"] = {"status": "ok", "message": f"Policy file exists: {policy_file}"}
    else:
        checks["policy_file"] = {"status": "error", "message": f"Policy file not found: {policy_file}"}
        overall_ready = False
    
    # Check critical environment variables
    env_checks = {}
    critical_env_vars = ["PII_TOKEN_SALT", "ON_ERROR"]
    for var in critical_env_vars:
        if hasattr(settings, var.lower()):
            env_checks[var] = "ok"
        else:
            env_checks[var] = "missing"
            overall_ready = False
    
    checks["environment"] = {
        "status": "ok" if all(v == "ok" for v in env_checks.values()) else "error",
        "message": f"Environment variables: {env_checks}"
    }
    
    # Check DLQ directory accessibility
    try:
        dlq_path = settings.precheck_dlq
        dlq_dir = os.path.dirname(dlq_path)
        os.makedirs(dlq_dir, exist_ok=True)
        checks["dlq"] = {"status": "ok", "message": f"DLQ directory accessible: {dlq_dir}"}
    except Exception as e:
        checks["dlq"] = {"status": "error", "message": f"DLQ directory error: {str(e)}"}
        overall_ready = False
    
    return {
        "ready": overall_ready,
        "service": "governsai-precheck",
        "version": "0.0.1",
        "checks": checks,
        "timestamp": int(time.time())
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
