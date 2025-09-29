from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Response
from .models import PrePostCheckRequest, DecisionResponse
from .auth import require_api_key
from .policies import evaluate
from .rate_limit import rate_limiter
from .events import emit_event, get_webhook_config
from .log import audit_log
from .metrics import (
    get_metrics, get_metrics_content_type, set_service_info,
    record_precheck_request, record_postcheck_request, record_policy_evaluation,
    set_active_requests
)
from .settings import settings
import time
import asyncio
import hashlib
import json
from datetime import datetime
from typing import List, Tuple, Optional

router = APIRouter()

def extract_pii_info_from_reasons(reasons: Optional[List[str]]) -> Tuple[List[str], float]:
    """Extract PII types and calculate confidence from reason codes"""
    pii_types = []
    confidence_scores = []
    
    if not reasons:
        return pii_types, 0.95  # Default confidence when no reasons
    
    for reason in reasons:
        if reason.startswith("pii."):
            # Extract PII type from reason codes like "pii.redacted:PII:email_address"
            parts = reason.split(":")
            if len(parts) >= 3:
                pii_type = parts[2]  # e.g., "email_address"
                pii_types.append(pii_type)
                
                # Assign confidence based on action type
                action = parts[1]  # e.g., "redacted", "allowed", "tokenized"
                if action == "allowed":
                    confidence_scores.append(0.9)  # High confidence for allowed
                elif action == "tokenized":
                    confidence_scores.append(0.8)  # High confidence for tokenized
                elif action == "redacted":
                    confidence_scores.append(0.7)  # Medium confidence for redacted
                else:
                    confidence_scores.append(0.5)  # Default confidence
    
    # Calculate average confidence, default to 0.95 if no PII detected
    avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.95
    
    return pii_types, avg_confidence

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

@router.get("/metrics")
async def metrics():
    """
    Prometheus metrics endpoint
    
    Returns metrics in Prometheus text format for monitoring and alerting.
    Includes counters, histograms, and gauges for request tracking, performance
    monitoring, and system health.
    """
    # Set service info if not already set
    set_service_info(
        version="0.0.1",
        build_date="2024-01-XX",
        git_commit="unknown"
    )
    
    metrics_data = get_metrics()
    return Response(
        content=metrics_data,
        media_type=get_metrics_content_type()
    )

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
    
    # Metrics: Track active requests
    set_active_requests("precheck", 1)
    
    start_time = time.time()
    start_ts = int(start_time)
    
    try:
        result = evaluate(req.tool, req.scope, req.raw_text, start_ts, direction="ingress")
        
        # Metrics: Record policy evaluation
        policy_eval_duration = time.time() - start_time
        record_policy_evaluation(
            tool=req.tool,
            direction="ingress", 
            policy_id=result.get("policy_id", "unknown"),
            duration=policy_eval_duration
        )
        
        # Extract PII information from reasons
        pii_types, confidence = extract_pii_info_from_reasons(result.get("reasons", []))
        
        # Get webhook configuration from URL
        webhook_org_id, webhook_channel, webhook_api_key = get_webhook_config()
        
        # Skip webhook emission if required values are not available from URL
        if not webhook_org_id or not webhook_channel:
            print(f"Warning: Missing webhook configuration - orgId: {webhook_org_id}, channel: {webhook_channel}")
            # Still return the response, just skip webhook emission
        else:
            # Build event
            event = {
                "type": "INGEST",
                "channel": webhook_channel,
                "schema": "decision.v1",
                "idempotencyKey": f"precheck-{start_ts}-{req.corr_id or 'unknown'}",
                "data": {
                    "orgId": webhook_org_id,
                    "direction": "precheck",
                    "decision": result["decision"],
                    "tool": req.tool,
                    "scope": req.scope,
                    "detectorSummary": {
                        "reasons": result.get("reasons", []),
                        "confidence": confidence,
                        "piiDetected": pii_types
                    },
                    "payloadHash": f"sha256:{hashlib.sha256(req.raw_text.encode()).hexdigest()}",
                    "latencyMs": int((time.time() - start_time) * 1000),
                    "correlationId": req.corr_id,
                    "tags": [],  # TODO: Extract from request or make configurable
                    "ts": f"{datetime.fromtimestamp(start_ts).isoformat()}Z"
                }
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
        
        # Metrics: Record precheck request
        total_duration = time.time() - start_time
        record_precheck_request(
            user_id=user_id,
            tool=req.tool,
            decision=result["decision"],
            policy_id=result.get("policy_id", "unknown"),
            duration=total_duration
        )
        
        return DecisionResponse(**result)
    
    except Exception as e:
        # Re-raise the exception after clearing metrics
        raise e
    
    finally:
        # Metrics: Clear active requests
        set_active_requests("precheck", 0)

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
    
    # Metrics: Track active requests
    set_active_requests("postcheck", 1)
    
    start_time = time.time()
    start_ts = int(start_time)
    
    try:
        result = evaluate(req.tool, req.scope, req.raw_text, start_ts, direction="egress")
        
        # Metrics: Record policy evaluation
        policy_eval_duration = time.time() - start_time
        record_policy_evaluation(
            tool=req.tool,
            direction="egress",
            policy_id=result.get("policy_id", "unknown"),
            duration=policy_eval_duration
        )
        
        # Extract PII information from reasons
        pii_types, confidence = extract_pii_info_from_reasons(result.get("reasons", []))
        
        # Get webhook configuration from URL
        webhook_org_id, webhook_channel, webhook_api_key = get_webhook_config()
        
        # Skip webhook emission if required values are not available from URL
        if not webhook_org_id or not webhook_channel:
            print(f"Warning: Missing webhook configuration - orgId: {webhook_org_id}, channel: {webhook_channel}")
            # Still return the response, just skip webhook emission
        else:
            # Build event
            event = {
                "type": "INGEST",
                "channel": webhook_channel,
                "schema": "decision.v1",
                "idempotencyKey": f"postcheck-{start_ts}-{req.corr_id or 'unknown'}",
                "data": {
                    "orgId": webhook_org_id,
                    "direction": "postcheck",
                    "decision": result["decision"],
                    "tool": req.tool,
                    "scope": req.scope,
                    "detectorSummary": {
                        "reasons": result.get("reasons", []),
                        "confidence": confidence,
                        "piiDetected": pii_types
                    },
                    "payloadHash": f"sha256:{hashlib.sha256(req.raw_text.encode()).hexdigest()}",
                    "latencyMs": int((time.time() - start_time) * 1000),
                    "correlationId": req.corr_id,
                    "tags": [],  # TODO: Extract from request or make configurable
                    "ts": f"{datetime.fromtimestamp(start_ts).isoformat()}Z"
                }
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
        
        # Metrics: Record postcheck request
        total_duration = time.time() - start_time
        record_postcheck_request(
            user_id=user_id,
            tool=req.tool,
            decision=result["decision"],
            policy_id=result.get("policy_id", "unknown"),
            duration=total_duration
        )
        
        return DecisionResponse(**result)
    
    except Exception as e:
        # Re-raise the exception after clearing metrics
        raise e
    
    finally:
        # Metrics: Clear active requests
        set_active_requests("postcheck", 0)
