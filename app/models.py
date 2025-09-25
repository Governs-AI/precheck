from pydantic import BaseModel, Field
from typing import Any, Optional, List, Dict

class PrePostCheckRequest(BaseModel):
    tool: str
    scope: Optional[str] = None
    payload: Dict[str, Any]
    tags: Optional[List[str]] = None
    corr_id: Optional[str] = None

class DecisionResponse(BaseModel):
    decision: str  # allow | deny | transform
    payload_out: Optional[Dict[str, Any]] = None  # sanitized payload to forward to LLM/tool
    reasons: Optional[List[str]] = None
    policy_id: Optional[str] = None
    ts: int

# Legacy models for backward compatibility
PrecheckReq = PrePostCheckRequest
PrecheckRes = DecisionResponse
