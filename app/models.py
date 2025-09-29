from pydantic import BaseModel, Field
from typing import Any, Optional, List, Dict

class PrePostCheckRequest(BaseModel):
    tool: str
    scope: Optional[str] = None
    raw_text: str  # Raw text input from user
    tags: Optional[List[str]] = None
    corr_id: Optional[str] = None

class DecisionResponse(BaseModel):
    decision: str  # allow | deny | transform
    raw_text_out: str  # Processed text with redundant values at place
    reasons: Optional[List[str]] = None
    policy_id: Optional[str] = None
    ts: int

# Legacy models for backward compatibility
PrecheckReq = PrePostCheckRequest
PrecheckRes = DecisionResponse
