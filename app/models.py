from pydantic import BaseModel, Field
from typing import Any, Optional, List, Dict

class PrecheckReq(BaseModel):
    tool: str
    scope: Optional[str] = None
    payload: Dict[str, Any]
    tags: Optional[List[str]] = None
    corr_id: Optional[str] = None

class PrecheckRes(BaseModel):
    decision: str  # allow | deny | transform
    payload: Optional[Dict[str, Any]] = None
    reasons: Optional[List[str]] = None
    policy_id: Optional[str] = None
    ts: int
