from pydantic import BaseModel, Field
from typing import Any, Optional, List, Dict

class ToolPolicy(BaseModel):
    """Tool-specific policy rules"""
    direction: str  # "ingress" or "egress"
    action: Optional[str] = None  # Override default action for this tool
    allow_pii: Dict[str, str] = {}  # PII:type -> action (pass_through, tokenize, redact, deny)

class PolicyConfig(BaseModel):
    """Policy configuration sent by agent"""
    version: str = "v1"
    
    # Global defaults for each direction
    defaults: Dict[str, Dict[str, str]] = {
        "ingress": {"action": "redact"},
        "egress": {"action": "redact"}
    }
    
    # Tool-specific policies
    tool_access: Dict[str, ToolPolicy] = {}
    
    # Dangerous tools to always deny
    deny_tools: List[str] = ["python.exec", "bash.exec", "code.exec", "shell.exec"]
    
    # Network scope patterns
    network_scopes: List[str] = ["net."]
    network_tools: List[str] = ["web.", "http.", "fetch.", "request."]
    
    # Error handling behavior
    on_error: str = "block"  # block | pass | best_effort

class ToolConfig(BaseModel):
    """Tool-specific configuration"""
    tool_name: str
    scope: Optional[str] = None
    direction: str  # "ingress" or "egress"
    metadata: Dict[str, Any] = {}  # Additional tool metadata

class PrePostCheckRequest(BaseModel):
    tool: str
    scope: Optional[str] = None
    raw_text: str  # Raw text input from user
    tags: Optional[List[str]] = None
    corr_id: Optional[str] = None
    
    # NEW: Policy and tool configuration from agent
    policy_config: Optional[PolicyConfig] = None
    tool_config: Optional[ToolConfig] = None

class DecisionResponse(BaseModel):
    decision: str  # allow | deny | transform
    raw_text_out: str  # Processed text with redundant values at place
    reasons: Optional[List[str]] = None
    policy_id: Optional[str] = None
    ts: int

# Legacy models for backward compatibility
PrecheckReq = PrePostCheckRequest
PrecheckRes = DecisionResponse
