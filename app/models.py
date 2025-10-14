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
    
    # Model information for cost estimation
    model: str = "gpt-4"

class ToolConfig(BaseModel):
    """Tool-specific configuration"""
    tool_name: str
    scope: Optional[str] = None
    direction: str  # "ingress" or "egress"
    metadata: Dict[str, Any] = {}  # Additional tool metadata

class BudgetContext(BaseModel):
    """Budget context information from agent"""
    monthly_limit: float
    current_spend: float
    llm_spend: float
    purchase_spend: float
    remaining_budget: float
    budget_type: str  # "user" or "organization"

class PrePostCheckRequest(BaseModel):
    tool: str
    scope: Optional[str] = None
    raw_text: str  # Raw text input from user
    tags: Optional[List[str]] = None
    corr_id: Optional[str] = None
    user_id: Optional[str] = None  # Optional - websocket will resolve from API key
    
    # NEW: Policy and tool configuration from agent
    policy_config: Optional[PolicyConfig] = None
    tool_config: Optional[ToolConfig] = None
    budget_context: Optional[BudgetContext] = None

class BudgetStatus(BaseModel):
    """Budget status information"""
    allowed: bool
    currentSpend: float
    limit: float
    remaining: float
    percentUsed: float
    reason: str

class BudgetInfo(BaseModel):
    """Detailed budget information"""
    monthly_limit: float
    current_spend: float
    llm_spend: float
    purchase_spend: float
    remaining_budget: float
    estimated_cost: float
    estimated_purchase: Optional[float] = None
    projected_total: float
    percent_used: float
    budget_type: str  # "user" or "organization"

class DecisionResponse(BaseModel):
    decision: str  # allow | deny | transform | confirm
    raw_text_out: str  # Processed text with redundant values at place
    reasons: Optional[List[str]] = None
    policy_id: Optional[str] = None
    ts: int
    budget_status: Optional[BudgetStatus] = None
    budget_info: Optional[BudgetInfo] = None

# Legacy models for backward compatibility
PrecheckReq = PrePostCheckRequest
PrecheckRes = DecisionResponse
