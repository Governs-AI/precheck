"""
Budget management and cost estimation for precheck service
"""

from typing import Optional, Tuple, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from .storage import Budget, BudgetTransaction, get_db
from .models import BudgetStatus, BudgetInfo
import json

# Cost estimation constants (per token/request)
MODEL_COSTS = {
    "gpt-4": {"input": 0.00003, "output": 0.00006},  # per token
    "gpt-4-turbo": {"input": 0.00001, "output": 0.00003},
    "gpt-3.5-turbo": {"input": 0.0000015, "output": 0.000002},
    "claude-3-opus": {"input": 0.000015, "output": 0.000075},
    "claude-3-sonnet": {"input": 0.000003, "output": 0.000015},
    "claude-3-haiku": {"input": 0.00000025, "output": 0.00000125},
}

def estimate_llm_cost(model: str, input_tokens: int = 0, output_tokens: int = 0) -> float:
    """Estimate LLM cost based on model and token usage"""
    if model not in MODEL_COSTS:
        model = "gpt-3.5-turbo"  # Default fallback
    
    costs = MODEL_COSTS[model]
    input_cost = input_tokens * costs["input"]
    output_cost = output_tokens * costs["output"]
    
    return input_cost + output_cost

def estimate_request_cost(raw_text: str, model: str = "gpt-4") -> float:
    """Estimate cost for a single request based on text length"""
    # Rough estimation: 1 token ≈ 4 characters for English text
    estimated_tokens = len(raw_text) // 4
    
    # Estimate 50% input, 50% output for typical requests
    input_tokens = int(estimated_tokens * 0.5)
    output_tokens = int(estimated_tokens * 0.5)
    
    return estimate_llm_cost(model, input_tokens, output_tokens)

def get_purchase_amount(tool_config: Dict[str, Any]) -> Optional[float]:
    """Extract purchase amount from tool config metadata"""
    metadata = tool_config.get("metadata", {})
    
    # Check various possible fields for purchase amount
    for field in ["purchase_amount", "amount", "price", "cost"]:
        if field in metadata:
            try:
                return float(metadata[field])
            except (ValueError, TypeError):
                continue
    
    return None

def get_user_budget(user_id: str, db: Session) -> Budget:
    """Get or create budget for user"""
    budget = db.query(Budget).filter(Budget.user_id == user_id).first()
    
    if not budget:
        budget = Budget(
            user_id=user_id,
            monthly_limit=10.0,  # Default $10/month
            current_spend=0.0,
            llm_spend=0.0,
            purchase_spend=0.0,
            budget_type="user"
        )
        db.add(budget)
        db.commit()
        db.refresh(budget)
    
    # Reset budget if it's a new month
    now = datetime.utcnow()
    if budget.last_reset.month != now.month or budget.last_reset.year != now.year:
        budget.current_spend = 0.0
        budget.llm_spend = 0.0
        budget.purchase_spend = 0.0
        budget.last_reset = now
        db.commit()
    
    return budget

def check_budget_with_context(
    budget_context: Dict,
    estimated_llm_cost: float, 
    estimated_purchase: Optional[float] = None
) -> Tuple[BudgetStatus, BudgetInfo]:
    """Check budget using context from request payload"""
    
    # Extract budget information from context
    monthly_limit = budget_context.get("monthly_limit", 0.0)
    current_spend = budget_context.get("current_spend", 0.0)
    llm_spend = budget_context.get("llm_spend", 0.0)
    purchase_spend = budget_context.get("purchase_spend", 0.0)
    remaining_budget = budget_context.get("remaining_budget", 0.0)
    budget_type = budget_context.get("budget_type", "user")
    
    # Calculate projected total
    projected_llm = llm_spend + estimated_llm_cost
    projected_purchase = purchase_spend + (estimated_purchase or 0.0)
    projected_total = projected_llm + projected_purchase
    
    # Check if within budget
    within_budget = projected_total <= monthly_limit
    
    # Calculate percentages
    current_percent = (current_spend / monthly_limit) * 100 if monthly_limit > 0 else 0
    projected_percent = (projected_total / monthly_limit) * 100 if monthly_limit > 0 else 0
    
    # Determine reason
    if not within_budget:
        reason = "budget_exceeded"
    elif projected_percent > 90:
        reason = "budget_warning"
    else:
        reason = "budget_ok"
    
    # Create budget status
    budget_status = BudgetStatus(
        allowed=within_budget,
        currentSpend=current_spend,
        limit=monthly_limit,
        remaining=monthly_limit - current_spend,
        percentUsed=current_percent,
        reason=reason
    )
    
    # Create detailed budget info
    budget_info = BudgetInfo(
        monthly_limit=monthly_limit,
        current_spend=current_spend,
        llm_spend=llm_spend,
        purchase_spend=purchase_spend,
        remaining_budget=remaining_budget,
        estimated_cost=estimated_llm_cost,
        estimated_purchase=estimated_purchase,
        projected_total=projected_total,
        percent_used=projected_percent,
        budget_type=budget_type
    )
    
    return budget_status, budget_info

def check_budget(
    user_id: str, 
    estimated_llm_cost: float, 
    estimated_purchase: Optional[float] = None,
    db: Optional[Session] = None
) -> Tuple[BudgetStatus, BudgetInfo]:
    """Check if request is within budget limits"""
    
    if db is None:
        db = next(get_db())
    
    try:
        budget = get_user_budget(user_id, db)
        
        # Calculate projected total
        projected_llm = budget.llm_spend + estimated_llm_cost
        projected_purchase = budget.purchase_spend + (estimated_purchase or 0.0)
        projected_total = projected_llm + projected_purchase
        
        # Check if within budget
        within_budget = projected_total <= budget.monthly_limit
        
        # Calculate percentages
        current_percent = (budget.current_spend / budget.monthly_limit) * 100
        projected_percent = (projected_total / budget.monthly_limit) * 100
        
        # Determine reason
        if not within_budget:
            reason = "budget_exceeded"
        elif projected_percent > 90:
            reason = "budget_warning"
        else:
            reason = "budget_ok"
        
        # Create budget status
        budget_status = BudgetStatus(
            allowed=within_budget,
            currentSpend=budget.current_spend,
            limit=budget.monthly_limit,
            remaining=budget.monthly_limit - budget.current_spend,
            percentUsed=current_percent,
            reason=reason
        )
        
        # Create detailed budget info
        budget_info = BudgetInfo(
            monthly_limit=budget.monthly_limit,
            current_spend=budget.current_spend,
            llm_spend=budget.llm_spend,
            purchase_spend=budget.purchase_spend,
            remaining_budget=budget.monthly_limit - budget.current_spend,
            estimated_cost=estimated_llm_cost,
            estimated_purchase=estimated_purchase,
            projected_total=projected_total,
            percent_used=projected_percent,
            budget_type=budget.budget_type
        )
        
        return budget_status, budget_info
        
    finally:
        if db:
            db.close()

def record_budget_transaction(
    user_id: str,
    transaction_type: str,  # "llm" or "purchase"
    amount: float,
    description: str = "",
    tool: str = "",
    correlation_id: str = "",
    db: Optional[Session] = None
) -> None:
    """Record a budget transaction"""
    
    if db is None:
        db = next(get_db())
    
    try:
        # Create transaction record
        transaction = BudgetTransaction(
            user_id=user_id,
            transaction_type=transaction_type,
            amount=amount,
            description=description,
            tool=tool,
            correlation_id=correlation_id
        )
        db.add(transaction)
        
        # Update budget
        budget = get_user_budget(user_id, db)
        budget.current_spend += amount
        
        if transaction_type == "llm":
            budget.llm_spend += amount
        elif transaction_type == "purchase":
            budget.purchase_spend += amount
        
        db.commit()
        
    finally:
        if db:
            db.close()

def update_budget_after_decision(
    user_id: str,
    decision: str,
    estimated_llm_cost: float,
    estimated_purchase: Optional[float] = None,
    tool: str = "",
    correlation_id: str = "",
    db: Optional[Session] = None
) -> None:
    """Update budget after policy decision is made"""
    
    # Only record if decision allows the request
    if decision in ["allow", "transform", "confirm"]:
        if estimated_llm_cost > 0:
            record_budget_transaction(
                user_id=user_id,
                transaction_type="llm",
                amount=estimated_llm_cost,
                description=f"LLM usage for {tool}",
                tool=tool,
                correlation_id=correlation_id,
                db=db
            )
        
        if estimated_purchase and estimated_purchase > 0:
            record_budget_transaction(
                user_id=user_id,
                transaction_type="purchase",
                amount=estimated_purchase,
                description=f"Purchase via {tool}",
                tool=tool,
                correlation_id=correlation_id,
                db=db
            )
