# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""Budget caps hold on every policy path.

The cap used to be checked only when the tool had its own tool_access rule
(or the default action was confirm). A purchase through any other path —
network-scope redaction, the strict fallback, pass_through/tokenize
defaults, a tool rule that redacted PII — went through past the cap. These
tests pin the cap on each path, with and without a user_id.
"""

from datetime import datetime

import pytest

from app import policy_source
from app.policies import evaluate_with_payload_policy
from app.storage import DashboardPolicy

ORG = "org-budget"
CAP = 1000.0
PURCHASE = 45.0


def _context(purchase_spend: float, monthly_limit: float = CAP) -> dict:
    return {
        "monthly_limit": monthly_limit,
        "current_spend": purchase_spend,
        "llm_spend": 0.0,
        "purchase_spend": purchase_spend,
        "remaining_budget": max(0.0, monthly_limit - purchase_spend),
        "budget_type": "user",
    }


OVER_CAP = _context(980.0)  # 980 + 45 = 1025 > 1000
NEAR_CAP = _context(900.0)  # 900 + 45 = 945 → 94.5%, warning
WELL_UNDER = _context(100.0)  # 100 + 45 = 145 → 14.5%

PURCHASE_TOOL_CONFIG = {
    "tool_name": "shop.checkout",
    "metadata": {"purchase_amount": PURCHASE},
}


def _row(**overrides) -> DashboardPolicy:
    fields = dict(
        id="pol-budget",
        org_id=ORG,
        name="budget policy",
        version="v1",
        defaults={"ingress": {"action": "redact"}, "egress": {"action": "redact"}},
        tool_access={},
        deny_tools=[],
        allow_tools=[],
        network_scopes=[],
        network_tools=[],
        on_error="block",
        is_active=True,
        priority=0,
        updated_at=datetime(2026, 11, 1, 12, 0, 0),
    )
    fields.update(overrides)
    return DashboardPolicy(**fields)


@pytest.fixture
def org_policy(monkeypatch):
    holder = {"row": _row()}

    def fake_get_active_policy(org_id):
        if org_id != ORG:
            return None
        return policy_source._map_row_to_policy_config(holder["row"])

    monkeypatch.setattr(policy_source, "get_active_policy", fake_get_active_policy)

    def set_row(**overrides):
        holder["row"] = _row(**overrides)

    return set_row


def _eval(
    budget_context,
    *,
    scope="net.external",
    text="Check out cart 77",
    user_id="user-1",
    tool_config=PURCHASE_TOOL_CONFIG,
):
    return evaluate_with_payload_policy(
        tool="shop.checkout",
        scope=scope,
        raw_text=text,
        now=1000,
        org_id=ORG,
        user_id=user_id,
        tool_config=tool_config,
        budget_context=budget_context,
    )


# Each entry is (policy row overrides, eval kwargs): one per decision path.
PATHS = {
    "network-redaction default": ({}, {"scope": "net.external"}),
    "strict fallback default": ({}, {"scope": "local"}),
    "pass_through default": (
        {"defaults": {"ingress": {"action": "allow"}}},
        {},
    ),
    "tokenize default": (
        {"defaults": {"ingress": {"action": "tokenize"}}},
        {},
    ),
    "confirm default": (
        {"defaults": {"ingress": {"action": "confirm"}}},
        {},
    ),
    "tool rule allow": (
        {"tool_access": {"shop.checkout": {"action": "allow"}}},
        {},
    ),
    "tool rule redact with PII": (
        {"tool_access": {"shop.checkout": {"action": "redact"}}},
        {"text": "Check out cart 77 for jane.doe@example.com"},
    ),
    "tool rule confirm": (
        {"tool_access": {"shop.checkout": {"action": "confirm"}}},
        {},
    ),
}


@pytest.mark.parametrize("path", sorted(PATHS))
def test_purchase_over_cap_is_denied_on_every_path(org_policy, path):
    row, kwargs = PATHS[path]
    org_policy(**row)

    result = _eval(OVER_CAP, **kwargs)

    assert result["decision"] == "deny"
    assert result["reasons"] == ["budget_exceeded"]
    assert result["policy_id"] == "budget-check"
    assert result["budget_status"].allowed is False


@pytest.mark.parametrize("path", sorted(PATHS))
def test_purchase_near_cap_needs_confirmation_on_every_path(org_policy, path):
    row, kwargs = PATHS[path]
    org_policy(**row)

    result = _eval(NEAR_CAP, **kwargs)

    assert result["decision"] == "confirm"
    assert "budget_warning" in result["reasons"]


@pytest.mark.parametrize("path", sorted(PATHS))
def test_cap_is_enforced_without_a_user_id(org_policy, path):
    row, kwargs = PATHS[path]
    org_policy(**row)

    result = _eval(OVER_CAP, user_id=None, **kwargs)

    assert result["decision"] == "deny"
    assert result["reasons"] == ["budget_exceeded"]


def test_under_cap_keeps_the_policy_decision(org_policy):
    org_policy()

    result = _eval(WELL_UNDER, scope="local")

    assert result["decision"] == "allow"
    assert result["policy_id"] == "strict-fallback"
    assert "budget_check_passed" in result["reasons"]
    assert result["budget_info"].projected_total == pytest.approx(145.0, abs=0.01)


def test_budget_decision_keeps_redacted_text(org_policy):
    org_policy()
    text = "Check out cart 77, card 4111 1111 1111 1111"

    for context, decision in ((NEAR_CAP, "confirm"), (OVER_CAP, "deny")):
        result = _eval(context, text=text)
        assert result["decision"] == decision
        assert "4111 1111 1111 1111" not in result["raw_text_out"]


def test_warning_keeps_pii_reasons(org_policy):
    org_policy()

    result = _eval(NEAR_CAP, text="Check out cart 77 for jane.doe@example.com")

    assert result["decision"] == "confirm"
    assert "pii.redacted:email_address" in result["reasons"]
    assert "budget_warning" in result["reasons"]


def test_policy_deny_is_not_softened_by_budget(org_policy):
    org_policy(tool_access={"shop.checkout": {"action": "block"}})

    result = _eval(WELL_UNDER)

    assert result["decision"] == "deny"
    assert result["reasons"] == ["tool-specific.block"]


def test_zero_limit_means_no_budget_configured(org_policy):
    org_policy()

    result = _eval(_context(0.0, monthly_limit=0.0), scope="local")

    assert result["decision"] == "allow"
    assert "budget_status" not in result


def test_already_over_cap_denies_even_a_cheap_request(org_policy):
    org_policy()

    result = _eval(_context(1000.5), tool_config=None, text="hi")

    assert result["decision"] == "deny"
    assert result["reasons"] == ["budget_exceeded"]


def test_no_budget_context_leaves_decision_alone(org_policy):
    org_policy()

    result = _eval(None, scope="local")

    assert result["decision"] == "allow"
    assert "budget_status" not in result
