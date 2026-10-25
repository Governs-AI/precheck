# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""Policy semantics as written by the dashboard policy UI (v2).

The UI stores `defaults.{ingress,egress}.action` and tool rules using the
allow/block/redact/tokenize/confirm vocabulary. These tests pin what each
action does with and without PII in the text, that the org's dashboard
policy beats a payload `policy_config`, and that cached allows are keyed by
the policy revision.
"""

from datetime import datetime, timedelta

import pytest

from app import api, policy_source
from app.policies import (
    DEFAULT_DENY_TOOLS,
    evaluate_with_payload_policy,
    is_listed_tool,
    normalize_action,
)
from app.storage import DashboardPolicy

PII_TEXT = "Email jane.doe@example.com about SSN 123-45-6789"
CLEAN_TEXT = "Summarise the release notes in three bullet points."
ORG = "org-v2"


def _row(**overrides) -> DashboardPolicy:
    fields = dict(
        id="pol-1",
        org_id=ORG,
        name="ui policy",
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
        updated_at=datetime(2026, 10, 25, 9, 0, 0),
    )
    fields.update(overrides)
    return DashboardPolicy(**fields)


@pytest.fixture
def org_policy(monkeypatch):
    """Serve a mapped DashboardPolicy row as the org's active policy."""
    holder = {"row": None}

    def fake_get_active_policy(org_id):
        if org_id != ORG or holder["row"] is None:
            return None
        return policy_source._map_row_to_policy_config(holder["row"])

    monkeypatch.setattr(policy_source, "get_active_policy", fake_get_active_policy)

    def set_row(**overrides):
        holder["row"] = _row(**overrides)

    return set_row


def _eval(tool="model.chat", text=PII_TEXT, scope="net.external", **kw):
    return evaluate_with_payload_policy(
        tool=tool, scope=scope, raw_text=text, now=1000, org_id=ORG, **kw
    )


# ─── vocabulary ───────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "given, expected",
    [
        ("allow", "pass_through"),
        ("pass_through", "pass_through"),
        ("block", "deny"),
        ("deny", "deny"),
        ("redact", "redact"),
        ("tokenize", "tokenize"),
        ("confirm", "confirm"),
        ("  Block ", "deny"),
    ],
)
def test_normalize_action_folds_both_vocabularies(given, expected):
    assert normalize_action(given) == expected


def test_normalize_action_unknown_falls_back_to_default():
    assert normalize_action("explode") == "redact"
    assert normalize_action(None, None) is None


def test_is_listed_tool_is_exact_or_wildcard():
    assert is_listed_tool("Payment_Process", ["payment.process"])
    assert is_listed_tool("payments.refund", ["payments.*"])
    assert not is_listed_tool("agent.payment.process", ["payment.process"])
    assert not is_listed_tool("anything", [])


# ─── default actions (UI shape) ──────────────────────────────────────────
def test_default_allow_passes_pii_untouched(org_policy):
    org_policy(defaults={"ingress": {"action": "allow"}})
    result = _eval()
    assert result["decision"] == "allow"
    assert result["raw_text_out"] == PII_TEXT


def test_default_block_denies(org_policy):
    org_policy(defaults={"ingress": {"action": "block"}})
    assert _eval()["decision"] == "deny"
    assert _eval(text=CLEAN_TEXT)["decision"] == "deny"


def test_default_redact_redacts_pii_and_allows_clean_text(org_policy):
    org_policy(defaults={"ingress": {"action": "redact"}})
    redacted = _eval()
    assert redacted["decision"] == "transform"
    assert "jane.doe@example.com" not in redacted["raw_text_out"]
    assert _eval(text=CLEAN_TEXT)["decision"] == "allow"


def test_default_confirm_requires_confirmation(org_policy):
    org_policy(defaults={"ingress": {"action": "confirm"}})
    result = _eval(text=CLEAN_TEXT)
    assert result["decision"] == "confirm"
    assert result["reasons"] == ["default.ingress.confirm"]


def test_legacy_pii_default_still_applies(org_policy):
    org_policy(defaults={"pii": "block"})
    assert _eval()["decision"] == "deny"


def test_direction_specific_default_beats_pii_shorthand(org_policy):
    org_policy(defaults={"pii": "block", "ingress": {"action": "allow"}})
    assert _eval()["decision"] == "allow"


# ─── tool rules ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("text", [PII_TEXT, CLEAN_TEXT])
def test_tool_block_denies_with_or_without_pii(org_policy, text):
    org_policy(tool_access={"email_send": {"direction": "both", "action": "block"}})
    result = _eval(tool="email_send", text=text)
    assert result["decision"] == "deny"
    assert result["reasons"] == ["tool-specific.block"]


@pytest.mark.parametrize("text", [PII_TEXT, CLEAN_TEXT])
def test_tool_confirm_confirms_with_or_without_pii(org_policy, text):
    org_policy(
        tool_access={"payment_process": {"direction": "ingress", "action": "confirm"}}
    )
    assert _eval(tool="payment_process", text=text)["decision"] == "confirm"


def test_tool_allow_lets_pii_through(org_policy):
    org_policy(tool_access={"crm_lookup": {"direction": "both", "action": "allow"}})
    result = _eval(tool="crm_lookup")
    assert result["decision"] == "allow"
    assert result["raw_text_out"] == PII_TEXT


def test_tool_redact_redacts_pii_and_allows_clean_text(org_policy):
    org_policy(tool_access={"web_search": {"direction": "both", "action": "redact"}})
    redacted = _eval(tool="web_search")
    assert redacted["decision"] == "transform"
    assert "jane.doe@example.com" not in redacted["raw_text_out"]
    assert _eval(tool="web_search", text=CLEAN_TEXT)["decision"] == "allow"


def test_tool_allow_pii_override_blocks_one_type(org_policy):
    org_policy(
        tool_access={
            "crm_lookup": {
                "direction": "both",
                "action": "allow",
                "allow_pii": {"PII:us_ssn": "block"},
            }
        }
    )
    result = _eval(tool="crm_lookup")
    assert result["decision"] == "deny"
    assert result["reasons"] == ["pii.blocked:us_ssn"]


def test_tool_rule_direction_is_respected(org_policy):
    org_policy(
        defaults={"ingress": {"action": "allow"}, "egress": {"action": "allow"}},
        tool_access={"export": {"direction": "egress", "action": "block"}},
    )
    assert _eval(tool="export")["decision"] == "allow"  # ingress


# ─── deny / allow lists ──────────────────────────────────────────────────
def test_builtin_exec_denylist_applies_to_empty_ui_policy(org_policy):
    org_policy(deny_tools=[], defaults={"ingress": {"action": "allow"}})
    for tool in ("python.exec", "bash.exec"):
        assert tool in DEFAULT_DENY_TOOLS
        assert _eval(tool=tool, text=CLEAN_TEXT)["decision"] == "deny"


def test_allow_tools_lifts_builtin_exec_deny(org_policy):
    org_policy(allow_tools=["python.exec"], defaults={"ingress": {"action": "allow"}})
    assert _eval(tool="python.exec", text=CLEAN_TEXT)["decision"] == "allow"
    assert _eval(tool="bash.exec", text=CLEAN_TEXT)["decision"] == "deny"


def test_default_block_with_allow_tools_is_an_allowlist(org_policy):
    org_policy(defaults={"ingress": {"action": "block"}}, allow_tools=["model.chat"])
    allowed = _eval(tool="model.chat")
    assert allowed["decision"] == "transform"  # allowed, PII still redacted
    assert "jane.doe@example.com" not in allowed["raw_text_out"]
    assert _eval(tool="web_search", text=CLEAN_TEXT)["decision"] == "deny"


def test_explicit_deny_tools_still_win_over_allow_tools(org_policy):
    org_policy(deny_tools=["email_send"], allow_tools=["email_send"])
    assert _eval(tool="email_send", text=CLEAN_TEXT)["decision"] == "deny"


# ─── precedence ──────────────────────────────────────────────────────────
def test_org_policy_beats_payload_policy_config(org_policy):
    org_policy(defaults={"ingress": {"action": "block"}})
    permissive = {
        "defaults": {"ingress": {"action": "pass_through"}},
        "deny_tools": [],
        "tool_access": {},
    }
    result = _eval(text=CLEAN_TEXT, policy_config=permissive)
    assert result["decision"] == "deny"


def test_payload_policy_used_when_org_has_no_policy(org_policy):
    permissive = {"defaults": {"ingress": {"action": "allow"}}, "tool_access": {}}
    result = _eval(policy_config=permissive)
    assert result["decision"] == "allow"


# ─── allow-cache keying ──────────────────────────────────────────────────
def test_allow_cache_key_changes_with_policy_revision(org_policy):
    from app.models import PrePostCheckRequest

    req = PrePostCheckRequest(tool="model.chat", raw_text=CLEAN_TEXT)
    org_policy()
    first = api._build_allow_cache_key(req, ORG)
    assert api._build_allow_cache_key(req, ORG) == first
    org_policy(updated_at=datetime(2026, 10, 25, 9, 0, 0) + timedelta(seconds=1))
    assert api._build_allow_cache_key(req, ORG) != first


def test_allow_cache_key_ignores_payload_when_org_policy_exists(org_policy):
    from app.models import PolicyConfig, PrePostCheckRequest

    org_policy()
    plain = PrePostCheckRequest(tool="model.chat", raw_text=CLEAN_TEXT)
    with_payload = PrePostCheckRequest(
        tool="model.chat", raw_text=CLEAN_TEXT, policy_config=PolicyConfig()
    )
    assert api._build_allow_cache_key(plain, ORG) == api._build_allow_cache_key(
        with_payload, ORG
    )


def test_result_names_the_dashboard_policy_that_decided(org_policy):
    org_policy(id="pol-xyz")
    assert _eval()["_policy_ref"] == "pol-xyz"


def test_payload_policy_has_no_dashboard_ref():
    result = evaluate_with_payload_policy(
        tool="model.chat",
        scope="net.external",
        raw_text=CLEAN_TEXT,
        now=1000,
        policy_config={"defaults": {"ingress": {"action": "allow"}}},
    )
    assert "_policy_ref" not in result
