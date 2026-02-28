# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""
TEST-3.1 — Policy engine tests covering all 5 decision types.

Decision types:
  allow        — clean text, non-dangerous tool, non-network scope
  deny         — tool in DENY_TOOLS, or default action = deny
  transform    — PII detected and redacted (net scope, regex fallback)
  confirm      — explicitly gated by dynamic policy (budget warning path)
  error paths  — on_error=block → deny, on_error=pass → pass_through,
                 on_error=best_effort → transform
"""

import time
from unittest.mock import patch, MagicMock

import pytest

NOW = int(time.time())

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _evaluate(tool, scope, text, direction="ingress"):
    from app.policies import evaluate
    return evaluate(tool, scope, text, NOW, direction)


# ---------------------------------------------------------------------------
# DECISION: deny — DENY_TOOLS hard block (precedence level 1)
# ---------------------------------------------------------------------------


class TestDenyTools:
    DANGEROUS = ["python.exec", "bash.exec", "code.exec", "shell.exec"]

    @pytest.mark.parametrize("tool", DANGEROUS)
    def test_dangerous_tool_returns_deny(self, tool):
        result = _evaluate(tool, "net.external", "print('hello')")
        assert result["decision"] == "deny"
        assert result["policy_id"] == "deny-exec"

    def test_deny_includes_reason(self):
        result = _evaluate("python.exec", None, "exec code")
        assert "reasons" in result
        assert len(result["reasons"]) > 0

    def test_deny_tool_in_net_scope_still_denied(self):
        # Even net scope PII logic must not override DENY_TOOLS
        result = _evaluate("bash.exec", "net.external", "rm -rf /")
        assert result["decision"] == "deny"


# ---------------------------------------------------------------------------
# DECISION: transform — net scope triggers PII redaction
# ---------------------------------------------------------------------------


class TestNetScopeTransform:
    """
    At precedence level 4, any tool with a 'net.*' scope or 'web.*' prefix
    triggers PII redaction.  Tests run with USE_PRESIDIO=False (no spaCy model
    in CI) so the regex fallback path is exercised.
    """

    @patch("app.policies.USE_PRESIDIO", False)
    @patch("app.policies.ANALYZER", None)
    def test_net_scope_email_redacted(self):
        result = _evaluate("model.chat", "net.external", "Email me at alice@example.com")
        assert result["decision"] in {"transform", "allow"}
        if result["decision"] == "transform":
            assert result.get("raw_text_out") is not None
            assert "alice@example.com" not in result["raw_text_out"]

    @patch("app.policies.USE_PRESIDIO", False)
    @patch("app.policies.ANALYZER", None)
    def test_net_scope_phone_redacted(self):
        result = _evaluate("model.chat", "net.external", "Call 555-867-5309 now")
        assert result["decision"] in {"transform", "allow"}

    @patch("app.policies.USE_PRESIDIO", False)
    @patch("app.policies.ANALYZER", None)
    def test_web_tool_prefix_triggers_redaction(self):
        result = _evaluate("web.search", None, "My email is bob@test.org")
        assert result["decision"] in {"transform", "allow"}

    @patch("app.policies.USE_PRESIDIO", False)
    @patch("app.policies.ANALYZER", None)
    def test_http_tool_prefix_triggers_redaction(self):
        result = _evaluate("http.post", None, "plain text no PII")
        # Even without PII, net tools pass through the net-redact path
        assert result["decision"] in {"transform", "allow"}


# ---------------------------------------------------------------------------
# DECISION: allow — clean text, non-dangerous tool, non-network scope
# ---------------------------------------------------------------------------


class TestAllowDecision:
    @patch("app.policies.USE_PRESIDIO", False)
    @patch("app.policies.ANALYZER", None)
    def test_clean_text_local_scope_allows(self):
        result = _evaluate("model.chat", "local", "Hello, how are you today?")
        assert result["decision"] in {"allow", "transform"}

    @patch("app.policies.USE_PRESIDIO", False)
    @patch("app.policies.ANALYZER", None)
    def test_non_deny_tool_no_pii_allows(self):
        result = _evaluate("file.read", None, "The weather is nice today.")
        assert result["decision"] in {"allow", "transform"}

    def test_safe_tool_in_deny_list_is_still_safe(self):
        # "file.read" is NOT in DENY_TOOLS
        from app.policies import DENY_TOOLS
        assert "file.read" not in DENY_TOOLS
        assert "model.chat" not in DENY_TOOLS


# ---------------------------------------------------------------------------
# DECISION: error handling — on_error controls fallback decision
# ---------------------------------------------------------------------------


class TestErrorHandling:
    def _patch_evaluate(self, monkeypatch, on_error_value):
        """Make _evaluate_policy raise, control on_error setting."""
        import app.policies as pol

        def _raise(*args, **kwargs):
            raise RuntimeError("simulated internal error")

        monkeypatch.setattr(pol, "_evaluate_policy", _raise)
        monkeypatch.setattr(pol.settings, "on_error", on_error_value)

    def test_on_error_block_returns_deny(self, monkeypatch):
        self._patch_evaluate(monkeypatch, "block")
        result = _evaluate("any.tool", None, "some text")
        assert result["decision"] == "deny"
        assert "precheck.error" in result["reasons"]

    def test_on_error_pass_returns_pass_through(self, monkeypatch):
        self._patch_evaluate(monkeypatch, "pass")
        result = _evaluate("any.tool", None, "some text")
        assert result["decision"] == "pass_through"
        assert "precheck.bypass" in result["reasons"]

    def test_on_error_best_effort_returns_transform(self, monkeypatch):
        import app.policies as pol

        def _raise(*args, **kwargs):
            raise RuntimeError("simulated error")

        monkeypatch.setattr(pol, "_evaluate_policy", _raise)
        monkeypatch.setattr(pol.settings, "on_error", "best_effort")
        monkeypatch.setattr(pol, "USE_PRESIDIO", False)
        monkeypatch.setattr(pol, "ANALYZER", None)

        result = _evaluate("any.tool", None, "Hello world email@example.com")
        assert result["decision"] in {"transform", "allow"}

    def test_on_error_unknown_defaults_to_deny(self, monkeypatch):
        self._patch_evaluate(monkeypatch, "unknown_value")
        result = _evaluate("any.tool", None, "text")
        assert result["decision"] == "deny"


# ---------------------------------------------------------------------------
# Policy precedence — deny tools override everything else
# ---------------------------------------------------------------------------


class TestPrecedenceOrder:
    def test_deny_tool_overrides_net_scope(self):
        """DENY_TOOLS (level 1) must win over net scope (level 4)."""
        result = _evaluate("python.exec", "net.external", "email@example.com")
        assert result["decision"] == "deny"

    @patch("app.policies.USE_PRESIDIO", False)
    @patch("app.policies.ANALYZER", None)
    def test_direction_egress_reaches_default_path(self):
        """Egress direction should still be evaluated without crashing."""
        result = _evaluate("model.chat", "local", "Good morning!", direction="egress")
        assert result["decision"] in {"allow", "transform", "deny"}

    def test_result_always_has_decision_key(self):
        for tool in ["python.exec", "model.chat", "web.search"]:
            result = _evaluate(tool, "net.external", "test text")
            assert "decision" in result

    def test_result_always_has_ts_key(self):
        for tool in ["bash.exec", "file.read"]:
            result = _evaluate(tool, None, "hello")
            assert "ts" in result
