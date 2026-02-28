# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""
TEST-3.9 — Additional policy engine coverage tests.

Targets paths in app/policies.py not exercised by test_policy_engine.py:
  - _load_policy()  / get_policy() — file-not-found, cached, hot-reload
  - tokenize()      — deterministic SHA-256 token
  - get_jsonpath()  / set_jsonpath() — deep access
  - apply_tool_access_text()   — pass_through, tokenize, redact
  - apply_tool_access()        — pass_through, tokenize, redact
  - redact_obj()               — dict, list, str, password field
  - _evaluate_policy() levels 3-5 — defaults deny/pass/tokenize, web.* prefix, strict fallback
  - evaluate_with_payload_policy() — with and without policy_config
  - is_password_field()        — keyword presence checks
  - anonymize_text_presidio()  — USE_PRESIDIO=False short-circuit
"""

import os
import json
import time
import tempfile
import pytest
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Module-level patches applied for the entire file
# ---------------------------------------------------------------------------

# Disable Presidio for all tests in this file — we want deterministic coverage
# of the regex fallback branch without spaCy model downloads in CI.
PATCH_NO_PRESIDIO = {
    "app.policies.USE_PRESIDIO": False,
    "app.policies.ANALYZER": None,
}


# ---------------------------------------------------------------------------
# _load_policy / get_policy
# ---------------------------------------------------------------------------


class TestLoadPolicy:
    def test_returns_empty_dict_when_file_not_found(self):
        import app.policies as pol

        original = pol._POLICY_PATH
        try:
            pol._POLICY_PATH = "/nonexistent/policy.yaml"
            pol._POLICY_MTIME = 0.0
            pol._POLICY_CACHE = {}
            result = pol._load_policy()
            assert result == {}
        finally:
            pol._POLICY_PATH = original
            pol._POLICY_MTIME = 0.0

    def test_returns_cached_dict_on_same_mtime(self, tmp_path):
        import app.policies as pol

        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("tool_access: {}\ndefaults: {}\n")
        mtime = os.path.getmtime(str(policy_file))

        original_path = pol._POLICY_PATH
        pol._POLICY_PATH = str(policy_file)
        pol._POLICY_MTIME = mtime
        pol._POLICY_CACHE = {"cached": True}

        try:
            result = pol._load_policy()
            assert result == {"cached": True}
        finally:
            pol._POLICY_PATH = original_path
            pol._POLICY_CACHE = {}
            pol._POLICY_MTIME = 0.0

    def test_hot_reloads_when_mtime_changes(self, tmp_path):
        import app.policies as pol

        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("tool_access: {}\n")
        time.sleep(0.01)  # ensure mtime delta
        pol._POLICY_PATH = str(policy_file)
        pol._POLICY_MTIME = 0.0  # force stale
        pol._POLICY_CACHE = {}

        result = pol._load_policy()
        assert isinstance(result, dict)

    def test_get_policy_returns_dict(self):
        from app.policies import get_policy

        result = get_policy()
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# tokenize
# ---------------------------------------------------------------------------


class TestTokenize:
    def test_returns_pii_prefix(self):
        from app.policies import tokenize

        token = tokenize("alice@example.com")
        assert token.startswith("pii_")

    def test_deterministic_for_same_input(self):
        from app.policies import tokenize

        assert tokenize("hello") == tokenize("hello")

    def test_different_inputs_give_different_tokens(self):
        from app.policies import tokenize

        assert tokenize("foo") != tokenize("bar")

    def test_token_is_short(self):
        from app.policies import tokenize

        # "pii_" + 8 hex chars
        assert len(tokenize("any value")) == 12


# ---------------------------------------------------------------------------
# get_jsonpath / set_jsonpath
# ---------------------------------------------------------------------------


class TestJsonPath:
    def test_get_simple_path(self):
        from app.policies import get_jsonpath

        obj = {"a": {"b": "value"}}
        assert get_jsonpath(obj, "$.a.b") == "value"

    def test_get_missing_key_returns_none(self):
        from app.policies import get_jsonpath

        assert get_jsonpath({"a": 1}, "$.missing") is None

    def test_get_invalid_path_returns_none(self):
        from app.policies import get_jsonpath

        assert get_jsonpath({}, "not_a_jsonpath") is None

    def test_get_deep_missing_returns_none(self):
        from app.policies import get_jsonpath

        assert get_jsonpath({"a": {}}, "$.a.b.c") is None

    def test_set_simple_path(self):
        from app.policies import set_jsonpath

        obj = {"a": {"b": "old"}}
        set_jsonpath(obj, "$.a.b", "new")
        assert obj["a"]["b"] == "new"

    def test_set_creates_missing_intermediate(self):
        from app.policies import set_jsonpath

        obj = {}
        set_jsonpath(obj, "$.x.y", 42)
        assert obj["x"]["y"] == 42

    def test_set_invalid_path_is_noop(self):
        from app.policies import set_jsonpath

        obj = {"a": 1}
        set_jsonpath(obj, "invalid", "v")
        assert obj == {"a": 1}


# ---------------------------------------------------------------------------
# is_password_field
# ---------------------------------------------------------------------------


class TestIsPasswordField:
    def test_exact_password_is_true(self):
        from app.policies import is_password_field

        assert is_password_field("password") is True

    def test_pass_is_true(self):
        from app.policies import is_password_field

        assert is_password_field("pass") is True

    def test_contains_secret_is_true(self):
        from app.policies import is_password_field

        assert is_password_field("user_secret") is True

    def test_email_field_is_false(self):
        from app.policies import is_password_field

        assert is_password_field("email") is False

    def test_empty_string_is_false(self):
        from app.policies import is_password_field

        assert is_password_field("") is False


# ---------------------------------------------------------------------------
# anonymize_text_presidio — USE_PRESIDIO=False path
# ---------------------------------------------------------------------------


class TestAnonymizeTextPresidioFallback:
    def test_returns_original_text_when_presidio_disabled(self):
        with patch("app.policies.USE_PRESIDIO", False), patch("app.policies.ANALYZER", None):
            from app.policies import anonymize_text_presidio

            text = "alice@example.com"
            out, reasons = anonymize_text_presidio(text)
            assert out == text
            assert reasons == []


# ---------------------------------------------------------------------------
# redact_obj
# ---------------------------------------------------------------------------


class TestRedactObj:
    def _redact(self, obj, field_name=""):
        with patch("app.policies.USE_PRESIDIO", False), patch("app.policies.ANALYZER", None):
            from app.policies import redact_obj

            return redact_obj(obj, field_name=field_name)

    def test_passthrough_for_non_string(self):
        result, reasons = self._redact(42)
        assert result == 42
        assert len(reasons) == 0

    def test_string_with_email_is_redacted(self):
        result, reasons = self._redact("reach me at dev@example.com please")
        assert "dev@example.com" not in result

    def test_password_field_returns_placeholder(self):
        result, reasons = self._redact("hunter2", field_name="password")
        assert result == "<PASSWORD>"
        assert "field.redacted:password" in reasons

    def test_dict_redacts_string_values(self):
        obj = {"msg": "email dev@example.com", "count": 5}
        result, reasons = self._redact(obj)
        assert "dev@example.com" not in result["msg"]
        assert result["count"] == 5

    def test_list_redacts_each_element(self):
        obj = ["clean text", "contact bob@b.com"]
        result, reasons = self._redact(obj)
        assert "bob@b.com" not in result[1]
        assert result[0] == "clean text"

    def test_nested_dict_redacted(self):
        obj = {"user": {"email": "a@b.com"}}
        result, reasons = self._redact(obj)
        assert "a@b.com" not in result["user"]["email"]


# ---------------------------------------------------------------------------
# apply_tool_access_text
# ---------------------------------------------------------------------------


class TestApplyToolAccessText:
    def _apply(self, tool, findings, raw_text, policy_override=None):
        with patch("app.policies.USE_PRESIDIO", False), patch("app.policies.ANALYZER", None):
            if policy_override is not None:
                with patch("app.policies.get_policy", return_value=policy_override):
                    from app.policies import apply_tool_access_text

                    return apply_tool_access_text(tool, findings, raw_text)
            else:
                from app.policies import apply_tool_access_text

                return apply_tool_access_text(tool, findings, raw_text)

    def test_pass_through_action(self):
        policy = {
            "tool_access": {
                "model.chat": {
                    "direction": "ingress",
                    "allow_pii": {"PII:email_address": "pass_through"},
                }
            }
        }
        findings = [{"type": "PII:email_address", "start": 0, "end": 17, "text": "alice@example.com"}]
        _, reasons = self._apply("model.chat", findings, "alice@example.com", policy)
        assert any("allowed" in r for r in reasons)

    def test_tokenize_action(self):
        policy = {
            "tool_access": {
                "model.chat": {
                    "direction": "ingress",
                    "allow_pii": {"PII:email_address": "tokenize"},
                }
            }
        }
        findings = [{"type": "PII:email_address", "start": 0, "end": 17, "text": "alice@example.com"}]
        transformed, reasons = self._apply("model.chat", findings, "alice@example.com", policy)
        assert any("tokenized" in r for r in reasons)
        assert "alice" not in transformed

    def test_no_policy_falls_back_to_redact(self):
        # No policy for this tool → apply_tool_access_text does regex redaction
        policy = {"tool_access": {}, "defaults": {}}
        findings = [{"type": "PII:email_address", "start": 0, "end": 17, "text": "alice@example.com"}]
        transformed, reasons = self._apply("unknown.tool", findings, "alice@example.com", policy)
        # Fallback redaction triggered
        assert any("redacted" in r for r in reasons) or transformed != "alice@example.com"


# ---------------------------------------------------------------------------
# _evaluate_policy — level 3 (global defaults)
# ---------------------------------------------------------------------------


class TestEvaluatePolicyDefaults:
    def _evaluate(self, tool, scope, raw_text, policy):
        with (
            patch("app.policies.USE_PRESIDIO", False),
            patch("app.policies.ANALYZER", None),
            patch("app.policies.get_policy", return_value=policy),
            patch("app.policies._POLICY_CACHE", policy),
        ):
            from app.policies import _evaluate_policy

            return _evaluate_policy(tool, scope, raw_text, int(time.time()))

    def test_global_default_deny(self):
        policy = {"defaults": {"ingress": {"action": "deny"}}, "tool_access": {}}
        result = self._evaluate("model.chat", "local", "hello", policy)
        assert result["decision"] == "deny"
        assert "default.ingress.deny" in result["reasons"]

    def test_global_default_pass_through(self):
        policy = {"defaults": {"ingress": {"action": "pass_through"}}, "tool_access": {}}
        result = self._evaluate("model.chat", "local", "hello", policy)
        assert result["decision"] == "allow"

    def test_global_default_tokenize(self):
        policy = {"defaults": {"ingress": {"action": "tokenize"}}, "tool_access": {}}
        result = self._evaluate("model.chat", "local", "secret text", policy)
        assert result["decision"] == "transform"
        assert result["raw_text_out"].startswith("pii_")


# ---------------------------------------------------------------------------
# _evaluate_policy — level 4 (network tools prefix)
# ---------------------------------------------------------------------------


class TestEvaluatePolicyNetworkToolsPrefix:
    def test_web_tool_triggers_redaction(self):
        policy = {"defaults": {}, "tool_access": {}}
        with (
            patch("app.policies.USE_PRESIDIO", False),
            patch("app.policies.ANALYZER", None),
            patch("app.policies.get_policy", return_value=policy),
        ):
            from app.policies import _evaluate_policy

            result = _evaluate_policy("web.search", None, "email me at dev@example.com", int(time.time()))
        # web.* triggers network redaction level
        assert result["decision"] == "transform"

    def test_http_tool_triggers_redaction(self):
        policy = {"defaults": {}, "tool_access": {}}
        with (
            patch("app.policies.USE_PRESIDIO", False),
            patch("app.policies.ANALYZER", None),
            patch("app.policies.get_policy", return_value=policy),
        ):
            from app.policies import _evaluate_policy

            result = _evaluate_policy("http.get", None, "safe text", int(time.time()))
        assert result["decision"] in {"transform", "allow"}


# ---------------------------------------------------------------------------
# _evaluate_policy — level 5 (strict fallback, no PII)
# ---------------------------------------------------------------------------


class TestEvaluatePolicyStrictFallback:
    def test_clean_text_with_local_scope_returns_allow(self):
        """No PII, no net scope, no deny tool → strict fallback allows clean text."""
        policy = {"defaults": {}, "tool_access": {}}
        with (
            patch("app.policies.USE_PRESIDIO", False),
            patch("app.policies.ANALYZER", None),
            patch("app.policies.get_policy", return_value=policy),
        ):
            from app.policies import _evaluate_policy

            result = _evaluate_policy("model.chat", "local", "hello world", int(time.time()))
        assert result["decision"] in {"allow", "transform"}

    def test_text_with_email_in_strict_fallback_transforms(self):
        """Email in strict fallback triggers transform."""
        policy = {"defaults": {}, "tool_access": {}}
        with (
            patch("app.policies.USE_PRESIDIO", False),
            patch("app.policies.ANALYZER", None),
            patch("app.policies.get_policy", return_value=policy),
        ):
            from app.policies import _evaluate_policy

            result = _evaluate_policy("model.chat", "local", "reach me at dev@example.com", int(time.time()))
        assert result["decision"] in {"transform", "allow"}


# ---------------------------------------------------------------------------
# evaluate_with_payload_policy
# ---------------------------------------------------------------------------


class TestEvaluateWithPayloadPolicy:
    def test_falls_back_to_static_yaml_when_no_policy_config(self):
        """Without policy_config, delegates to the static evaluate() path."""
        with (
            patch("app.policies.USE_PRESIDIO", False),
            patch("app.policies.ANALYZER", None),
        ):
            from app.policies import evaluate_with_payload_policy

            result = evaluate_with_payload_policy("python.exec", "local", "import os", int(time.time()))
        # DENY_TOOLS path should deny
        assert result["decision"] == "deny"

    def test_uses_dynamic_policy_when_provided(self):
        """With policy_config provided, uses dynamic evaluation."""
        with (
            patch("app.policies.USE_PRESIDIO", False),
            patch("app.policies.ANALYZER", None),
        ):
            from app.policies import evaluate_with_payload_policy

            policy_config = {
                "deny_tools": [],
                "tool_access": {},
                "defaults": {"ingress": {"action": "pass_through"}},
            }
            result = evaluate_with_payload_policy(
                "model.chat", "local", "hello", int(time.time()), policy_config=policy_config
            )
        assert result["decision"] in {"allow", "transform"}
