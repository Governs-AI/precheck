# SPDX-License-Identifier: MIT
# Copyright (c) 2024 GovernsAI. All rights reserved.
"""TEST — denylist matching for dangerous tools.

The previous implementation was `if tool in deny_tools`, an exact string
membership test. Every case in TestBypassVariants walked past it while naming
the same code-execution primitive. Denial is a security boundary: these tests
pin the matcher's generosity so a later refactor cannot quietly narrow it.
"""

import pytest

from app.policies import DEFAULT_DENY_TOOLS, is_denied_tool, normalize_tool_name


class TestNormalizeToolName:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("python.exec", "python.exec"),
            ("Python.Exec", "python.exec"),
            ("PYTHON.EXEC", "python.exec"),
            ("  python.exec  ", "python.exec"),
            ("python_exec", "python.exec"),
            ("python-exec", "python.exec"),
            ("python/exec", "python.exec"),
            ("python:exec", "python.exec"),
            ("python..exec", "python.exec"),
            (".python.exec.", "python.exec"),
            ("", ""),
        ],
    )
    def test_folds_to_canonical_form(self, raw, expected):
        assert normalize_tool_name(raw) == expected

    def test_handles_none(self):
        assert normalize_tool_name(None) == ""


class TestBypassVariants:
    """Each of these was allowed by the exact-match implementation."""

    @pytest.mark.parametrize(
        "tool",
        [
            "Python.Exec",
            "PYTHON.EXEC",
            " python.exec ",
            "python_exec",
            "python-exec",
            "python/exec",
            "shell/exec",
            "Bash.Exec",
            "exec.python",  # component order
            "exec.shell",
            "agent.python.exec.v2",  # namespaced
            "tools.bash.exec",
        ],
    )
    def test_denied(self, tool):
        assert is_denied_tool(tool) is True

    @pytest.mark.parametrize(
        "tool",
        [
            "subprocess.run",
            "subprocess.popen",
            "os.system",
            "child_process.spawn",
            "runtime.exec",
        ],
    )
    def test_semantically_equivalent_primitives_denied(self, tool):
        """Names that are code execution by any other spelling."""
        assert is_denied_tool(tool) is True


class TestLegitimateToolsStillAllowed:
    @pytest.mark.parametrize(
        "tool",
        [
            "chat",
            "db.query",
            "web.search",
            "http.get",
            "python.format",  # not exec
            "exec_summary",  # substring of "exec", not the primitive
            "executive.report",
            "search.python.docs",
            "",
        ],
    )
    def test_allowed(self, tool):
        assert is_denied_tool(tool) is False

    def test_empty_denylist_allows_everything(self):
        assert is_denied_tool("python.exec", []) is False


class TestCustomDenylists:
    def test_operator_supplied_list_is_normalized_too(self):
        assert is_denied_tool("Danger_Tool", ["danger.tool"]) is True

    def test_wildcard_denies_namespace(self):
        assert is_denied_tool("shell.anything", ["shell.*"]) is True
        assert is_denied_tool("shell", ["shell.*"]) is True

    def test_wildcard_does_not_leak_across_prefixes(self):
        assert is_denied_tool("shelly.thing", ["shell.*"]) is False

    def test_non_string_entries_are_skipped(self):
        assert is_denied_tool("python.exec", [None, 42, "python.exec"]) is True
        assert is_denied_tool("chat", [None, 42]) is False


class TestDefaults:
    def test_legacy_defaults_retained(self):
        for tool in ["python.exec", "bash.exec", "code.exec", "shell.exec"]:
            assert tool in DEFAULT_DENY_TOOLS
