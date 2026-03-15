"""
Unit tests for src.runtime.agent_loop (plan §1.6, §4.1).
"""

import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.runtime.agent_loop import (
    load_tool_definitions,
    to_ollama_tools,
    _extract_read_file_intent,
    check_prompt_against_policy,
    _parse_tool_call_from_content,
    parse_tool_call,
    _normalize_git_params,
    run_tool_and_format,
    tool_definitions_json_path,
    create_runtime,
)
from src.runtime import AgentRuntime


class TestLoadToolDefinitions:
    """Tests for load_tool_definitions."""

    def test_load_returns_list(self, tool_definitions_json_path: Path) -> None:
        """load_tool_definitions returns list of tool dicts."""
        tools = load_tool_definitions(tool_definitions_json_path)
        assert isinstance(tools, list)
        assert len(tools) >= 1

    def test_each_tool_has_name_description_parameters(
        self, tool_definitions_json_path: Path
    ) -> None:
        """Each tool has name, description, parameters."""
        tools = load_tool_definitions(tool_definitions_json_path)
        for t in tools:
            assert "name" in t
            assert "description" in t
            assert "parameters" in t
            assert "type" in t["parameters"]
            assert "properties" in t["parameters"]


class TestToOllamaTools:
    """Tests for to_ollama_tools."""

    def test_wraps_in_type_function(self) -> None:
        """Output has type=function and function.name/description/parameters."""
        tools = [
            {
                "name": "filesystem.read",
                "description": "Read a file.",
                "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
            }
        ]
        out = to_ollama_tools(tools)
        assert len(out) == 1
        assert out[0]["type"] == "function"
        assert out[0]["function"]["name"] == "filesystem.read"
        assert out[0]["function"]["description"] == "Read a file."
        assert "path" in out[0]["function"]["parameters"]["properties"]


class TestExtractReadFileIntent:
    """Tests for _extract_read_file_intent."""

    def test_read_the_file_path(self) -> None:
        """Extracts capability and path from 'read the file PATH'."""
        cap, params = _extract_read_file_intent("read the file README.md")
        assert cap == "filesystem.read"
        assert params == {"path": "README.md"}

    def test_read_file_path(self) -> None:
        """Extracts from 'read file PATH'."""
        cap, params = _extract_read_file_intent("read file C:\\Windows\\file.log")
        assert cap == "filesystem.read"
        assert params["path"] == "C:\\Windows\\file.log"

    def test_open_the_file_path(self) -> None:
        """Extracts from 'open the file PATH'."""
        cap, params = _extract_read_file_intent("open the file src/main.py")
        assert cap == "filesystem.read"
        assert params == {"path": "src/main.py"}

    def test_no_intent_returns_none(self) -> None:
        """Returns (None, {}) when no read-file intent."""
        cap, params = _extract_read_file_intent("what is the weather?")
        assert cap is None
        assert params == {}


class TestCheckPromptAgainstPolicy:
    """Tests for check_prompt_against_policy."""

    def test_prompt_allowed_when_intent_not_detected(self, policy_yaml_path: Path) -> None:
        """Returns (True, 'Prompt allowed.') when intent not detected."""
        runtime = create_runtime(policy_yaml_path)
        allowed, msg = check_prompt_against_policy(runtime, "hello world")
        assert allowed is True
        assert "Prompt allowed" in msg

    def test_prompt_denied_when_path_not_allowed(self, policy_yaml_path: Path) -> None:
        """Returns (False, ...) when read-file path is denied by policy."""
        runtime = create_runtime(policy_yaml_path)
        allowed, msg = check_prompt_against_policy(
            runtime, "read the file C:\\Windows\\System32\\config"
        )
        assert allowed is False
        assert "Prompt denied" in msg or "denied" in msg.lower()


class TestParseToolCallFromContent:
    """Tests for _parse_tool_call_from_content (fallback)."""

    def test_parses_tool_and_path_json(self) -> None:
        """Parses {\"tool\": \"filesystem.read\", \"path\": \"x\"}."""
        content = '{"tool": "filesystem.read", "path": "README.md"}'
        name, params = _parse_tool_call_from_content(content)
        assert name == "filesystem.read"
        assert params == {"path": "README.md"}

    def test_parses_with_code_fence(self) -> None:
        """Strips markdown code block and parses JSON."""
        content = '```json\n{"tool": "filesystem.read", "path": "a.txt"}\n```'
        name, params = _parse_tool_call_from_content(content)
        assert name == "filesystem.read"
        assert params.get("path") == "a.txt"

    def test_returns_none_for_invalid_json(self) -> None:
        """Returns (None, None) for non-JSON content."""
        name, params = _parse_tool_call_from_content("not json")
        assert name is None
        assert params is None


class TestParseToolCall:
    """Tests for parse_tool_call."""

    def test_structured_tool_calls(self) -> None:
        """Uses tool_calls[].function.name and .function.arguments."""
        response = {
            "message": {
                "tool_calls": [
                    {"function": {"name": "filesystem.read", "arguments": {"path": "x"}}}
                ]
            }
        }
        name, params = parse_tool_call(response)
        assert name == "filesystem.read"
        assert params == {"path": "x"}

    def test_fallback_content_json(self) -> None:
        """When no tool_calls, parses message.content as JSON."""
        response = {
            "message": {"content": '{"tool": "filesystem.read", "path": "y"}'}
        }
        name, params = parse_tool_call(response)
        assert name == "filesystem.read"
        assert params == {"path": "y"}

    def test_no_tool_call_returns_none(self) -> None:
        """Returns (None, None) when no tool call in response."""
        response = {"message": {"content": "Just text."}}
        name, params = parse_tool_call(response)
        assert name is None
        assert params is None


class TestNormalizeGitParams:
    """Tests for _normalize_git_params."""

    def test_placeholder_path_replaced_with_cwd(self) -> None:
        """When capability is git and path is /think, path and repo_path become cwd."""
        import os
        params = _normalize_git_params("git", {"path": "/think", "command": "status"})
        assert params["path"] == os.getcwd()
        assert params["repo_path"] == os.getcwd()
        assert params["command"] == "status"

    def test_non_git_unchanged(self) -> None:
        """Non-git capability params are not modified."""
        params = _normalize_git_params("filesystem.read", {"path": "/think"})
        assert params["path"] == "/think"

    def test_git_valid_path_unchanged(self) -> None:
        """When capability is git and path is a valid dir, params are unchanged."""
        import os
        params = _normalize_git_params("git", {"path": os.getcwd(), "command": "status"})
        assert params["path"] == os.getcwd()

    def test_git_placeholder_replaced_with_workspace(self) -> None:
        """When workspace is set, placeholder path is replaced with workspace."""
        import os
        workspace = os.getcwd()
        params = _normalize_git_params("git", {"path": "/think", "command": "status"}, workspace=workspace)
        assert params["path"] == os.path.abspath(workspace)
        assert params["repo_path"] == os.path.abspath(workspace)


class TestRunToolAndFormat:
    """Tests for run_tool_and_format."""

    def test_denied_returns_explanation(self, policy_yaml_path: Path) -> None:
        """When execute_tool denies, returns 'Tool denied: ...'."""
        runtime = create_runtime(policy_yaml_path)
        msg = run_tool_and_format(runtime, "shell.execute", {})
        assert "Tool denied" in msg
        assert runtime.execute_tool("shell.execute", {}).explanation

    def test_run_tool_and_format_returns_string(self, policy_yaml_path: Path) -> None:
        """run_tool_and_format returns a string (Tool denied or Tool X succeeded)."""
        runtime = create_runtime(policy_yaml_path)
        msg = run_tool_and_format(runtime, "filesystem.read", {"path": "README.md"})
        assert isinstance(msg, str)
        assert "Tool " in msg


class TestToolDefinitionsJsonPath:
    """Tests for tool_definitions_json_path."""

    def test_with_tools_arg(self) -> None:
        """When args.tools is set, returns that path."""
        args = MagicMock(tools="/custom/tools.json", policy=None)
        path = tool_definitions_json_path(args)
        assert path == Path("/custom/tools.json")

    def test_with_policy_arg(self) -> None:
        """When args.policy is set, returns same dir / tool_definitions.json."""
        args = MagicMock(tools=None, policy="examples/policies/Policy.yaml")
        path = tool_definitions_json_path(args)
        assert path == Path("examples/policies/tool_definitions.json")

    def test_default_path(self) -> None:
        """When neither set, returns default path."""
        args = MagicMock(spec=["tools", "policy"])
        args.tools = None
        args.policy = None
        path = tool_definitions_json_path(args)
        assert path == Path("examples/policies/tool_definitions.json")


class TestCreateRuntime:
    """Tests for create_runtime."""

    def test_creates_runtime_with_policy(self, policy_yaml_path: Path) -> None:
        """create_runtime(policy_path) returns AgentRuntime with policy loaded."""
        runtime = create_runtime(policy_yaml_path)
        assert isinstance(runtime, AgentRuntime)
        decision = runtime.evaluate_policy("shell.execute", {})
        assert decision.allowed is False
