"""
Phase 0 (PR-1) — verify that the policy-declared `max_response_size` is
enforced even when the caller does not pass an explicit cap in tool
parameters.

Pipeline under test:

    PolicyEngine.evaluate(...) -> Decision(details={"max_response_size": "5MB"})
    -> AgentRuntime._apply_policy_resource_limits(...) injects the cap
    -> HttpFetchTool.execute(...) streams response and trips the cap

Without the runtime injection, the http.fetch tool falls back to its
internal default (also 5MB), so the previous behavior masked policy
mis-configuration. This test patches `requests.request` with a fake
response that streams chunks past the policy cap and asserts the tool
returns a structured failure citing `max_response_size`.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List

import pytest

import src.tools.base as _tool_base
import src.tools.http_fetch as http_fetch_module
from src.runtime.agent_runtime import AgentRuntime
from src.runtime.bootstrap import register_default_tools


@pytest.fixture(autouse=True)
def _clear_tool_registry(monkeypatch: pytest.MonkeyPatch) -> Any:
    # The Docker sandbox path bypasses in-process tool execution, which would
    # mask the runtime injection we want to verify here. Force the in-process
    # path regardless of the developer's shell environment.
    monkeypatch.delenv("AGENT_RUNTIME_USE_DOCKER_SANDBOX", raising=False)
    _tool_base._TOOL_REGISTRY.clear()
    yield
    _tool_base._TOOL_REGISTRY.clear()


class _FakeResponse:
    """Minimal stand-in for `requests.Response` returned in streaming mode."""

    def __init__(self, status_code: int, chunks: Iterable[bytes], headers: Dict[str, str] | None = None) -> None:
        self.status_code = status_code
        self.headers = headers or {"content-type": "text/plain"}
        self._chunks: List[bytes] = list(chunks)

    def iter_content(self, chunk_size: int = 64 * 1024) -> Iterable[bytes]:
        for c in self._chunks:
            yield c

    def close(self) -> None:  # pragma: no cover - parity with requests
        pass


def _runtime(policy_yaml_path: Path) -> AgentRuntime:
    rt = AgentRuntime(approval_callback=lambda cap, params: True)
    rt.load_policy(policy_yaml_path)
    register_default_tools(rt)
    return rt


def test_policy_cap_is_enforced_when_params_omit_max_response_size(
    monkeypatch: pytest.MonkeyPatch, policy_yaml_path: Path
) -> None:
    # examples/policies/Policy.yaml caps http.fetch at 5MB. Stream 6MB.
    chunk = b"A" * (1024 * 1024)
    fake = _FakeResponse(status_code=200, chunks=[chunk] * 6)

    captured: Dict[str, Any] = {}

    def fake_request(method: str, url: str, **kwargs: Any) -> _FakeResponse:
        captured["method"] = method
        captured["url"] = url
        captured["kwargs"] = kwargs
        return fake

    monkeypatch.setattr(http_fetch_module.requests, "request", fake_request)

    rt = _runtime(policy_yaml_path)
    result = rt.execute_tool(
        "http.fetch",
        {"url": "https://api.github.com/", "method": "GET"},
    )

    # When a tool returns success=False the runtime currently rewrites the
    # outer ExecuteResult to allowed=False, but the inner ToolResult still
    # carries the diagnostic from the tool. Both are surfaced here because
    # both matter for downstream auditing.
    assert result.result is not None, "Runtime must surface the tool result on cap violation."
    assert result.result.success is False, "Tool must fail when streamed bytes exceed policy cap."
    assert result.result.error and "max_response_size" in result.result.error
    # The policy says 5MB; tool should report the same cap it enforced.
    assert isinstance(result.result.output, dict)
    assert result.result.output.get("max_response_size") == 5 * 1024 * 1024
    assert captured.get("url") == "https://api.github.com/"
    # And the runtime exposes the failure as a denial.
    assert result.allowed is False


def test_caller_provided_cap_wins_over_policy(
    monkeypatch: pytest.MonkeyPatch, policy_yaml_path: Path
) -> None:
    # Caller passes a tighter cap (1KB). Stream 2KB and expect failure citing the
    # caller-provided value, proving the runtime never overwrites caller params.
    chunk = b"B" * 1024
    fake = _FakeResponse(status_code=200, chunks=[chunk, chunk])

    monkeypatch.setattr(
        http_fetch_module.requests,
        "request",
        lambda method, url, **kwargs: fake,
    )

    rt = _runtime(policy_yaml_path)
    result = rt.execute_tool(
        "http.fetch",
        {
            "url": "https://api.github.com/",
            "method": "GET",
            "max_response_size": 1024,
        },
    )

    assert result.result is not None
    assert result.result.success is False
    assert result.result.output.get("max_response_size") == 1024
    assert result.allowed is False
