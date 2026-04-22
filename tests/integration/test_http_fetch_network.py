from __future__ import annotations

import os
import pytest

import src.tools.base as _tool_base
from src.runtime.agent_runtime import AgentRuntime
from src.runtime.bootstrap import register_default_tools


@pytest.fixture(autouse=True)
def clear_tool_registry():
    _tool_base._TOOL_REGISTRY.clear()
    yield
    _tool_base._TOOL_REGISTRY.clear()


@pytest.mark.network
def test_http_fetch_real_network(policy_yaml_path):
    """
    Opt-in network test.

    Enable with:
      PHASE5_NETWORK_TESTS=1 pytest -m network
    """
    if os.environ.get("PHASE5_NETWORK_TESTS") != "1":
        pytest.skip("Set PHASE5_NETWORK_TESTS=1 to enable network tests.")

    rt = AgentRuntime()
    rt.load_policy(policy_yaml_path)
    register_default_tools(rt)

    # Policy.yaml requires approval for http.fetch; no callback means deny.
    # Use a runtime with approval callback by setting it directly.
    rt._approval_callback = lambda capability, params: True  # noqa: SLF001 (test-only)

    result = rt.execute_tool("http.fetch", {"url": "https://api.github.com/"})
    assert result.allowed is True
    assert result.result is not None
    assert result.result.success is True

