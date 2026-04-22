"""Runtime bootstrap helpers (register default tools)."""

from __future__ import annotations

from src.runtime.agent_runtime import AgentRuntime
from src.tools.git_tool import GitBaseTool
from src.tools.http_fetch import HttpFetchTool
from src.tools.package_manager import PackageManagerQueryTool


def register_default_tools(runtime: AgentRuntime) -> None:
    """
    Register built-in tool implementations.

    Safe to call multiple times (duplicate registrations are ignored).
    """
    for tool in (GitBaseTool(), HttpFetchTool(), PackageManagerQueryTool()):
        try:
            runtime.register_tool(tool)
        except ValueError:
            # tool already registered (tests or repeated bootstrap)
            pass

