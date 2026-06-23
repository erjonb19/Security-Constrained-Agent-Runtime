"""
Milestone 1: Guarded MCP Server (stdio)
=======================================
Exposes your Security-Constrained Agent Runtime as an MCP server.
Every MCP tool call is routed through your REAL policy engine
(AgentRuntime.execute_tool) before anything runs.

Place this file at the repo ROOT (same level as the `src/` folder)
and run it from there.

Run:
    pip install "mcp[cli]"
    python mcp_server.py            # starts the server on stdio

Test (either one):
    npx @modelcontextprotocol/inspector python mcp_server.py
    # or add it to Claude Desktop's MCP config and call the tools

What this demonstrates (the whole point of Milestone 1):
    echo("hi")      -> ALLOWED  (capability demo.echo is permitted)
    fetch_url(...)  -> DENIED    (http.fetch is high-risk, needs approval,
                                  no approver wired -> default deny)
    git_push(...)   -> DENIED    (git.push is allowed:false in the policy)

The policy engine, capability model, six-layer defense, and audit log are
all UNCHANGED. This file is just a new front door (MCP) onto execute_tool().
"""

from __future__ import annotations

import os
import sys

# make `from src...` imports work when run from the repo root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp.server.fastmcp import FastMCP

from src.runtime.agent_runtime import AgentRuntime
from src.runtime.bootstrap import register_default_tools
from src.tools.base import BaseTool, ToolResult


# ---------------------------------------------------------------------------
# A tiny demo tool so Milestone 1 has a clean "allowed" path to show.
# In later milestones you delete this and expose your real tools instead.
# ---------------------------------------------------------------------------
class EchoTool(BaseTool):
    @property
    def name(self) -> str:
        return "demo.echo"

    def execute(self, params):
        return ToolResult(success=True, output=f"echo: {params.get('text', '')}")


# ---------------------------------------------------------------------------
# Boot the REAL runtime once, at server startup.
# ---------------------------------------------------------------------------
POLICY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp_demo_policy.yaml")

runtime = AgentRuntime()
runtime.load_policy(POLICY_PATH)
register_default_tools(runtime)      # git, http.fetch, package_manager.query
runtime.register_tool(EchoTool())    # demo.echo


# ---------------------------------------------------------------------------
# The mediation seam: every MCP tool call goes through here.
# This is the heart of the project. MCP call -> capability -> execute_tool.
# ---------------------------------------------------------------------------
def guarded(capability: str, params: dict) -> str:
    result = runtime.execute_tool(capability, params)
    if not result.allowed:
        reason = result.explanation
        if not reason and result.decision is not None:
            reason = getattr(result.decision, "reason", "not permitted")
        return f"DENIED by policy [{capability}]: {reason or 'not permitted'}"
    tool_result = result.result
    if tool_result is not None and tool_result.success:
        return str(tool_result.output)
    err = tool_result.error if tool_result is not None else "no result"
    return f"TOOL ERROR [{capability}]: {err}"


# ---------------------------------------------------------------------------
# The MCP server. Each @mcp.tool() is an MCP-exposed tool that any client
# (Claude Desktop, VS Code, the Inspector) can call. Each one maps to a
# capability and is mediated by your policy engine.
# ---------------------------------------------------------------------------
mcp = FastMCP("guarded-runtime")


@mcp.tool()
def echo(text: str) -> str:
    """Echo text back. Low-risk capability (demo.echo) — should be ALLOWED."""
    return guarded("demo.echo", {"text": text})


@mcp.tool()
def fetch_url(url: str) -> str:
    """Fetch a URL. High-risk capability (http.fetch) — requires approval,
    so it is DENIED unless a human approver is wired in."""
    return guarded("http.fetch", {"url": url})


@mcp.tool()
def git_push(remote: str = "origin", branch: str = "main") -> str:
    """Attempt a git push. Capability git.push is allowed:false — DENIED."""
    return guarded("git.push", {"remote": remote, "branch": branch})


if __name__ == "__main__":
    # stdio transport for local dev. Milestone 3 switches to Streamable HTTP.
    mcp.run()
