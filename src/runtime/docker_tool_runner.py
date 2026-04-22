"""
Docker sandbox tool runner.

This module is intended to run *inside* a Docker container. It reads a single
JSON object from stdin:

  {"capability": "...", "parameters": {...}}

and writes a single JSON object to stdout:

  {"success": bool, "output": ..., "error": "..."}
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict

from src.tools.base import ToolResult
from src.tools.http_fetch import HttpFetchTool
from src.tools.package_manager import PackageManagerQueryTool


def _get_tool(capability: str):
    # Keep runner explicit/deterministic (no dynamic imports).
    if capability == "http.fetch":
        return HttpFetchTool()
    if capability == "package_manager.query":
        return PackageManagerQueryTool()
    return None


def main() -> None:
    raw = sys.stdin.read()
    payload = json.loads(raw or "{}")
    capability = payload.get("capability") or ""
    params: Dict[str, Any] = payload.get("parameters") or {}

    tool = _get_tool(str(capability))
    if tool is None:
        out = ToolResult(success=False, output=None, error=f"Sandbox runner: unsupported capability {capability!r}.")
        sys.stdout.write(json.dumps(out.to_dict()))
        return

    result = tool.execute(params)
    sys.stdout.write(json.dumps(result.to_dict()))


if __name__ == "__main__":
    main()

