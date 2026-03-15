"""BaseTool for generic git commands (e.g. status) run in a given directory.

Uses subprocess so the agent loop can run git in the current working directory
when the model sends a placeholder path like /think.
"""

from __future__ import annotations

import os
import subprocess
from typing import Any, Dict

from src.tools.base import BaseTool, ToolResult


class GitBaseTool(BaseTool):
    """Runs git subcommands (e.g. status) in path/repo_path; defaults to cwd."""

    @property
    def name(self) -> str:
        return "git"

    def execute(self, params: Dict[str, Any]) -> ToolResult:
        repo_path = params.get("path") or params.get("repo_path") or "."
        command = (params.get("command") or "status").strip().lower()
        # Restrict to read-only / safe commands
        allowed = ("status", "log", "diff", "branch", "remote", "show")
        if command not in allowed:
            return ToolResult(
                success=False,
                output=None,
                error=f"Git command not allowed: {command}. Allowed: {allowed}.",
            )
        abs_path = os.path.abspath(repo_path)
        if not os.path.isdir(abs_path):
            return ToolResult(
                success=False,
                output=None,
                error=f"Not a directory: {repo_path}",
            )
        try:
            proc = subprocess.run(
                ["git", command],
                cwd=abs_path,
                capture_output=True,
                text=True,
                timeout=30,
            )
            out = (proc.stdout or "").strip() or (proc.stderr or "").strip()
            if proc.returncode != 0:
                return ToolResult(success=False, output=out, error=out or f"git exit code {proc.returncode}")
            return ToolResult(success=True, output=out)
        except subprocess.TimeoutExpired:
            return ToolResult(success=False, output=None, error="git command timed out")
        except FileNotFoundError:
            return ToolResult(success=False, output=None, error="git not found")
        except Exception as e:
            return ToolResult(success=False, output=None, error=str(e))
