"""Package manager query-only tool.

Implements the `package_manager.query` capability with *read-only* behavior:
- list: show installed distributions (via importlib.metadata)
- info: fetch package metadata from PyPI JSON API
- search: query versions using `pip index versions` (read-only network query)

Security note: allowed operations are enforced by the parameter validator via
the policy `constraints.operations` allow-list.
"""

from __future__ import annotations

import re
import subprocess
import sys
from importlib import metadata
from typing import Any, Dict, List, Optional

import requests

from src.tools.base import BaseTool, ToolResult


_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _safe_pkg_name(name: Any) -> Optional[str]:
    if not isinstance(name, str):
        return None
    s = name.strip()
    if not s:
        return None
    if not _SAFE_NAME_RE.fullmatch(s):
        return None
    return s


class PackageManagerQueryTool(BaseTool):
    @property
    def name(self) -> str:
        return "package_manager.query"

    def execute(self, params: Dict[str, Any]) -> ToolResult:
        action = (params.get("action") or "").strip().lower()
        name = _safe_pkg_name(params.get("name"))

        if action not in ("list", "search", "info"):
            return ToolResult(success=False, output=None, error="Invalid action. Allowed: list, search, info.")

        if action in ("search", "info") and not name:
            return ToolResult(success=False, output=None, error="Parameter 'name' is required for this action.")

        try:
            if action == "list":
                return self._list_installed()
            if action == "info":
                return self._pypi_info(name)
            if action == "search":
                return self._pip_index_versions(name)
            return ToolResult(success=False, output=None, error="Unknown action.")
        except Exception as e:
            return ToolResult(success=False, output=None, error=f"package_manager.query failed: {e}")

    def _list_installed(self) -> ToolResult:
        rows: List[dict] = []
        for dist in metadata.distributions():
            name = dist.metadata.get("Name") or dist.metadata.get("Summary") or dist.name
            version = dist.version
            if name:
                rows.append({"name": str(name), "version": str(version)})
        rows.sort(key=lambda r: r["name"].lower())
        return ToolResult(success=True, output={"count": len(rows), "packages": rows[:500]})

    def _pypi_info(self, name: str) -> ToolResult:
        url = f"https://pypi.org/pypi/{name}/json"
        try:
            r = requests.get(url, timeout=15)
            if r.status_code == 404:
                return ToolResult(success=False, output={"name": name, "url": url}, error="Package not found on PyPI.")
            r.raise_for_status()
            data = r.json()
            info = data.get("info") or {}
            releases = data.get("releases") or {}
            versions = sorted(releases.keys())
            latest = info.get("version") or (versions[-1] if versions else None)
            return ToolResult(
                success=True,
                output={
                    "name": name,
                    "url": url,
                    "summary": info.get("summary"),
                    "home_page": info.get("home_page"),
                    "license": info.get("license"),
                    "latest_version": latest,
                    "versions_count": len(versions),
                    "versions_tail": versions[-20:],
                },
            )
        except requests.RequestException as e:
            return ToolResult(success=False, output={"name": name, "url": url}, error=f"PyPI query failed: {e}")

    def _pip_index_versions(self, name: str) -> ToolResult:
        # Uses pip's index query (read-only). This does not install anything.
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pip", "index", "versions", name],
                capture_output=True,
                text=True,
                timeout=30,
            )
            out = (proc.stdout or "").strip() or (proc.stderr or "").strip()
            if proc.returncode != 0:
                return ToolResult(success=False, output={"name": name, "raw": out}, error="pip index query failed.")

            # Best-effort parse: pip prints something like:
            #   Available versions: 2.0, 1.9, ...
            versions: List[str] = []
            for line in out.splitlines():
                if "Available versions:" in line:
                    tail = line.split("Available versions:", 1)[1].strip()
                    versions = [v.strip() for v in tail.split(",") if v.strip()]
                    break
            return ToolResult(
                success=True,
                output={
                    "name": name,
                    "versions": versions[:200],
                    "raw": out if not versions else None,
                },
            )
        except subprocess.TimeoutExpired:
            return ToolResult(success=False, output={"name": name}, error="pip index query timed out.")
        except FileNotFoundError:
            return ToolResult(success=False, output={"name": name}, error="Python/pip not found.")
