"""HTTP fetch tool implementation.

Security note: endpoint allow/deny and HTTPS enforcement are performed by the
policy engine + parameter validator before this tool executes. This tool still
enforces response size limits to reduce data-exfil/DoS risk.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

import requests

from src.tools.base import BaseTool, ToolResult


_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([KMG]?B)\s*$", re.IGNORECASE)


def _parse_size_to_bytes(value: Any) -> Optional[int]:
    """Parse sizes like 1024, '5MB', '200KB' into bytes."""
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, float):
        return max(0, int(value))
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    m = _SIZE_RE.match(s)
    if not m:
        # fall back: try raw integer string
        try:
            return max(0, int(s))
        except Exception:
            return None
    num = float(m.group(1))
    unit = m.group(2).upper()
    mult = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3}.get(unit, 1)
    return max(0, int(num * mult))


class HttpFetchTool(BaseTool):
    @property
    def name(self) -> str:
        return "http.fetch"

    def execute(self, params: Dict[str, Any]) -> ToolResult:
        url = params.get("url")
        method = (params.get("method") or "GET").strip().upper()

        if not isinstance(url, str) or not url.strip():
            return ToolResult(success=False, output=None, error="Missing required parameter: 'url'.")
        if method not in ("GET", "POST"):
            return ToolResult(success=False, output=None, error="Invalid method. Allowed: GET, POST.")

        # Optional: allow caller to pass a policy-derived limit through params.
        # Runtime currently does not inject constraints into params, so this is
        # best-effort and used primarily by evaluation harnesses.
        max_bytes = _parse_size_to_bytes(params.get("max_response_size"))
        if max_bytes is None:
            # Default conservative cap to avoid accidental huge downloads.
            max_bytes = 5 * 1024 * 1024

        timeout_s = params.get("timeout_s")
        try:
            timeout_s = float(timeout_s) if timeout_s is not None else 15.0
        except Exception:
            timeout_s = 15.0

        try:
            # Stream so we can cap response size without buffering everything.
            req = requests.request(method, url, stream=True, timeout=timeout_s)
            status_code = int(getattr(req, "status_code", 0) or 0)
            content_type = req.headers.get("content-type") if hasattr(req, "headers") else None

            # Read up to max_bytes + 1 to detect overflow.
            chunks: list[bytes] = []
            total = 0
            for chunk in req.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total > max_bytes:
                    return ToolResult(
                        success=False,
                        output={
                            "url": url,
                            "status_code": status_code,
                            "content_type": content_type,
                            "bytes_read": total,
                            "max_response_size": max_bytes,
                        },
                        error=f"Response exceeded max_response_size ({max_bytes} bytes).",
                    )

            body_bytes = b"".join(chunks)
            # Decode as utf-8 with replacement; callers can fetch binary via another tool later.
            text = body_bytes.decode("utf-8", errors="replace")
            ok = 200 <= status_code < 300
            return ToolResult(
                success=ok,
                output={
                    "url": url,
                    "method": method,
                    "status_code": status_code,
                    "content_type": content_type,
                    "text": text,
                    "bytes": len(body_bytes),
                },
                error=None if ok else f"HTTP error {status_code}",
            )
        except requests.Timeout:
            return ToolResult(success=False, output=None, error="HTTP request timed out.")
        except requests.RequestException as e:
            return ToolResult(success=False, output=None, error=f"HTTP request failed: {e}")
        except Exception as e:
            return ToolResult(success=False, output=None, error=f"HTTP fetch tool error: {e}")
