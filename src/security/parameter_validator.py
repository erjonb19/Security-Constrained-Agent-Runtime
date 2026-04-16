"""Parameter validation against policy constraints (Phase 2.1 / 2.3).

Defense in depth: structural checks on tool parameters before execution, in addition
to policy engine evaluation. Used by :meth:`AgentRuntime.execute_tool`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


@dataclass
class ValidationResult:
    """Result of :func:`validate`."""

    valid: bool
    errors: List[str] = field(default_factory=list)
    constraint_violated: Optional[str] = None


_PATHLIKE_KEYS: Set[str] = frozenset(
    {
        "path",
        "repo_path",
        "cwd",
        "workspace",
        "target",
        "file",
        "destination",
        "local_path",
        "src",
        "dst",
    }
)


def _has_path_traversal(path_str: str) -> bool:
    if not path_str:
        return False
    if "\x00" in path_str:
        return True
    try:
        if ".." in Path(path_str).parts:
            return True
    except (OSError, ValueError):
        pass
    return ".." in path_str.replace("\\", "/").split("/")


def _validate_pathlike(key: str, value: str, errors: List[str]) -> Optional[str]:
    if _has_path_traversal(value):
        errors.append(f"Path traversal or invalid path in {key!r}")
        return "paths"
    return None


def _walk_strings(obj: Any, key_hint: str, errors: List[str], violated: List[Optional[str]]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            sk = str(k)
            if isinstance(v, str):
                if sk in _PATHLIKE_KEYS or key_hint in _PATHLIKE_KEYS:
                    c = _validate_pathlike(sk, v, errors)
                    if c:
                        violated.append(c)
                elif "\x00" in v:
                    errors.append(f"Null byte in parameter {sk!r}")
                    violated.append("sanitization")
            else:
                _walk_strings(v, sk, errors, violated)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _walk_strings(v, f"{key_hint}[{i}]", errors, violated)


def validate(capability: str, parameters: Dict[str, Any], constraints: Dict[str, Any]) -> ValidationResult:
    """
    Validate ``parameters`` for ``capability`` using policy ``constraints``.

    Checks include path traversal on path-like keys, ``operations`` allow-list for
    package_manager capabilities, and HTTPS enforcement for ``http.fetch`` when policy
    denies ``http://`` endpoints.
    """
    errors: List[str] = []
    violated: List[Optional[str]] = []
    params = parameters or {}

    for key, val in params.items():
        if isinstance(val, str) and key in _PATHLIKE_KEYS:
            c = _validate_pathlike(key, val, errors)
            if c:
                violated.append(c)
        elif isinstance(val, (dict, list)):
            _walk_strings(val, str(key), errors, violated)

    ops = constraints.get("operations")
    if ops is not None and isinstance(ops, (list, tuple)) and capability.startswith("package_manager."):
        action = params.get("action")
        if action is not None:
            allowed = {str(o).strip().lower() for o in ops}
            if str(action).strip().lower() not in allowed:
                errors.append(f"action {action!r} not in allowed operations {list(ops)}")
                violated.append("operations")

    if capability == "http.fetch" or capability.startswith("http."):
        url = params.get("url") or params.get("endpoint")
        if isinstance(url, str) and url.strip():
            ep = constraints.get("endpoints") or {}
            deny = ep.get("deny") or []
            deny_http = any("http://**" in str(d) or str(d).startswith("http://") for d in deny)
            if deny_http and url.strip().lower().startswith("http://"):
                errors.append("URL must use HTTPS (http:// not permitted by policy)")
                violated.append("endpoints")

    first = next((v for v in violated if v is not None), None)
    return ValidationResult(valid=len(errors) == 0, errors=errors, constraint_violated=first)
