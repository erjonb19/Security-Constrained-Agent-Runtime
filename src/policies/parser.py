"""
YAML/JSON policy parser.

Implements plan §1.1 (docs/plan.md): load policy from file, parse into internal
structure (version, default_policy, capabilities with constraints), and support
globs for paths/endpoints via pathspec.

Component reuse (see docs/COMPONENT_REUSE_COMPARISON.md):
- NeMo Guardrails: YAML config loading from file, config structure patterns
  (COMPONENT_REUSE_COMPARISON §5.1, §7 – nemoguardrails/config/config.py).
- OPA: Path/glob evaluation order (deny takes precedence over allow)
  (COMPONENT_REUSE_COMPARISON §2.2 – path matching and constraints).
- Design: Internal structure follows DESIGN.md §3.1 (Policy Structure).
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any

import yaml

# Module-level logger for debug messages
logger = logging.getLogger(__name__)

# pathspec: used for path/endpoint glob matching (plan §1.1; COMPONENT_REUSE §2.2 OPA)
try:
    import pathspec
except ImportError:
    pathspec = None  # type: ignore[assignment]


# -----------------------------------------------------------------------------
# Internal structures (DESIGN.md §3.1 – Policy Structure)
# -----------------------------------------------------------------------------


def _normalize_default_policy(value: Any) -> str:
    """Normalize default_policy to 'deny' or 'allow' (design §3.1)."""
    if value is None:
        logger.debug("default_policy: missing, using 'deny'")
        return "deny"
    s = str(value).strip().lower()
    if s in ("deny", "allow"):
        logger.debug("default_policy: normalized to %r", s)
        return s
    logger.debug("default_policy: invalid value %r, using 'deny'", value)
    return "deny"


def _ensure_list(value: Any, key: str) -> list[str]:
    """Ensure a constraint list (paths.allow/deny, endpoints.allow/deny) is a list of strings."""
    if value is None:
        logger.debug("%s: None -> []", key)
        return []
    if isinstance(value, list):
        out = [str(item).strip() for item in value if item is not None]
        logger.debug("%s: list of %d item(s)", key, len(out))
        return out
    out = [str(value).strip()]
    logger.debug("%s: single value -> %s", key, out)
    return out


def _ensure_constraints(raw: Any) -> dict[str, Any]:
    """
    Normalize a capability's constraints dict (design §3.1).
    Supports: paths (allow/deny), endpoints (allow/deny), max_file_size,
    max_response_size, require_approval, prevent_history_rewrite, prevent_force_push,
    operations.
    """
    if raw is None or not isinstance(raw, dict):
        logger.debug("constraints: raw is None or not dict -> {}")
        return {}
    out: dict[str, Any] = {}
    # Path constraints – stored as lists; glob matching done via pathspec (plan §1.1)
    if "paths" in raw and isinstance(raw["paths"], dict):
        p = raw["paths"]
        out["paths"] = {
            "allow": _ensure_list(p.get("allow"), "paths.allow"),
            "deny": _ensure_list(p.get("deny"), "paths.deny"),
        }
    else:
        out["paths"] = {"allow": [], "deny": []}
    # Endpoint constraints – same allow/deny list pattern (design §3.1)
    if "endpoints" in raw and isinstance(raw["endpoints"], dict):
        e = raw["endpoints"]
        out["endpoints"] = {
            "allow": _ensure_list(e.get("allow"), "endpoints.allow"),
            "deny": _ensure_list(e.get("deny"), "endpoints.deny"),
        }
    else:
        out["endpoints"] = {"allow": [], "deny": []}
    # Resource limits and flags
    if "max_file_size" in raw and raw["max_file_size"] is not None:
        out["max_file_size"] = raw["max_file_size"]
    if "max_response_size" in raw and raw["max_response_size"] is not None:
        out["max_response_size"] = raw["max_response_size"]
    if "require_approval" in raw:
        out["require_approval"] = bool(raw["require_approval"])
    if "prevent_history_rewrite" in raw:
        out["prevent_history_rewrite"] = bool(raw["prevent_history_rewrite"])
    if "prevent_force_push" in raw:
        out["prevent_force_push"] = bool(raw["prevent_force_push"])
    if "operations" in raw and isinstance(raw["operations"], list):
        out["operations"] = [str(x) for x in raw["operations"]]
    logger.debug("constraints: normalized keys %s", list(out.keys()))
    return out


def _parse_capability(raw: Any) -> dict[str, Any] | None:
    """Parse one capability entry: name, allowed (bool), constraints (design §3.1)."""
    if not isinstance(raw, dict):
        logger.debug("parse_capability: skip non-dict item")
        return None
    name = raw.get("name")
    if not name or not str(name).strip():
        logger.debug("parse_capability: skip item with missing/empty name")
        return None
    allowed = raw.get("allowed", True)
    if isinstance(allowed, str):
        allowed = allowed.strip().lower() in ("true", "yes", "1")
    else:
        allowed = bool(allowed)
    cap = {
        "name": str(name).strip(),
        "allowed": allowed,
        "constraints": _ensure_constraints(raw.get("constraints")),
    }
    logger.debug("parse_capability: parsed %r allowed=%s", cap["name"], allowed)
    return cap


def _parse_capabilities(raw: Any) -> list[dict[str, Any]]:
    """Parse capabilities list (design §3.1)."""
    if raw is None:
        logger.debug("parse_capabilities: raw is None -> []")
        return []
    if not isinstance(raw, list):
        logger.debug("parse_capabilities: raw is not list -> []")
        return []
    capabilities = []
    for i, item in enumerate(raw):
        cap = _parse_capability(item)
        if cap:
            capabilities.append(cap)
        else:
            logger.debug("parse_capabilities: skipped item index %d", i)
    logger.debug("parse_capabilities: %d capability(ies) parsed", len(capabilities))
    return capabilities


# -----------------------------------------------------------------------------
# File loading (NeMo Guardrails – COMPONENT_REUSE §5.1, §7: config load from file)
# -----------------------------------------------------------------------------


def _load_raw_from_file(path: str | Path) -> dict[str, Any]:
    """
    Load policy from file path (YAML or JSON).
    Adapted from NeMo Guardrails config loading pattern: load from path,
    support YAML/JSON (COMPONENT_REUSE §5.1, §7 – nemoguardrails/config/config.py).
    """
    path = Path(path)
    logger.debug("load_raw: path=%s", path.resolve())
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")
    if not path.is_file():
        raise IsADirectoryError(f"Policy path is a directory: {path}")

    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8")
    logger.debug("load_raw: suffix=%s, read %d bytes", suffix or "(none)", len(text))

    if suffix in (".yaml", ".yml"):
        # NeMo Guardrails: YAML config structure (COMPONENT_REUSE §5.1)
        data = yaml.safe_load(text)
        logger.debug("load_raw: parsed as YAML")
    elif suffix == ".json":
        data = json.loads(text)
        logger.debug("load_raw: parsed as JSON")
    else:
        # Try YAML first, then JSON (e.g. extensionless or .config)
        try:
            data = yaml.safe_load(text)
            logger.debug("load_raw: parsed as YAML (no extension)")
        except Exception:
            data = json.loads(text)
            logger.debug("load_raw: parsed as JSON (fallback)")

    if not isinstance(data, dict):
        raise ValueError("Policy root must be a mapping (YAML/JSON object)")
    logger.debug("load_raw: root keys %s", list(data.keys()) if isinstance(data, dict) else "n/a")
    return data


# -----------------------------------------------------------------------------
# Public API (plan §1.1)
# -----------------------------------------------------------------------------


def load_policy(path: str | Path) -> dict[str, Any]:
    """
    Load policy from file path (YAML or JSON) and parse into internal structure.

    Internal structure (DESIGN.md §3.1):
    - version: str (e.g. "1.0")
    - default_policy: "deny" | "allow"
    - capabilities: list of { name, allowed, constraints }

    Each capability's constraints may include:
    - paths.allow / paths.deny (glob lists; matching via pathspec – plan §1.1)
    - endpoints.allow / endpoints.deny (glob lists)
    - max_file_size, max_response_size, require_approval,
      prevent_history_rewrite, prevent_force_push, operations

    Component reuse:
    - NeMo Guardrails: loading from path, YAML/JSON (COMPONENT_REUSE §5.1, §7).
    - OPA: deny takes precedence over allow for path/endpoint lists (§2.2).
    """
    raw = _load_raw_from_file(path)
    logger.debug("load_policy: raw loaded, normalizing")

    version = str(raw.get("version", "1.0")).strip()
    default_policy = _normalize_default_policy(raw.get("default_policy"))
    capabilities = _parse_capabilities(raw.get("capabilities"))

    result = {
        "version": version,
        "default_policy": default_policy,
        "capabilities": capabilities,
    }
    logger.debug("load_policy: done version=%s default_policy=%s capabilities=%d", version, default_policy, len(capabilities))
    return result


# -----------------------------------------------------------------------------
# Glob support via pathspec (plan §1.1; OPA §2.2 – path matching, allow/deny)
# -----------------------------------------------------------------------------


def compile_path_specs(
    allow_patterns: list[str], deny_patterns: list[str]
) -> tuple[Any, Any]:
    """
    Compile path allow/deny glob lists into pathspec matchers.

    OPA pattern (COMPONENT_REUSE §2.2): deny is evaluated first; if a path
    matches deny it is denied; otherwise allow is checked. We return (allow_spec, deny_spec)
    so the policy engine can apply: if deny matches → deny; elif allow matches → allow.

    Uses pathspec (plan §1.1) with gitignore-style patterns; glob-style patterns
    are converted (e.g. ** for recursive).
    """
    if pathspec is None:
        logger.debug("compile_path_specs: pathspec module not available -> (None, None)")
        return (None, None)

    def to_gitignore_lines(patterns: list[str]) -> list[str]:
        # pathspec uses gitignore syntax; ** is supported
        return [p for p in patterns if p]

    allow_lines = to_gitignore_lines(allow_patterns)
    deny_lines = to_gitignore_lines(deny_patterns)
    logger.debug("compile_path_specs: allow %d pattern(s), deny %d pattern(s)", len(allow_lines), len(deny_lines))

    allow_spec = pathspec.PathSpec.from_lines("gitwildmatch", allow_lines) if allow_lines else None
    deny_spec = pathspec.PathSpec.from_lines("gitwildmatch", deny_lines) if deny_lines else None
    return (allow_spec, deny_spec)


def path_matches_globs(
    path: str | Path,
    allow_patterns: list[str],
    deny_patterns: list[str],
    *,
    allow_spec: Any = None,
    deny_spec: Any = None,
) -> bool:
    """
    Return True if path is allowed by allow/deny globs (OPA §2.2: deny takes precedence).

    If allow_spec/deny_spec are provided, use them; otherwise compile from
    allow_patterns/deny_patterns. Path should be normalized (e.g. absolute).
    """
    path_str = str(Path(path).resolve())
    if deny_spec is None or allow_spec is None:
        allow_spec, deny_spec = compile_path_specs(allow_patterns, deny_patterns)
    if pathspec is None:
        # Fallback: no pathspec – treat as allow if in allow list as literal, and not in deny
        if deny_patterns and path_str in deny_patterns:
            logger.debug("path_matches_globs: path %r in deny list (literal) -> False", path_str)
            return False
        result = path_str in allow_patterns if allow_patterns else False
        logger.debug("path_matches_globs: path %r (pathspec unavailable) -> %s", path_str, result)
        return result
    # OPA: deny first (COMPONENT_REUSE §2.2)
    if deny_spec and deny_spec.match_file(path_str):
        logger.debug("path_matches_globs: path %r matched deny -> False", path_str)
        return False
    if allow_spec and allow_spec.match_file(path_str):
        logger.debug("path_matches_globs: path %r matched allow -> True", path_str)
        return True
    # No allow match → deny (default-deny)
    result = not allow_patterns
    logger.debug("path_matches_globs: path %r no allow match, allow_patterns empty=%s -> %s", path_str, not allow_patterns, result)
    return result


def endpoint_matches_globs(
    url: str, allow_patterns: list[str], deny_patterns: list[str]
) -> bool:
    """
    Return True if URL is allowed by endpoint allow/deny globs (design §3.1).
    Deny takes precedence (OPA §2.2). Uses fnmatch-style matching for URL patterns.
    """
    import fnmatch
    url_norm = url.strip()
    for pattern in deny_patterns:
        if fnmatch.fnmatch(url_norm, pattern):
            logger.debug("endpoint_matches_globs: url %r matched deny pattern %r -> False", url_norm, pattern)
            return False
    for pattern in allow_patterns:
        if fnmatch.fnmatch(url_norm, pattern):
            logger.debug("endpoint_matches_globs: url %r matched allow pattern %r -> True", url_norm, pattern)
            return True
    result = not allow_patterns
    logger.debug("endpoint_matches_globs: url %r no allow match -> %s", url_norm, result)
    return result


# -----------------------------------------------------------------------------
# Runnable as script: load policy from path and print (with optional --debug)
# -----------------------------------------------------------------------------


def _main() -> None:
    parser = argparse.ArgumentParser(
        description="Load and parse a policy file (YAML or JSON), print the normalized structure."
    )
    parser.add_argument(
        "path",
        nargs="?",
        default="examples/policies/Policy.yaml",
        help="Path to policy file (default: examples/policies/Policy.yaml)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON (default: pretty-print dict)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s [%(name)s] %(message)s",
    )
    if not args.debug:
        logging.getLogger(__name__).setLevel(logging.WARNING)

    path = Path(args.path)
    if not path.is_absolute():
        # Resolve relative to cwd; common when run from repo root
        path = path.resolve()
    policy = load_policy(path)
    if args.json:
        print(json.dumps(policy, indent=2))
    else:
        print("version:", policy["version"])
        print("default_policy:", policy["default_policy"])
        print("capabilities:", len(policy["capabilities"]))
        for cap in policy["capabilities"]:
            print(f"  - {cap['name']!r} allowed={cap['allowed']}")


if __name__ == "__main__":
    _main()
