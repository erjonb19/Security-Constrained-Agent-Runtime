"""
Policy evaluation and enforcement (plan §1.2).

Load policy via parser, validate, store. Evaluate(capability, parameters) applies
default if capability missing, checks allow/deny and constraints (paths,
endpoints, resource limits, require_approval), returns a decision object.
Path/endpoint checks use allow/deny globs with deny precedence.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from src.policies.parser import (
    load_policy as parser_load_policy,
    path_matches_globs,
    endpoint_matches_globs,
)
from src.policies.validator import validate_policy


# -----------------------------------------------------------------------------
# Decision object (plan §1.2)
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Decision:
    """Result of policy evaluation: allow/deny, reason, and optional needs_approval."""

    allowed: bool
    reason: str
    needs_approval: bool = False
    details: Optional[dict[str, Any]] = None
    policy_rule: Optional[str] = None


# -----------------------------------------------------------------------------
# Policy engine (plan §1.2)
# -----------------------------------------------------------------------------


class PolicyEngine:
    """
    Load policy, evaluate capability + parameters, return decisions.

    - load_policy(path): load via parser, validate, store.
    - evaluate(capability, parameters): apply default if missing; if allowed,
      evaluate path/endpoint constraints (deny takes precedence); return
      Decision(allowed, reason, needs_approval).
    - get_explanation(decision): human-readable string.
    """

    def __init__(self) -> None:
        self._policy: dict[str, Any] = {}

    def load_policy(self, path: str | Path | None = None) -> None:
        """
        Load policy from file path (YAML/JSON), validate, and store.

        Uses parser.load_policy and validator.validate_policy. Raises on
        validation error.
        """
        policy = parser_load_policy(path)
        validate_policy(policy)
        self._policy = policy

    def get_policy(self) -> dict[str, Any]:
        """Return the currently loaded policy (read-only)."""
        return self._policy

    def _get_default_policy(self) -> str:
        """Return 'deny' or 'allow' for unknown capabilities."""
        return self._policy.get("default_policy", "deny")

    def _find_capability(self, capability: str) -> Optional[dict[str, Any]]:
        """Return the capability config dict if present."""
        caps = self._policy.get("capabilities") or []
        for c in caps:
            if c.get("name") == capability:
                return c
        return None

    def get_capability_constraints(self, capability: str) -> dict[str, Any]:
        """Return the constraints dict for a named capability, or {} if not listed."""
        cap = self._find_capability(capability)
        if cap is None:
            return {}
        return dict(cap.get("constraints") or {})

    def evaluate(self, capability: str, parameters: Optional[dict[str, Any]] = None) -> Decision:
        """
        Evaluate (capability, parameters) against the loaded policy.

        1. If capability not in policy, apply default_policy (deny or allow).
        2. If allowed, evaluate path/endpoint constraints (deny takes precedence).
        3. Set needs_approval if require_approval is true in constraints.
        4. Return Decision(allowed, reason, needs_approval).
        """
        parameters = parameters or {}
        cap_config = self._find_capability(capability)

        if cap_config is None:
            default = self._get_default_policy()
            if default == "allow":
                return Decision(
                    allowed=True,
                    reason="Capability not in policy; default_policy is allow.",
                    needs_approval=False,
                )
            return Decision(
                allowed=False,
                reason=f"Capability {capability!r} not in policy; default_policy is deny.",
            )

        if not cap_config.get("allowed", False):
            return Decision(
                allowed=False,
                reason=f"Capability {capability!r} is explicitly denied by policy.",
            )

        constraints = cap_config.get("constraints") or {}

        # Path constraints (for capabilities that use a path parameter)
        if capability.startswith("filesystem.") or "path" in parameters:
            path_val = parameters.get("path")
            if path_val is not None and isinstance(path_val, str):
                paths_cfg = constraints.get("paths") or {}
                allow_list = paths_cfg.get("allow") or []
                deny_list = paths_cfg.get("deny") or []
                try:
                    path_resolved = str(Path(path_val).resolve())
                except Exception:
                    path_resolved = path_val
                if not path_matches_globs(path_resolved, allow_list, deny_list):
                    return Decision(
                        allowed=False,
                        reason=f"Path {path_val!r} is not allowed by policy (deny or not in allow list).",
                        details={"path": path_resolved, "capability": capability},
                    )

        # Endpoint constraints (for http.fetch etc.)
        if "endpoints" in constraints or "url" in parameters or "endpoint" in parameters:
            url = parameters.get("url") or parameters.get("endpoint")
            if url is not None and isinstance(url, str):
                endpoints_cfg = constraints.get("endpoints") or {}
                allow_list = endpoints_cfg.get("allow") or []
                deny_list = endpoints_cfg.get("deny") or []
                if not endpoint_matches_globs(url, allow_list, deny_list):
                    return Decision(
                        allowed=False,
                        reason=f"Endpoint {url!r} is not allowed by policy (deny or not in allow list).",
                        details={"url": url, "capability": capability},
                    )

        # Resource limits: pass through in details for runtime/tool to enforce
        details: dict[str, Any] = {}
        if "max_file_size" in constraints:
            details["max_file_size"] = constraints["max_file_size"]
        if "max_response_size" in constraints:
            details["max_response_size"] = constraints["max_response_size"]

        needs_approval = bool(constraints.get("require_approval", False))

        return Decision(
            allowed=True,
            reason="Allowed by policy.",
            needs_approval=needs_approval,
            details=details if details else None,
        )

    def get_explanation(self, decision: Decision) -> str:
        """
        Return a human-readable explanation of the decision (plan §1.2).

        Can be extended to delegate to a full explainer module later.
        """
        if decision.allowed:
            if decision.needs_approval:
                return f"Allowed; reason: {decision.reason} This action requires approval before execution."
            return decision.reason
        return f"Denied: {decision.reason}"
