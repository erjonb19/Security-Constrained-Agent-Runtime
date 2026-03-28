"""Main runtime orchestrator for agent security (plan §1.4)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from .capability import resolve_capability
from .policy_engine import Decision, PolicyEngine
from src.tools.base import BaseTool, ToolResult, ToolError, get_tool, register_tool as base_register_tool

logger = logging.getLogger(__name__)


@dataclass
class ExecuteResult:
    """Result of execute_tool: allowed, result (if allowed), explanation."""

    allowed: bool
    result: Optional[ToolResult] = None
    explanation: str = ""
    decision: Optional[Decision] = None


class AgentRuntime:
    """
    Orchestrator: evaluate policy, optional approval, execute tool, return result.

    - execute_tool(capability, parameters): main entry (plan §1.4).
    - register_tool(tool): delegate to tools.base.register_tool.
    - request_approval(capability, parameters): sync callback or default deny when needs_approval.
    """

    def __init__(
        self,
        policy_engine: Optional[PolicyEngine] = None,
        approval_callback: Optional[Callable[[str, Dict[str, Any]], bool]] = None,
    ) -> None:
        self._policy_engine = policy_engine or PolicyEngine()
        self._approval_callback = approval_callback

    def load_policy(self, path: Optional[str | Path] = None) -> None:
        """Load policy from file (YAML/JSON). Raises on validation error."""
        self._policy_engine.load_policy(path)

    def evaluate_policy(
        self, capability: str, parameters: Optional[Dict[str, Any]] = None
    ) -> Decision:
        """Evaluate policy only (no tool lookup or execution). Use for pre-checks."""
        parameters = parameters or {}
        capability = resolve_capability(capability)
        return self._policy_engine.evaluate(capability, parameters)

    def get_explanation(self, decision: Decision) -> str:
        """Return human-readable explanation for a policy decision."""
        return self._policy_engine.get_explanation(decision)

    def register_tool(self, tool: BaseTool) -> None:
        """Register a tool implementation (capability name = tool.name)."""
        base_register_tool(tool)

    def request_approval(self, capability: str, parameters: Dict[str, Any]) -> bool:
        """
        Return True if approved, False if rejected or no callback.
        When needs_approval and no callback is set, defaults to False (deny).
        """
        if self._approval_callback is None:
            return False
        return self._approval_callback(capability, parameters)

    def execute_tool(
        self,
        capability: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> ExecuteResult:
        """
        Main entry (plan §1.4):
        1. Evaluate policy. If deny → return denial + explanation.
        2. If allow and needs_approval → request_approval; if not approved → deny.
        3. If allow (and approved if required) → get tool, execute, return result.
        """
        parameters = parameters or {}
        capability = resolve_capability(capability)
        decision = self._policy_engine.evaluate(capability, parameters)

        if not decision.allowed:
            explanation = self._policy_engine.get_explanation(decision)
            logger.info("execute_tool denied: %s - %s", capability, explanation)
            return ExecuteResult(
                allowed=False,
                explanation=explanation,
                decision=decision,
            )

        if decision.needs_approval:
            if not self.request_approval(capability, parameters):
                explanation = "Approval required but not granted."
                logger.info("execute_tool approval denied: %s", capability)
                return ExecuteResult(allowed=False, explanation=explanation, decision=decision)

        tool = get_tool(capability)
        if tool is None:
            explanation = f"No tool registered for capability {capability!r}."
            logger.warning(explanation)
            return ExecuteResult(allowed=False, explanation=explanation, decision=decision)

        try:
            tool_result = tool.execute(parameters)
        except ToolError as e:
            explanation = str(e)
            logger.exception("execute_tool ToolError: %s", capability)
            return ExecuteResult(
                allowed=True,
                result=ToolResult(success=False, error=explanation),
                explanation=explanation,
                decision=decision,
            )
        except Exception as e:
            explanation = f"Tool execution failed: {e}"
            logger.exception("execute_tool failed: %s", capability)
            return ExecuteResult(
                allowed=True,
                result=ToolResult(success=False, error=explanation),
                explanation=explanation,
                decision=decision,
            )

        explanation = self._policy_engine.get_explanation(decision)
        return ExecuteResult(
            allowed=True,
            result=tool_result,
            explanation=explanation,
            decision=decision,
        )


ARG_POLICY = "policy"
DEFAULT_POLICY = "configs/default_policy.yaml"

def main() -> None:
    """CLI entry: load policy, create runtime, optionally run one execute_tool (demo)."""
    import argparse
    import json
    parser = argparse.ArgumentParser(description="Security-constrained agent runtime (plan §1.4)")
    parser.add_argument(
        "--" + ARG_POLICY,
        type=str,
        default=DEFAULT_POLICY,
        required=False,
        help=f"Path to policy (default: {DEFAULT_POLICY})"
    )
    parser.add_argument(
        "--capability",
        type=str,
        required=True,
        help="REQUIRED: The tool capability to execute"
    )
    parser.add_argument(
        "--params",
        type=str,
        default="{}",
        required=False,
        help="JSON params (default: {})"
    )
    args = parser.parse_args()
    runtime = AgentRuntime()
    # policy_path = Path(args.policy) if args.policy else None
    # runtime.load_policy(policy_path)
    policy_path = Path(args.policy) if args.policy else Path(DEFAULT_POLICY)
    runtime.load_policy(policy_path)
    if args.capability:
        params = json.loads(args.params)
        result = runtime.execute_tool(args.capability, params)
        print("allowed:", result.allowed)
        print("explanation:", result.explanation)
        if result.result:
            print("result:", result.result.to_dict())
    else:
        print("Runtime ready. Use --capability and --params to run a tool call, or use as a library.")
