"""Main runtime orchestrator for agent security (plan §1.4)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from .capability import resolve_capability
from .policy_engine import Decision, PolicyEngine
from .audit_logger import AuditLogger, DecisionType
from src.tools.base import BaseTool, ToolResult, ToolError, get_tool, register_tool as base_register_tool
# [TASK 2.3] Import parameter validator to enable pre-execution validation of tool parameters.
# This replaces the TODO stub in parameter_validator.py (completed in task 2.1).
from src.security.parameter_validator import validate as validate_parameters
from src.security.injection_detector import InjectionDetector

logger = logging.getLogger(__name__)

_DEFAULT_INJECTION_DETECTOR = object()


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
        audit_logger: Optional[AuditLogger] = None,
        injection_detector: Any = _DEFAULT_INJECTION_DETECTOR,
    ) -> None:
        self._policy_engine = policy_engine or PolicyEngine()
        self._approval_callback = approval_callback
        self.audit_logger = audit_logger
        if injection_detector is _DEFAULT_INJECTION_DETECTOR:
            self._injection_detector: Optional[InjectionDetector] = InjectionDetector()
        else:
            self._injection_detector = injection_detector

    def load_policy(self, path: Optional[str | Path] = None) -> None:
        """Load policy from file (YAML/JSON). Raises on validation error."""
        self._policy_engine.load_policy(path)

    def evaluate_policy(self, capability: str, parameters: Optional[Dict[str, Any]] = None) -> Decision:
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
        3. [TASK 2.3] Parameter validation → if invalid → deny and log.
        4. If allow (and approved if required) → get tool, execute, return result.
        """
        parameters = parameters or {}
        capability = resolve_capability(capability)

        # Time policy evaluation
        eval_start_time = datetime.now()
        decision = self._policy_engine.evaluate(capability, parameters)
        evaluation_time_ms = (datetime.now() - eval_start_time).total_seconds() * 1000

        # Log policy evaluation
        if self.audit_logger:
            decision_type = DecisionType.ALLOW if decision.allowed else DecisionType.DENY
            if decision.needs_approval:
                decision_type = DecisionType.REQUIRE_APPROVAL

            self.audit_logger.log_policy_evaluation(
                capability=capability,
                decision=decision_type,
                reason=decision.reason or "Policy evaluation",
                parameters=parameters,
                policy_rule=decision.policy_rule,
                evaluation_time_ms=evaluation_time_ms,
            )

        if not decision.allowed:
            explanation = self._policy_engine.get_explanation(decision)
            logger.info("execute_tool denied: %s - %s", capability, explanation)
            return ExecuteResult(
                allowed=False,
                explanation=explanation,
                decision=decision,
            )

        if decision.needs_approval:
            # Log approval request
            if self.audit_logger:
                self.audit_logger.log_approval_requested(
                    capability=capability, parameters=parameters, reason="Policy requires approval for this operation"
                )

            approved = self.request_approval(capability, parameters)

            # Log approval decision
            if self.audit_logger:
                self.audit_logger.log_approval_decision(
                    request_event_id="",  # Could be tracked if needed
                    capability=capability,
                    approved=approved,
                    approver="approval_callback",
                    comment="Callback decision",
                )

            if not approved:
                explanation = "Approval required but not granted."
                logger.info("execute_tool approval denied: %s", capability)
                return ExecuteResult(allowed=False, explanation=explanation, decision=decision)

        # [TASK 2.3] Parameter validation — runs after policy allows and after approval check,
        # before tool lookup and execution. This enforces type, path traversal, enum, range,
        # and shell-pattern constraints defined in the policy. On failure, deny and log so
        # the audit trail captures exactly which constraint was violated.
        # Old code went straight to: tool = get_tool(capability)
        cap_config = self._policy_engine._find_capability(capability)
        constraints = cap_config.get("constraints") or {} if cap_config else {}

        validation = validate_parameters(capability, parameters, constraints)
        if not validation.valid:
            explanation = "Parameter validation failed: " + "; ".join(validation.errors)
            logger.info("execute_tool validation denied: %s - %s", capability, explanation)

            if self.audit_logger:
                self.audit_logger.log_parameter_validation(
                    capability=capability,
                    parameters=parameters,
                    validation_errors=validation.errors,
                    constraint_violated=validation.constraint_violated,
                )

            return ExecuteResult(
                allowed=False,
                explanation=explanation,
                decision=decision,
            )
        # [END TASK 2.3]

        if self._injection_detector is not None:
            inj = self._injection_detector.scan(capability, parameters)
            if not inj.clean:
                explanation = (
                    f"Blocked: possible injection in tool parameters ({inj.injection_type}). {inj.reason}"
                )
                logger.info(
                    "execute_tool injection blocked: %s at %s",
                    capability,
                    inj.parameter_path,
                )
                if self.audit_logger:
                    self.audit_logger.log_injection_detected(
                        capability=capability,
                        parameters=parameters,
                        injection_type=inj.injection_type,
                        pattern_matched=inj.pattern_matched,
                        context={
                            "parameter_path": inj.parameter_path,
                            "reason": inj.reason,
                        },
                    )
                return ExecuteResult(allowed=False, explanation=explanation, decision=None)

        tool = get_tool(capability)
        if tool is None:
            explanation = f"No tool registered for capability {capability!r}."
            logger.warning(explanation)

            if self.audit_logger:
                self.audit_logger.log_tool_execution(
                    capability=capability, parameters=parameters, success=False, execution_time_ms=0, error=explanation
                )

            return ExecuteResult(allowed=False, explanation=explanation, decision=decision)

        # Execute tool with timing
        exec_start_time = datetime.now()
        try:
            tool_result = tool.execute(parameters)
            execution_time_ms = (datetime.now() - exec_start_time).total_seconds() * 1000

            # Log successful execution
            if self.audit_logger:
                self.audit_logger.log_tool_execution(
                    capability=capability,
                    parameters=parameters,
                    success=tool_result.success,
                    execution_time_ms=execution_time_ms,
                    result={
                        "output_length": len(str(tool_result.output)) if tool_result.output else 0,
                        "success": tool_result.success,
                    },
                    error=tool_result.error if not tool_result.success else None,
                )

        except ToolError as e:
            execution_time_ms = (datetime.now() - exec_start_time).total_seconds() * 1000
            explanation = str(e)
            logger.exception("execute_tool ToolError: %s", capability)

            if self.audit_logger:
                self.audit_logger.log_tool_execution(
                    capability=capability,
                    parameters=parameters,
                    success=False,
                    execution_time_ms=execution_time_ms,
                    error=explanation,
                )

            return ExecuteResult(
                allowed=True,
                result=ToolResult(success=False, error=explanation),
                explanation=explanation,
                decision=decision,
            )
        except Exception as e:
            execution_time_ms = (datetime.now() - exec_start_time).total_seconds() * 1000
            explanation = f"Tool execution failed: {e}"
            logger.exception("execute_tool failed: %s", capability)

            if self.audit_logger:
                self.audit_logger.log_tool_execution(
                    capability=capability,
                    parameters=parameters,
                    success=False,
                    execution_time_ms=execution_time_ms,
                    error=explanation,
                )

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
