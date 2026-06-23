"""Brief commit tool (capability: brief.commit).

Gated capability: the policy requires human approval AND groundedness. Approval
is handled by the runtime before this tool runs. This tool enforces the second
half: every structured claim in the brief must trace to a real returned row in
the shared QueryLedger, or the commit is refused.

A claim is structured, e.g.:
    {"value": 18.2, "metric": "readmit_per_1k",
     "dims": {"region": "Bronx"}, "source_query_id": 1}

The narrative is free text for readability, but it may only restate numbers that
exist as grounded claims. Anything else is the agent inventing a figure.
"""

from __future__ import annotations

from typing import Any, Dict, List

from src.tools.base import BaseTool, ToolResult
from groundedness import QueryLedger, Claim, check_claims


class BriefCommitTool(BaseTool):
    def __init__(self, ledger: QueryLedger):
        self._ledger = ledger

    @property
    def name(self) -> str:
        return "brief.commit"

    def execute(self, params: Dict[str, Any]) -> ToolResult:
        claims_raw = params.get("claims")
        if not isinstance(claims_raw, list) or not claims_raw:
            return ToolResult(success=False, output=None,
                              error="Parameter 'claims' (a non-empty list of structured claims) is required.")

        try:
            claims: List[Claim] = [Claim.from_dict(c) for c in claims_raw]
        except (KeyError, ValueError, TypeError) as e:
            return ToolResult(success=False, output=None,
                              error=f"malformed claim: {e}")

        result = check_claims(claims, self._ledger)
        if not result.ok:
            ungrounded = [f.reason for f in result.ungrounded]
            return ToolResult(
                success=False,
                output={"ungrounded": ungrounded,
                        "grounded_count": len(claims) - len(ungrounded),
                        "total_claims": len(claims)},
                error=f"groundedness failed: {len(ungrounded)} of {len(claims)} claim(s) "
                      f"not supported by returned data; commit blocked.",
            )

        # All claims grounded. Commit. In the demo this just returns the brief
        # as committed; in production this is where it persists/publishes.
        return ToolResult(
            success=True,
            output={
                "committed": True,
                "narrative": params.get("narrative", ""),
                "claims_verified": len(claims),
                "evidence": [{"claim": f.claim.label or f.claim.metric,
                              "matched_query_id": f.matched_query_id} for f in result.findings],
            },
        )
