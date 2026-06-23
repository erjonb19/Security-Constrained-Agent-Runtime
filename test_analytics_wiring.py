"""
test_analytics_wiring.py
========================
Proves the analytics tool runs through your REAL runtime and policy, with two
independent layers of control:

  Layer 1  policy engine     -> may analytics.query_aggregate run at all?
  Layer 2  sql_guard         -> is THIS specific query safe?

Run from the repo root with venv311 active:
    python test_analytics_wiring.py

Expected:
  [1] allowed query        -> ALLOWED by policy, ALLOWED by guard, rows returned
  [2] drop table           -> ALLOWED by policy, DENIED by guard
  [3] PHI table            -> ALLOWED by policy, DENIED by guard
  [4] data.write           -> DENIED by policy (tool never even runs)
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.runtime.agent_runtime import AgentRuntime
from analytics_query_tool import AnalyticsQueryTool


POLICY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "medicare_policy.yaml")


def show(label: str, capability: str, params: dict, runtime: AgentRuntime) -> None:
    print(f"\n[{label}] capability={capability}")
    print(f"        params={params}")
    result = runtime.execute_tool(capability, params)

    # Layer 1: did the policy allow this capability to run?
    if not result.allowed:
        reason = getattr(result, "explanation", None)
        if not reason and getattr(result, "decision", None) is not None:
            reason = getattr(result.decision, "reason", "not permitted")
        print(f"        -> DENIED BY POLICY: {reason or 'not permitted'}")
        return

    # Layer 2: the tool ran. Did the guard inside it allow the query?
    tool_result = result.result
    if tool_result is None:
        print("        -> policy allowed, but no tool result returned")
        return
    if tool_result.success:
        out = tool_result.output or {}
        print(f"        -> ALLOWED. rows={out.get('row_count')} sql={out.get('safe_sql')}")
        for row in (out.get("rows") or [])[:5]:
            print(f"             {row}")
    else:
        print(f"        -> TOOL DENIED: {tool_result.error}")


def main() -> None:
    runtime = AgentRuntime()
    runtime.load_policy(POLICY_PATH)
    runtime.register_tool(AnalyticsQueryTool())   # seeds demo Gold in-memory

    show("1 allowed query", "analytics.query_aggregate",
         {"sql": "SELECT region, readmit_per_1k FROM gold_utilization "
                 "WHERE year = 2023 ORDER BY readmit_per_1k DESC"}, runtime)

    show("2 drop table", "analytics.query_aggregate",
         {"sql": "DROP TABLE gold_utilization"}, runtime)

    show("3 PHI table", "analytics.query_aggregate",
         {"sql": "SELECT * FROM raw_member_phi"}, runtime)

    show("4 data.write", "data.write",
         {"table": "gold_utilization", "values": "anything"}, runtime)


if __name__ == "__main__":
    main()
