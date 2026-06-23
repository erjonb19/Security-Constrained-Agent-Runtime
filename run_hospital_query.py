"""
run_hospital_query.py
=====================
Fires real care-navigation questions at the hospital-profile Gold THROUGH your
governed runtime. Every query passes the same two layers as your wiring test:

  Layer 1  policy engine   -> may analytics.query_aggregate run at all?
  Layer 2  sql_guard       -> is THIS specific query safe (read-only, allowed table, row cap)?

Prereqs:
  1. Built medallion\\hospital_gold.duckdb (python build_hospital_gold.py)
  2. Added "gold_hospital_profile" to ALLOWED_TABLES in sql_guard.py
     (otherwise every query below returns DENIED BY GUARD: table not allowed)

Run from the repo root with venv311 active:
    python run_hospital_query.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.runtime.agent_runtime import AgentRuntime
from analytics_query_tool import AnalyticsQueryTool

POLICY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "medicare_policy.yaml")
GOLD_DB = "medallion/hospital_gold.duckdb"


def show(label: str, sql: str, runtime: AgentRuntime) -> None:
    print(f"\n[{label}]")
    print(f"  sql: {sql}")
    result = runtime.execute_tool("analytics.query_aggregate", {"sql": sql})

    # Layer 1: policy
    if not result.allowed:
        reason = getattr(result, "explanation", None)
        if not reason and getattr(result, "decision", None) is not None:
            reason = getattr(result.decision, "reason", "not permitted")
        print(f"  -> DENIED BY POLICY: {reason or 'not permitted'}")
        return

    # Layer 2: guard + execution
    tool_result = result.result
    if tool_result is None:
        print("  -> policy allowed, but no tool result returned")
        return
    if not tool_result.success:
        print(f"  -> DENIED BY GUARD: {tool_result.error}")
        return

    out = tool_result.output or {}
    print(f"  -> ALLOWED. rows={out.get('row_count')}")
    print(f"     safe_sql: {out.get('safe_sql')}")
    for row in (out.get("rows") or [])[:15]:
        print(f"       {row}")


def main() -> None:
    if not os.path.exists(GOLD_DB):
        sys.exit(f"missing {GOLD_DB} -- run build_hospital_gold.py first")

    runtime = AgentRuntime()
    runtime.load_policy(POLICY_PATH)
    # point the analytics tool at the REAL hospital Gold, not the seeded demo
    runtime.register_tool(AnalyticsQueryTool(db_path=GOLD_DB, seed_demo=False))

    show("1 best value: high quality, low cost",
         "SELECT facility_name, state, star_rating, mspb_score, readmit_hwr "
         "FROM gold_hospital_profile "
         "WHERE star_rating >= 4 AND mspb_score < 1.0 "
         "ORDER BY mspb_score LIMIT 15", runtime)

    show("2 worst psychiatric ED waits",
         "SELECT facility_name, state, ed_psych_median_min, ed_median_min "
         "FROM gold_hospital_profile "
         "WHERE ed_psych_median_min IS NOT NULL "
         "ORDER BY ed_psych_median_min DESC LIMIT 15", runtime)

    show("3 heart-failure readmission leaders",
         "SELECT facility_name, state, readmit_hf, star_rating "
         "FROM gold_hospital_profile "
         "WHERE readmit_hf IS NOT NULL "
         "ORDER BY readmit_hf ASC LIMIT 15", runtime)

    show("4 state quality and cost averages",
         "SELECT state, round(avg(star_rating),2) AS avg_stars, "
         "round(avg(readmit_hwr),1) AS avg_readmit, "
         "round(avg(mspb_score),3) AS avg_cost "
         "FROM gold_hospital_profile GROUP BY state ORDER BY avg_readmit", runtime)


if __name__ == "__main__":
    main()
