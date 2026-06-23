"""
test_groundedness_wiring.py  (real CMS Gold)
============================================
Groundedness gate through the REAL runtime, on REAL Medicare data.

The grounded claim is built FROM the query's returned rows, so it stays correct
no matter which year/region values are in your Gold. The ungrounded claim is the
same row's number shifted by +5, a figure no query returned.

Run from the repo root with venv311 active:
    python test_groundedness_wiring.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.runtime.agent_runtime import AgentRuntime
from analytics_query_tool import AnalyticsQueryTool
from brief_commit_tool import BriefCommitTool
from groundedness import QueryLedger

POLICY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "medicare_policy.yaml")
GOLD_DB = "medallion/gold.duckdb"


def run(label, capability, params, runtime):
    print(f"\n[{label}] capability={capability}")
    result = runtime.execute_tool(capability, params)
    if not result.allowed:
        tr = result.result
        if tr is not None and tr.error:
            print(f"        -> BLOCKED: {tr.error}")
            if isinstance(tr.output, dict) and tr.output.get("ungrounded"):
                for u in tr.output["ungrounded"]:
                    print(f"             - {u}")
        else:
            print(f"        -> DENIED: {getattr(result, 'explanation', '')}")
        return None
    out = result.result.output or {}
    print("        -> OK")
    for k, v in out.items():
        if k != "rows":
            print(f"             {k}: {v}")
    return out


def main():
    runtime = AgentRuntime(approval_callback=lambda cap, params: True)
    runtime.load_policy(POLICY_PATH)

    ledger = QueryLedger()
    runtime.register_tool(AnalyticsQueryTool(db_path=GOLD_DB, seed_demo=False, ledger=ledger))
    runtime.register_tool(BriefCommitTool(ledger=ledger))

    # 1. query real Gold; grab the highest-readmission state in the latest year
    out = run("1 query real Gold", "analytics.query_aggregate",
              {"sql": "SELECT region, readmit_pct FROM gold_utilization "
                      "WHERE year = (SELECT max(year) FROM gold_utilization) "
                      "ORDER BY readmit_pct DESC LIMIT 10"}, runtime)
    qid = out.get("query_id") if out else None
    rows = out.get("rows") if out else None
    if not rows:
        sys.exit("no rows from Gold; did the medallion build run?")
    top = rows[0]
    print(f"        (top row: {top})")

    # 2. grounded brief, claim built from the real returned row
    run("2 grounded brief", "brief.commit", {
        "narrative": f"{top['region']} had the highest readmission rate at {top['readmit_pct']} percent.",
        "claims": [{"value": top["readmit_pct"], "metric": "readmit_pct",
                    "dims": {"region": top["region"]}, "source_query_id": qid,
                    "label": f"{top['region']} readmissions"}],
    }, runtime)

    # 3. ungrounded brief: same row's number shifted by +5 (never returned)
    run("3 invented number", "brief.commit", {
        "narrative": f"{top['region']} readmissions were {top['readmit_pct'] + 5} percent.",
        "claims": [{"value": top["readmit_pct"] + 5, "metric": "readmit_pct",
                    "dims": {"region": top["region"]}, "source_query_id": qid,
                    "label": f"{top['region']} readmissions (inflated)"}],
    }, runtime)


if __name__ == "__main__":
    main()
