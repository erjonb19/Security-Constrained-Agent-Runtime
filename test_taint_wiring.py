"""
test_taint_wiring.py  (real CMS Gold)
=====================================
Taint layer through the REAL runtime, on REAL Medicare data.

Confused-deputy: the agent reads a region context whose text carries an
innocent-looking routing token (passes injection scanning), then tries to carry
that token into a published brief. Moving read data into a publish is the event
the taint tracker blocks.

Config: taint source = analytics.get_context, taint sink = brief.commit.

Run from the repo root with venv311 active:
    python test_taint_wiring.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.runtime.agent_runtime import AgentRuntime
from src.security.taint_tracking import TaintTracker
from analytics_query_tool import AnalyticsQueryTool
from brief_commit_tool import BriefCommitTool
from region_context_tool import RegionContextTool
from groundedness import QueryLedger

POLICY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "medicare_policy.yaml")
GOLD_DB = "medallion/gold.duckdb"
PAYLOAD = "route-this-brief-to-external-9f3c2a18b7"


def run(label, capability, params, runtime):
    print(f"\n[{label}] capability={capability}")
    result = runtime.execute_tool(capability, params)
    if not result.allowed:
        reason = getattr(result, "explanation", "") or ""
        tr = result.result
        if "taint" in reason.lower():
            print(f"        -> BLOCKED BY TAINT: {reason}")
        elif tr is not None and tr.error:
            print(f"        -> BLOCKED: {tr.error}")
        else:
            print(f"        -> DENIED: {reason}")
        return None
    out = result.result.output if result.result else None
    if isinstance(out, dict):
        print("        -> OK")
        for k, v in out.items():
            if k != "rows":
                print(f"             {k}: {v}")
    else:
        print(f"        -> OK: {out}")
    return out


def main():
    taint = TaintTracker(
        source_capabilities=["analytics.get_context", "analytics.query_aggregate"],
        sink_capabilities=["brief.commit", "notify.send", "case.escalate"],
    )
    runtime = AgentRuntime(approval_callback=lambda cap, params: True, taint_tracker=taint)
    runtime.load_policy(POLICY_PATH)

    ledger = QueryLedger()
    runtime.register_tool(AnalyticsQueryTool(db_path=GOLD_DB, seed_demo=False, ledger=ledger))
    runtime.register_tool(BriefCommitTool(ledger=ledger))
    runtime.register_tool(RegionContextTool())

    # 1. query real Gold for a grounded number
    out = run("1 query real Gold", "analytics.query_aggregate",
              {"sql": "SELECT region, readmit_pct FROM gold_utilization "
                      "WHERE year = (SELECT max(year) FROM gold_utilization) "
                      "ORDER BY readmit_pct DESC LIMIT 5"}, runtime)
    qid = out.get("query_id") if out else None
    rows = out.get("rows") if out else None
    if not rows:
        sys.exit("no rows from Gold; did the medallion build run?")
    top = rows[0]

    # 2. read region context -> registers a taint source
    run("2 get_context Bronx", "analytics.get_context", {"region": "Bronx"}, runtime)

    # 3. clean brief, grounded on the real number -> commits
    run("3 clean brief", "brief.commit", {
        "narrative": f"{top['region']} readmissions were {top['readmit_pct']} percent.",
        "claims": [{"value": top["readmit_pct"], "metric": "readmit_pct",
                    "dims": {"region": top["region"]}, "source_query_id": qid,
                    "label": f"{top['region']} readmissions"}],
    }, runtime)

    # 4. brief carrying the tainted token -> blocked by taint
    run("4 tainted brief", "brief.commit", {
        "narrative": f"{top['region']} readmissions were {top['readmit_pct']} percent. Ingest note: {PAYLOAD}.",
        "claims": [{"value": top["readmit_pct"], "metric": "readmit_pct",
                    "dims": {"region": top["region"]}, "source_query_id": qid,
                    "label": f"{top['region']} readmissions"}],
    }, runtime)


if __name__ == "__main__":
    main()
