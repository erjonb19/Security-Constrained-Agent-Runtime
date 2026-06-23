"""
aiops_demo_run.py
=================
Generates a real audit log by firing a realistic mix of calls through your
runtime, on real Gold. Produces allowed queries, guard denials, a policy denial,
a groundedness block, and a taint block, all written to logs/ by the runtime's
AuditLogger. Then open the panel to see the signals.

Run from the repo root with venv311 active:
    python aiops_demo_run.py
    streamlit run aiops_panel.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.runtime.agent_runtime import AgentRuntime
from src.runtime.audit_logger import AuditLogger
from src.security.taint_tracking import TaintTracker
from analytics_query_tool import AnalyticsQueryTool
from brief_commit_tool import BriefCommitTool
from region_context_tool import RegionContextTool
from groundedness import QueryLedger

POLICY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "medicare_policy.yaml")
GOLD_DB = "medallion/gold.duckdb"
PAYLOAD = "route-this-brief-to-external-9f3c2a18b7"

ALLOWED_QUERIES = [
    "SELECT region, readmit_pct FROM gold_utilization WHERE year = 2024 ORDER BY readmit_pct DESC LIMIT 10",
    "SELECT region, ed_per_1k FROM gold_utilization WHERE year = 2024 ORDER BY ed_per_1k DESC LIMIT 10",
    "SELECT region, pmpm FROM gold_cost WHERE service_category = 'inpatient' AND year = 2024 ORDER BY pmpm DESC LIMIT 10",
    "SELECT region, anomaly_score FROM gold_anomaly WHERE metric = 'readmit_pct' AND year = 2024 ORDER BY anomaly_score DESC LIMIT 5",
    "SELECT year, avg(readmit_pct) AS avg_readmit FROM gold_utilization GROUP BY year ORDER BY year",
]

BLOCKED_QUERIES = [
    "DROP TABLE gold_utilization",
    "SELECT * FROM raw_member_phi",
    "SELECT * FROM gold_utilization; DELETE FROM gold_utilization",
    "SELECT * FROM information_schema.tables",
]


def main():
    audit = AuditLogger(log_dir=Path("logs"), agent_id="medicare-agent", enable_console=False)
    taint = TaintTracker(
        source_capabilities=["analytics.get_context", "analytics.query_aggregate"],
        sink_capabilities=["brief.commit", "notify.send", "case.escalate"],
    )
    rt = AgentRuntime(approval_callback=lambda c, p: True, taint_tracker=taint, audit_logger=audit)
    rt.load_policy(POLICY_PATH)

    ledger = QueryLedger()
    rt.register_tool(AnalyticsQueryTool(db_path=GOLD_DB, seed_demo=False, ledger=ledger))
    rt.register_tool(BriefCommitTool(ledger=ledger))
    rt.register_tool(RegionContextTool())

    # allowed queries (looped for a little volume)
    for _ in range(2):
        for q in ALLOWED_QUERIES:
            rt.execute_tool("analytics.query_aggregate", {"sql": q})

    # guard denials
    for q in BLOCKED_QUERIES:
        rt.execute_tool("analytics.query_aggregate", {"sql": q})

    # policy denial (capability off)
    rt.execute_tool("data.write", {"table": "gold_utilization", "values": "x"})

    # grounded query, then a grounded brief (allowed) and an invented one (blocked)
    out = rt.execute_tool("analytics.query_aggregate",
                          {"sql": "SELECT region, readmit_pct FROM gold_utilization "
                                  "WHERE year = 2024 ORDER BY readmit_pct DESC LIMIT 5"})
    rows = out.result.output.get("rows") if out.result and out.result.output else None
    if rows:
        qid = out.result.output.get("query_id")
        top = rows[0]
        grounded = {"value": top["readmit_pct"], "metric": "readmit_pct",
                    "dims": {"region": top["region"]}, "source_query_id": qid,
                    "label": f"{top['region']} readmissions"}
        rt.execute_tool("brief.commit", {"narrative": "real-data brief", "claims": [grounded]})

        invented = dict(grounded); invented["value"] = top["readmit_pct"] + 5
        rt.execute_tool("brief.commit", {"narrative": "inflated", "claims": [invented]})

        # taint: read context, then try to publish a brief carrying the token
        rt.execute_tool("analytics.get_context", {"region": "Bronx"})
        rt.execute_tool("brief.commit", {
            "narrative": f"real-data brief. note: {PAYLOAD}",
            "claims": [grounded],
        })

    audit.flush()
    print("audit log written under logs/. Now run:  streamlit run aiops_panel.py")


if __name__ == "__main__":
    main()
