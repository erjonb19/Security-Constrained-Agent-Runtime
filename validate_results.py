"""
validate_results.py
===================
Ground-truth validation. Runs each question TWO ways:

  reference : a hand-written SQL query we trust, executed directly on the Gold.
  agent     : the full governed pipeline -- planner writes SQL, guard validates,
              backend executes.

Then compares the answers EXACTLY. This proves the agent returns correct
results, not just plausible ones, and doubles as a regression test: run it again
after switching DATA_BACKEND=databricks to prove the cloud path returns the
identical answers to the local path.

Each case declares how to compare, so cosmetic differences (extra display
columns, column naming) don't cause false mismatches, but the actual answer must
match exactly:

  mode 'scalar' : result is a single value (a count, an average). Compare it.
  mode 'keyed'  : result is an ordered list. Compare the key column(s), in order.

Run from the repo root with venv311 active (needs the planner key set):
    python validate_results.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.runtime.agent_runtime import AgentRuntime
from analytics_query_tool import AnalyticsQueryTool
from nl_to_sql_planner import NLToSQLPlanner
from data_backends import LocalDuckDBBackend, get_backend

GOLD_DB = os.environ.get("HOSPITAL_GOLD_DB", "medallion/hospital_gold.duckdb")
POLICY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "medicare_policy.yaml")
CAPABILITY = "analytics.query_aggregate"


# Each case: a precise question (one correct answer), the trusted reference SQL,
# and how to compare. Questions are phrased to be deterministic so agent and
# reference must agree.
CASES = [
    {
        "label": "count of 5-star hospitals",
        "question": "How many hospitals in the data have an overall star rating of exactly 5?",
        "reference_sql": "SELECT count(*) AS n FROM gold_hospital_profile WHERE star_rating = 5",
        "mode": "scalar",
    },
    {
        "label": "average MSPB in Pennsylvania",
        "question": "What is the average Medicare spending per beneficiary score for hospitals in Pennsylvania (PA)? Round to 4 decimals.",
        "reference_sql": "SELECT round(avg(mspb_score), 4) AS v FROM gold_hospital_profile WHERE state = 'PA' AND mspb_score IS NOT NULL",
        "mode": "scalar",
    },
    {
        "label": "count with HF readmission data",
        "question": "How many hospitals have a non-null heart failure readmission rate?",
        "reference_sql": "SELECT count(*) AS n FROM gold_hospital_profile WHERE readmit_hf IS NOT NULL",
        "mode": "scalar",
    },
    {
        "label": "top 10 lowest HF readmission, by facility_id order",
        "question": "List the facility_id and facility_name of the 10 hospitals with the lowest heart failure readmission rate, lowest first. Include facility_id.",
        "reference_sql": ("SELECT facility_id FROM gold_hospital_profile "
                          "WHERE readmit_hf IS NOT NULL ORDER BY readmit_hf ASC, facility_id ASC LIMIT 10"),
        "mode": "keyed",
        "key_columns": ["facility_id"],
    },
    {
        "label": "single worst psychiatric ED wait",
        "question": "Which single hospital has the highest psychiatric ED median wait time? Give its facility_id.",
        "reference_sql": ("SELECT facility_id FROM gold_hospital_profile "
                          "WHERE ed_psych_median_min IS NOT NULL ORDER BY ed_psych_median_min DESC, facility_id ASC LIMIT 1"),
        "mode": "keyed",
        "key_columns": ["facility_id"],
    },
]


def _scalar(rows: list[dict]):
    """Pull the single value out of a 1x1 result, tolerant of column naming."""
    if not rows:
        return None
    first = rows[0]
    vals = list(first.values())
    return vals[0] if vals else None


def _keys(rows: list[dict], key_columns: list[str]):
    """Ordered list of key tuples; None if a key column is absent."""
    out = []
    for r in rows:
        if not all(k in r for k in key_columns):
            return None
        out.append(tuple(r[k] for k in key_columns))
    return out


def compare(case: dict, agent_rows: list[dict], ref_rows: list[dict]) -> tuple[bool, str]:
    if case["mode"] == "scalar":
        a, b = _scalar(agent_rows), _scalar(ref_rows)
        # exact compare; allow int/float equality (5 == 5.0)
        ok = (a == b) or (a is not None and b is not None and float(a) == float(b))
        return ok, f"agent={a!r} reference={b!r}"
    # keyed
    kc = case["key_columns"]
    a, b = _keys(agent_rows, kc), _keys(ref_rows, kc)
    if a is None:
        return False, f"agent result missing key column(s) {kc}; got columns {list(agent_rows[0].keys()) if agent_rows else []}"
    if a == b:
        return True, f"{len(a)} rows match exactly on {kc}"
    # find first divergence
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return False, f"row {i}: agent={x} reference={y}"
    return False, f"length differs: agent={len(a)} reference={len(b)}"


def run_agent(question: str, runtime: AgentRuntime, planner: NLToSQLPlanner):
    sql = planner.generate_sql(question)
    result = runtime.execute_tool(CAPABILITY, {"sql": sql})
    if not getattr(result, "allowed", False):
        return None, sql, getattr(result, "explanation", "denied")
    tr = result.result
    if tr is None or not tr.success:
        return None, sql, getattr(tr, "error", "no result")
    return (tr.output or {}).get("rows", []), sql, None


def main():
    if not os.path.exists(GOLD_DB):
        sys.exit(f"missing {GOLD_DB} -- build the hospital Gold first")

    runtime = AgentRuntime()
    runtime.load_policy(POLICY_PATH)
    runtime.register_tool(AnalyticsQueryTool(db_path=GOLD_DB, seed_demo=False))
    planner = NLToSQLPlanner()

    # trusted reference path: straight to the Gold, no planner, no guard
    ref_backend = LocalDuckDBBackend(GOLD_DB)

    print(f"backend under test: {get_backend(GOLD_DB).kind}")
    print(f"planner: {planner.provider} ({planner._model})\n")

    passed = 0
    for case in CASES:
        print("=" * 70)
        print(f"[{case['label']}]")
        _, ref_rows = ref_backend.execute(case["reference_sql"])
        agent_rows, agent_sql, err = run_agent(case["question"], runtime, planner)
        if err:
            print(f"  AGENT ERROR: {err}")
            print(f"  agent sql: {agent_sql}")
            continue
        ok, detail = compare(case, agent_rows, ref_rows)
        print(f"  {'PASS' if ok else 'FAIL'}: {detail}")
        if not ok:
            print(f"  agent sql: {agent_sql}")
            print(f"  reference: {case['reference_sql']}")
        passed += 1 if ok else 0

    print("=" * 70)
    print(f"\n{passed}/{len(CASES)} cases match the reference exactly")
    sys.exit(0 if passed == len(CASES) else 1)


if __name__ == "__main__":
    main()
