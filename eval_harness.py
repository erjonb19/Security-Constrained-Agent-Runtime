"""
eval_harness.py
===============
The evaluation framework. Runs every case in eval_bank.py through the full
governed agent, multiple times each, and scores the results against trusted
reference SQL. Built to answer the question every AI-engineering role asks:
how do you know the agent is correct, and how consistently?

What it measures:
  - Accuracy: does the agent's answer match the reference exactly (per run)
  - Consistency: across N runs of the same question, how stable is it
    (LLMs are non-deterministic; a question that passes 1/3 is not "passing")
  - Failure modes: WHY a run failed, classified into a taxonomy
  - Per-tier accuracy: where the agent is strong vs. where it breaks down

Output:
  - A console report
  - A timestamped JSON in eval_runs/ for regression tracking over time
  - Exit code 0 only if accuracy meets THRESHOLD (a deployment eval gate)

Run from the repo root with the planner key set:
    python eval_harness.py
    python eval_harness.py --runs 5        # more rigorous
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.runtime.agent_runtime import AgentRuntime
from analytics_query_tool import AnalyticsQueryTool
from nl_to_sql_planner import NLToSQLPlanner
from data_backends import LocalDuckDBBackend, get_backend
from eval_bank import CASES

GOLD_DB = os.environ.get("HOSPITAL_GOLD_DB", "medallion/hospital_gold.duckdb")
POLICY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "medicare_policy.yaml")
CAPABILITY = "analytics.query_aggregate"

DEFAULT_RUNS = 3
THRESHOLD = 0.80          # eval gate: overall accuracy must meet this
OUT_DIR = "eval_runs"

# failure taxonomy
F_CORRECT = "correct"
F_WRONG_ANSWER = "wrong_answer"       # ran fine, result disagrees with reference
F_MISSING_KEY = "missing_key_column"  # agent didn't return the column asked for
F_GUARD_DENIED = "guard_denied"       # guard rejected the SQL
F_SQL_ERROR = "sql_error"             # SQL ran but errored (bad column, etc.)
F_MODEL_ERROR = "model_error"         # planner/model call failed


def _scalar(rows):
    """Pull the answer value from a scalar result.

    A strict scalar query returns one column. But the agent often returns a row
    like (facility_name, measure) for a 'what is the highest X' question -- the
    ANSWER is the measure, which lands LAST, not first. So: if the single row has
    multiple columns, prefer the last numeric column; fall back to the last
    column; only use the first when there is just one.
    """
    if not rows:
        return None
    row = rows[0]
    vals = list(row.values())
    if not vals:
        return None
    if len(vals) == 1:
        return vals[0]
    # multiple columns: the measure is the answer. Prefer the last numeric value.
    for v in reversed(vals):
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return v
    return vals[-1]


def _keys(rows, key_columns):
    out = []
    for r in rows:
        if not all(k in r for k in key_columns):
            return None
        out.append(tuple(r[k] for k in key_columns))
    return out


def score_one(case, agent_rows) -> tuple[str, str]:
    """Return (failure_mode, detail). F_CORRECT means it matched."""
    # reference is computed once by the caller and passed via case['_ref_rows']
    ref_rows = case["_ref_rows"]
    if case["mode"] == "scalar":
        a, b = _scalar(agent_rows), _scalar(ref_rows)
        try:
            ok = (a == b) or (a is not None and b is not None and float(a) == float(b))
        except (TypeError, ValueError):
            ok = (a == b)
        return (F_CORRECT, f"{a}") if ok else (F_WRONG_ANSWER, f"agent={a} ref={b}")
    kc = case["key_columns"]
    a = _keys(agent_rows, kc)
    b = _keys(ref_rows, kc)
    if a is None:
        cols = list(agent_rows[0].keys()) if agent_rows else []
        return F_MISSING_KEY, f"missing {kc}; got {cols}"
    if a == b:
        return F_CORRECT, f"{len(a)} rows"
    return F_WRONG_ANSWER, f"agent={a[:3]}... ref={b[:3]}..."


def run_once(case, runtime, planner) -> tuple[str, str]:
    """One agent attempt at one case. Returns (failure_mode, detail)."""
    try:
        sql = planner.generate_sql(case["question"])
    except Exception as e:
        return F_MODEL_ERROR, str(e)[:120]
    result = runtime.execute_tool(CAPABILITY, {"sql": sql})
    if not getattr(result, "allowed", False):
        reason = getattr(result, "explanation", "") or ""
        mode = F_GUARD_DENIED if ("guard" in reason.lower() or "sql_guard" in reason) else F_GUARD_DENIED
        return mode, reason[:120]
    tr = result.result
    if tr is None:
        return F_SQL_ERROR, "no tool result"
    if not tr.success:
        err = (tr.error or "")[:120]
        mode = F_GUARD_DENIED if "guard" in err.lower() else F_SQL_ERROR
        return mode, err
    return score_one(case, (tr.output or {}).get("rows", []))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    args = ap.parse_args()
    runs = args.runs

    if not os.path.exists(GOLD_DB):
        sys.exit(f"missing {GOLD_DB} -- build the hospital Gold first")

    runtime = AgentRuntime()
    runtime.load_policy(POLICY_PATH)
    runtime.register_tool(AnalyticsQueryTool(db_path=GOLD_DB, seed_demo=False))
    planner = NLToSQLPlanner()
    ref_backend = LocalDuckDBBackend(GOLD_DB)

    # precompute reference answers once
    for case in CASES:
        _, case["_ref_rows"] = ref_backend.execute(case["reference_sql"])

    backend_kind = get_backend(GOLD_DB).kind
    print(f"eval: {len(CASES)} cases x {runs} runs | backend={backend_kind} | "
          f"planner={planner.provider} ({planner._model})\n")

    case_results = []
    tier_totals = defaultdict(lambda: [0, 0])   # tier -> [correct_runs, total_runs]
    failure_counts = defaultdict(int)
    t_start = time.time()

    for case in CASES:
        outcomes = []
        details = []
        for _ in range(runs):
            mode, detail = run_once(case, runtime, planner)
            outcomes.append(mode)
            details.append(detail)
            failure_counts[mode] += 1
            tier_totals[case["tier"]][1] += 1
            if mode == F_CORRECT:
                tier_totals[case["tier"]][0] += 1
        correct = sum(1 for o in outcomes if o == F_CORRECT)
        stability = correct / runs
        # a case "passes" only if it is correct on the majority of runs
        passed = correct > runs / 2
        case_results.append({
            "id": case["id"], "tier": case["tier"], "question": case["question"],
            "correct_runs": correct, "runs": runs, "stability": round(stability, 2),
            "passed": passed, "outcomes": outcomes, "sample_detail": details[0],
        })
        flag = "PASS" if passed else "FAIL"
        bar = "".join("O" if o == F_CORRECT else "x" for o in outcomes)
        print(f"[{flag}] t{case['tier']} {case['id']:26} {bar}  ({correct}/{runs})  {details[0][:50]}")

    elapsed = time.time() - t_start
    n_pass = sum(1 for c in case_results if c["passed"])
    total_runs = len(CASES) * runs
    correct_runs = sum(c["correct_runs"] for c in case_results)
    run_accuracy = correct_runs / total_runs
    case_pass_rate = n_pass / len(CASES)

    print("\n" + "=" * 60)
    print(f"cases passed (majority-correct): {n_pass}/{len(CASES)}  ({case_pass_rate:.0%})")
    print(f"run-level accuracy:              {correct_runs}/{total_runs}  ({run_accuracy:.0%})")
    print("per tier (run-level):")
    for tier in sorted(tier_totals):
        c, t = tier_totals[tier]
        print(f"  tier {tier}: {c}/{t}  ({c/t:.0%})")
    print("failure modes:")
    for mode, n in sorted(failure_counts.items(), key=lambda x: -x[1]):
        if mode != F_CORRECT:
            print(f"  {mode}: {n}")
    print(f"elapsed: {elapsed:.0f}s")

    # write timestamped report for regression tracking
    os.makedirs(OUT_DIR, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report = {
        "timestamp": stamp,
        "backend": backend_kind,
        "model": planner._model,
        "runs_per_case": runs,
        "case_pass_rate": round(case_pass_rate, 4),
        "run_accuracy": round(run_accuracy, 4),
        "tier_accuracy": {str(t): round(v[0]/v[1], 4) for t, v in sorted(tier_totals.items())},
        "failure_counts": dict(failure_counts),
        "cases": case_results,
    }
    path = os.path.join(OUT_DIR, f"eval_{stamp}.json")
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nreport -> {path}")

    # eval gate
    gate = "PASS" if run_accuracy >= THRESHOLD else "FAIL"
    print(f"eval gate (>= {THRESHOLD:.0%}): {gate}")
    sys.exit(0 if run_accuracy >= THRESHOLD else 1)


if __name__ == "__main__":
    main()
