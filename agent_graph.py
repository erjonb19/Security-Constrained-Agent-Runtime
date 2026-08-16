"""
agent_graph.py
==============
The agent as a STATEFUL GRAPH (LangGraph), not a single-shot call.

Why this exists: the original planner is one-shot. Question in, SQL out, and if
the guard denies it or the SQL errors, that is the end -- the agent has no way to
recover. Real agentic systems recover: they read the failure, revise, and try
again within bounds.

The graph:

    plan ---> execute ---> route --(success)--> finish
     ^                       |
     |                       |
     +----(retry w/ reason)--+   (bounded; gives up gracefully when exhausted)

Design decisions worth defending:

  SELF-CORRECTION. When execute fails, the FAILURE REASON is fed back into the
  next plan attempt. The agent sees "DENIED by sql_guard: table not on Gold
  allowlist: billing_raw" and writes a different query. This is the core
  capability upgrade over the one-shot planner.

  BOUNDED RETRIES. MAX_ATTEMPTS caps the loop. An unbounded agent loop is a real
  production failure mode: cost and latency runaway, and a model that keeps
  making the same mistake forever. Bounded retry with graceful give-up is the
  correct shape.

  GOVERNANCE IS UNCHANGED. The graph decides WHAT TO TRY NEXT. sql_guard and the
  policy engine still decide WHAT IS ALLOWED TO RUN. LangGraph orchestrates
  around the governance; it does not replace or weaken it. Every attempt --
  including every retry -- goes through the same runtime.

  TRAJECTORY CAPTURE. Every step is recorded in state["trajectory"]: what was
  attempted, what the guard said, how long it took, what it cost. You cannot
  evaluate a path you did not record, and trajectory-level evaluation (did the
  agent take sane steps, not just land on the answer) is what the agentic-AI job
  descriptions ask for.

  ALONGSIDE, NOT REPLACING. nl_to_sql_planner.py is untouched and still works.
  This graph USES it as a component. That means the existing eval harness, API,
  and validator keep running, and you can A/B the two paths against the eval
  suite to MEASURE whether self-correction actually improves accuracy.

Run the demo (needs the planner key + the hospital Gold):
    python agent_graph.py
"""

import os
import sys
from typing import Any, Optional, TypedDict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from langgraph.graph import StateGraph, START, END

from src.runtime.agent_runtime import AgentRuntime
from analytics_query_tool import AnalyticsQueryTool
from nl_to_sql_planner import NLToSQLPlanner, SCHEMA_DOC
import schema_check

GOLD_DB = os.environ.get("HOSPITAL_GOLD_DB", "medallion/hospital_gold.duckdb")
POLICY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "medicare_policy.yaml")
CAPABILITY = "analytics.query_aggregate"

MAX_ATTEMPTS = 3          # bounded retries: cost/latency runaway is a real failure mode


class AgentState(TypedDict, total=False):
    """State carried through the graph. Every node reads and updates this."""
    question: str
    sql: Optional[str]              # the SQL from the latest plan step
    attempts: int                   # how many plan->execute cycles so far
    last_error: Optional[str]       # why the previous attempt failed (fed back into plan)
    allowed: bool
    decided_by: Optional[str]       # "executed" | "guard" | "policy" | "exhausted"
    reason: Optional[str]
    safe_sql: Optional[str]
    row_count: Optional[int]
    columns: Optional[list]
    rows: Optional[list]
    trajectory: list                # every step, in order -- the agent's PATH
    total_latency_ms: int
    total_tokens: int
    total_cost_usd: float


class GovernedAgentGraph:
    """Builds and runs the stateful agent graph over the governed runtime."""

    def __init__(self, db_path: str = GOLD_DB, max_attempts: int = MAX_ATTEMPTS):
        self.max_attempts = max_attempts
        self.runtime = AgentRuntime()
        self.runtime.load_policy(POLICY_PATH)
        tool = AnalyticsQueryTool(db_path=db_path, seed_demo=False)
        self.runtime.register_tool(tool)
        self.planner = NLToSQLPlanner()
        # Fail loudly if PLANNER_SCHEMA does not match the connected database.
        # A mismatch makes every query fail against tables that do not exist --
        # silent, misleading, and it looks like the agent is broken when the
        # configuration is.
        schema_check.verify(SCHEMA_DOC, tool._con,
                            schema_label=os.environ.get("PLANNER_SCHEMA", "hospital"),
                            db_label=db_path)
        self.graph = self._build()

    # ---------------- nodes ----------------

    def _plan(self, state: AgentState) -> dict:
        """Write SQL. On a retry, include WHY the last attempt failed."""
        question = state["question"]
        attempt = state.get("attempts", 0) + 1
        last_error = state.get("last_error")

        prompt = question
        if last_error:
            # self-correction: the agent sees its own failure and revises
            prompt = (
                f"{question}\n\n"
                f"Your previous SQL attempt was REJECTED. Reason:\n{last_error}\n\n"
                f"Write a corrected query that avoids this problem. Use only the "
                f"allowed table and columns from the schema."
            )

        sql, metrics = self.planner.generate_sql_with_metrics(prompt)
        step = {
            "step": "plan",
            "attempt": attempt,
            "sql": sql,
            "retry_context": bool(last_error),
            "latency_ms": metrics.latency_ms,
            "tokens": metrics.total_tokens,
            "est_cost_usd": metrics.est_cost_usd,
        }
        return {
            "sql": sql,
            "attempts": attempt,
            "trajectory": state.get("trajectory", []) + [step],
            "total_latency_ms": state.get("total_latency_ms", 0) + metrics.latency_ms,
            "total_tokens": state.get("total_tokens", 0) + metrics.total_tokens,
            "total_cost_usd": round(state.get("total_cost_usd", 0.0) + metrics.est_cost_usd, 6),
        }

    def _execute(self, state: AgentState) -> dict:
        """Run the SQL through the SAME governed runtime. Guard is unchanged."""
        sql = state.get("sql") or ""
        result = self.runtime.execute_tool(CAPABILITY, {"sql": sql})

        # policy-level denial
        if not getattr(result, "allowed", False):
            reason = getattr(result, "explanation", None) or "not permitted"
            decided_by = "guard" if "guard" in reason.lower() else "policy"
            step = {"step": "execute", "attempt": state.get("attempts"),
                    "outcome": "denied", "decided_by": decided_by, "reason": reason[:200]}
            return {
                "allowed": False, "decided_by": decided_by, "reason": reason,
                "last_error": reason,
                "trajectory": state.get("trajectory", []) + [step],
            }

        tool_result = result.result
        if tool_result is None or not getattr(tool_result, "success", False):
            err = getattr(tool_result, "error", "no tool result") if tool_result else "no tool result"
            decided_by = "guard" if "guard" in (err or "").lower() else "sql_error"
            step = {"step": "execute", "attempt": state.get("attempts"),
                    "outcome": "failed", "decided_by": decided_by, "reason": err[:200]}
            return {
                "allowed": False, "decided_by": decided_by, "reason": err,
                "last_error": err,
                "trajectory": state.get("trajectory", []) + [step],
            }

        out = tool_result.output or {}
        step = {"step": "execute", "attempt": state.get("attempts"),
                "outcome": "success", "row_count": out.get("row_count")}
        return {
            "allowed": True, "decided_by": "executed", "reason": None, "last_error": None,
            "safe_sql": out.get("safe_sql"), "row_count": out.get("row_count"),
            "columns": out.get("columns"), "rows": out.get("rows"),
            "trajectory": state.get("trajectory", []) + [step],
        }

    def _finish(self, state: AgentState) -> dict:
        """Terminal node. If we exhausted retries, say so explicitly."""
        if not state.get("allowed") and state.get("attempts", 0) >= self.max_attempts:
            step = {"step": "finish", "outcome": "exhausted",
                    "attempts": state.get("attempts")}
            return {
                "decided_by": "exhausted",
                "reason": f"gave up after {state.get('attempts')} attempts: {state.get('reason')}",
                "trajectory": state.get("trajectory", []) + [step],
            }
        step = {"step": "finish", "outcome": "success" if state.get("allowed") else "failed"}
        return {"trajectory": state.get("trajectory", []) + [step]}

    # ---------------- routing ----------------

    def _route(self, state: AgentState) -> str:
        """Success -> finish. Failure with retries left -> plan again. Else finish."""
        if state.get("allowed"):
            return "finish"
        if state.get("attempts", 0) < self.max_attempts:
            return "plan"          # self-correct: loop back with last_error in state
        return "finish"            # bounded: give up gracefully

    # ---------------- graph ----------------

    def _build(self):
        g = StateGraph(AgentState)
        g.add_node("plan", self._plan)
        g.add_node("execute", self._execute)
        g.add_node("finish", self._finish)
        g.add_edge(START, "plan")
        g.add_edge("plan", "execute")
        g.add_conditional_edges("execute", self._route, {"plan": "plan", "finish": "finish"})
        g.add_edge("finish", END)
        return g.compile()

    def run(self, question: str) -> AgentState:
        initial: AgentState = {
            "question": question, "attempts": 0, "trajectory": [],
            "total_latency_ms": 0, "total_tokens": 0, "total_cost_usd": 0.0,
        }
        return self.graph.invoke(initial)


# ---------------------------------------------------------------------------
# Demo: a normal question, and one designed to force self-correction.
# ---------------------------------------------------------------------------
def _demo():
    if not os.path.exists(GOLD_DB):
        sys.exit(f"missing {GOLD_DB} -- build the hospital Gold first")

    agent = GovernedAgentGraph()
    questions = [
        # Care-navigation / network steering: where should we route members for
        # a high-volume condition, balancing quality against cost?
        "For heart failure care coordination, which in-network hospitals should we "
        "steer members to, balancing readmission performance against cost?",
        # Behavioral-health access gap: psychiatric boarding in the ED is a real
        # provider-side operational problem and a care-coordination failure mode.
        "Which facilities have the longest psychiatric emergency department boarding "
        "times, where behavioral health patients are waiting for placement?",
        # This one reliably trips the guard. The CORRECT answer to "list every
        # table" is a query against information_schema -- which the guard denies
        # outright (no catalog/system schemas). The agent writes it faithfully
        # because it looks harmless, gets denied, and must self-correct. This
        # demonstrates the retry loop on a real denial rather than a contrived one.
        "List every table available in this database, using the information_schema catalog.",
    ]

    for q in questions:
        print("=" * 72)
        print(f"Q: {q}")
        state = agent.run(q)
        print(f"  attempts: {state.get('attempts')}  decided_by: {state.get('decided_by')}")
        print(f"  tokens: {state.get('total_tokens')}  "
              f"latency: {state.get('total_latency_ms')}ms  "
              f"cost: ${state.get('total_cost_usd')}")
        print("  trajectory:")
        for s in state.get("trajectory", []):
            if s["step"] == "plan":
                tag = " (retry, with failure context)" if s.get("retry_context") else ""
                print(f"    [plan  #{s['attempt']}]{tag} {s['sql'][:70]}...")
            elif s["step"] == "execute":
                print(f"    [exec  #{s['attempt']}] {s['outcome']}"
                      + (f" -> {s.get('decided_by')}: {str(s.get('reason'))[:60]}"
                         if s["outcome"] != "success" else f" -> {s.get('row_count')} rows"))
            else:
                print(f"    [finish] {s.get('outcome')}")
        if state.get("allowed"):
            for row in (state.get("rows") or [])[:3]:
                print(f"      {row}")
        else:
            print(f"  final reason: {str(state.get('reason'))[:160]}")
    print("=" * 72)


if __name__ == "__main__":
    _demo()
