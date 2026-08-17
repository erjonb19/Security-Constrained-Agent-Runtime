"""
app.py  --  Security-Constrained Agent Runtime, HTTP service layer
==================================================================
Turns the governed runtime into a callable service. A question (or raw SQL)
comes in over HTTP; a governed answer plus the full decision trail goes out.

The governance is part of the API contract, not an internal detail: every
response says whether the request was allowed, which layer decided, the reason,
and the exact safe SQL that ran. That is the product -- a boundary a buyer can
put an LLM behind without it touching anything its guardrails forbid.

Endpoints:
  GET  /health      service + dependency status
  GET  /schema      the Gold schema the agent may query
  POST /query       { "question": "..." }  natural language -> governed answer
  POST /raw-sql     { "sql": "SELECT ..." } guarded SQL execution

Run locally:
    pip install fastapi "uvicorn[standard]"
    uvicorn app:app --reload --port 8000
Then open http://localhost:8000/docs for the interactive API.
"""

from __future__ import annotations

import os
import sys
import hmac
import threading
from contextlib import asynccontextmanager
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.runtime.agent_runtime import AgentRuntime
from analytics_query_tool import AnalyticsQueryTool
from nl_to_sql_planner import NLToSQLPlanner, SCHEMA_DOC
import cost_tracker
from approval import (ApprovalStore, APPROVE, REJECT, ESCALATE,
                      APPROVE_WITH_EDITS, DECISIONS)

GOLD_DB = os.environ.get("HOSPITAL_GOLD_DB", "medallion/hospital_gold.duckdb")
POLICY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "medicare_policy.yaml")
CAPABILITY = "analytics.query_aggregate"

# --- API key auth -----------------------------------------------------------
# Set API_KEY in the environment to require a key on the data endpoints.
# If unset, the service runs in OPEN dev mode (flagged loudly in /health and at
# startup). Never deploy publicly without API_KEY set.
API_KEY = os.environ.get("API_KEY")
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(provided: Optional[str] = Security(_api_key_header)) -> None:
    if not API_KEY:
        return  # dev mode: no key configured, allow (see /health auth_enabled)
    if provided is None or not hmac.compare_digest(provided, API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing API key (send header X-API-Key)",
        )

# Built once at startup, shared across requests. DuckDB connections are not
# thread-safe, and FastAPI runs sync endpoints in a threadpool, so we serialize
# tool execution with a lock. Correct and sufficient for a single-instance
# free-tier deploy; horizontal scaling is a later concern.
_STATE: dict[str, Any] = {"runtime": None, "planner": None, "planner_error": None}
_LOCK = threading.Lock()


@asynccontextmanager
async def lifespan(app: FastAPI):
    runtime = AgentRuntime()
    runtime.load_policy(POLICY_PATH)
    runtime.register_tool(AnalyticsQueryTool(db_path=GOLD_DB, seed_demo=False))
    _STATE["runtime"] = runtime
    if not API_KEY:
        print("WARNING: API_KEY not set -- data endpoints are OPEN (dev mode). "
              "Set API_KEY before exposing this service publicly.")
    # planner is optional: /raw-sql works without an LLM key, /query needs one
    try:
        _STATE["planner"] = NLToSQLPlanner()
    except BaseException as e:  # SystemExit if no API key
        _STATE["planner"] = None
        _STATE["planner_error"] = str(e)
    # Approval agent is optional: /query and /raw-sql work without it. It needs
    # the planner (to draft) and the checkpointer (to persist the pause).
    try:
        from approval_graph import GovernedApprovalAgent
        _STATE["approval_agent"] = GovernedApprovalAgent(
            db_path=GOLD_DB, runtime=runtime, planner=_STATE.get("planner"))
        _STATE["approval_store"] = _STATE["approval_agent"].store
    except BaseException as e:
        _STATE["approval_agent"] = None
        _STATE["approval_store"] = ApprovalStore()   # queue is still readable
        _STATE["approval_error"] = str(e)
    yield
    _STATE.clear()


app = FastAPI(
    title="Security-Constrained Agent Runtime",
    description="Governed natural-language analytics over CMS Medicare data.",
    version="1.0.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Request / response models -- the contract.
# ---------------------------------------------------------------------------
class QueryRequest(BaseModel):
    question: str = Field(..., examples=["Which hospitals give the best value, high quality and low cost?"])


class SqlRequest(BaseModel):
    sql: str = Field(..., examples=["SELECT facility_name, star_rating FROM gold_hospital_profile WHERE star_rating = 5 LIMIT 10"])


class ProposeRequest(BaseModel):
    question: str = Field(..., examples=["Which hospitals have the worst heart failure readmission rates?"])
    capability: str = Field("brief.commit", examples=["brief.commit"])


class DecisionRequest(BaseModel):
    """A reviewer's verdict on a pending proposal."""
    decision: str = Field(..., examples=["approve"],
                          description="approve | reject | escalate | approve_with_edits")
    decided_by: str = Field(..., examples=["e.brucaj"])
    reason: Optional[str] = None
    edited_proposal: Optional[str] = Field(
        None, description="required when decision is approve_with_edits")
    escalated_to: Optional[str] = Field(
        None, description="required when decision is escalate")


class GovernedResponse(BaseModel):
    allowed: bool
    decided_by: str                      # "policy" | "guard" | "executed"
    reason: Optional[str] = None
    sql: Optional[str] = None            # the SQL that was evaluated
    safe_sql: Optional[str] = None       # what the guard actually ran
    row_count: Optional[int] = None
    columns: Optional[list] = None
    rows: Optional[list] = None
    planner_metrics: Optional[dict] = None   # per-call latency, tokens, est cost


# ---------------------------------------------------------------------------
# Core: run SQL through the governed runtime and map the result to the contract.
# Pure-ish mapping factored out so it is unit-testable without the runtime.
# ---------------------------------------------------------------------------
def interpret_result(result: Any, sql: str) -> dict:
    # policy/guard denial both surface as allowed=False (single denial channel);
    # distinguish by whether the guard named itself in the explanation.
    if not getattr(result, "allowed", False):
        reason = getattr(result, "explanation", None)
        if not reason and getattr(result, "decision", None) is not None:
            reason = getattr(result.decision, "reason", None)
        reason = reason or "not permitted"
        decided_by = "guard" if "sql_guard" in reason or "guard" in reason.lower() else "policy"
        return {"allowed": False, "decided_by": decided_by, "reason": reason, "sql": sql}

    tr = getattr(result, "result", None)
    if tr is None:
        return {"allowed": True, "decided_by": "policy", "reason": "allowed, no tool result", "sql": sql}
    if not getattr(tr, "success", False):
        return {"allowed": False, "decided_by": "guard", "reason": getattr(tr, "error", "denied by guard"), "sql": sql}

    out = tr.output or {}
    return {
        "allowed": True,
        "decided_by": "executed",
        "reason": None,
        "sql": sql,
        "safe_sql": out.get("safe_sql"),
        "row_count": out.get("row_count"),
        "columns": out.get("columns"),
        "rows": out.get("rows"),
    }


def run_governed_sql(sql: str) -> dict:
    runtime = _STATE["runtime"]
    with _LOCK:
        result = runtime.execute_tool(CAPABILITY, {"sql": sql})
    return interpret_result(result, sql)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "gold_db": GOLD_DB,
        "gold_db_present": os.path.exists(GOLD_DB),
        "runtime_ready": _STATE.get("runtime") is not None,
        "planner_enabled": _STATE.get("planner") is not None,
        "planner_error": _STATE.get("planner_error"),
        "auth_enabled": bool(API_KEY),
        "approvals_enabled": _STATE.get("approval_agent") is not None,
        "approval_error": _STATE.get("approval_error"),
    }


@app.get("/schema")
def schema() -> dict:
    return {"capability": CAPABILITY, "schema": SCHEMA_DOC}


@app.post("/raw-sql", response_model=GovernedResponse, dependencies=[Depends(require_api_key)])
def raw_sql(req: SqlRequest) -> dict:
    return run_governed_sql(req.sql)


@app.post("/query", response_model=GovernedResponse, dependencies=[Depends(require_api_key)])
def query(req: QueryRequest) -> dict:
    planner = _STATE.get("planner")
    if planner is None:
        return {
            "allowed": False,
            "decided_by": "policy",
            "reason": f"planner not configured: {_STATE.get('planner_error')}",
        }
    try:
        sql, metrics = planner.generate_sql_with_metrics(req.question)
    except Exception as e:
        return {"allowed": False, "decided_by": "policy", "reason": f"planner error: {e}"}
    out = run_governed_sql(sql)
    out["planner_metrics"] = metrics.as_dict()
    cost_tracker.record(metrics.as_dict(), question=req.question)
    return out


@app.get("/metrics")
def metrics() -> dict:
    """Aggregate cost and latency across all planner calls (optimization view)."""
    return cost_tracker.summarize()


# ---------------------------------------------------------------------------
# Human-in-the-loop approval.
#
# /propose runs the agent to the checkpoint and RETURNS IMMEDIATELY with a
# pending id -- the graph state is persisted, not held open on this request.
# A reviewer later GETs the queue and POSTs a decision, which RESUMES the graph
# from exactly where it stopped. That is what makes this an approval QUEUE
# rather than a blocking call.
# ---------------------------------------------------------------------------

@app.post("/propose", dependencies=[Depends(require_api_key)])
def propose(req: ProposeRequest) -> dict:
    """Run the agent until it drafts a consequential action, then pause."""
    agent = _STATE.get("approval_agent")
    if agent is None:
        raise HTTPException(status_code=503,
                            detail=f"approvals unavailable: {_STATE.get('approval_error')}")
    with _LOCK:
        return agent.start(req.question)


@app.get("/approvals", dependencies=[Depends(require_api_key)])
def list_approvals() -> dict:
    """The review queue: everything awaiting a human decision."""
    store = _STATE.get("approval_store") or ApprovalStore()
    return {"pending": store.pending(), "metrics": store.metrics()}


@app.get("/approvals/{approval_id}", dependencies=[Depends(require_api_key)])
def get_approval(approval_id: str) -> dict:
    store = _STATE.get("approval_store") or ApprovalStore()
    item = store.get(approval_id)
    if item is None:
        raise HTTPException(status_code=404, detail=f"no approval {approval_id}")
    return item


@app.post("/approvals/{approval_id}", dependencies=[Depends(require_api_key)])
def decide_approval(approval_id: str, req: DecisionRequest) -> dict:
    """Submit a decision and RESUME the paused graph.

    approve / approve_with_edits -> the action executes
    reject / escalate            -> it does not
    """
    agent = _STATE.get("approval_agent")
    store = _STATE.get("approval_store") or ApprovalStore()
    if req.decision not in DECISIONS:
        raise HTTPException(status_code=400,
                            detail=f"decision must be one of {sorted(DECISIONS)}")
    item = store.get(approval_id)
    if item is None:
        raise HTTPException(status_code=404, detail=f"no approval {approval_id}")
    if item["status"] != "pending":
        raise HTTPException(status_code=409,
                            detail=f"approval {approval_id} already {item['status']}")
    if agent is None:
        raise HTTPException(status_code=503,
                            detail=f"approvals unavailable: {_STATE.get('approval_error')}")
    try:
        with _LOCK:
            return agent.resume(
                thread_id=item["thread_id"], decision=req.decision,
                decided_by=req.decided_by, reason=req.reason,
                edited_proposal=req.edited_proposal, escalated_to=req.escalated_to)
    except (ValueError, KeyError) as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/")
def root() -> dict:
    return {
        "service": "Security-Constrained Agent Runtime",
        "docs": "/docs",
        "endpoints": ["/health", "/schema", "/query", "/raw-sql", "/metrics",
                      "/propose", "/approvals", "/approvals/{id}"],
    }
