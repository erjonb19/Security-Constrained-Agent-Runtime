"""
approval.py
===========
Human-in-the-loop approval for consequential agent actions.

WHY THIS EXISTS
Reads are safe, so the agent runs them autonomously. But some actions are
consequential -- committing a clinical brief to a record, escalating a case to a
care manager, sending a notification. Those must not be autonomous. The policy
engine already marks them as requiring approval (medicare_policy.yaml); this is
the surface that makes that real.

THE ARCHITECTURAL POINT
An approval is NOT a blocking function call. In any real deployment a reviewer
picks the item up minutes or days later, not while an HTTP request holds a thread
open. So the agent's execution state must OUTLIVE the request that created it.

That is what LangGraph's interrupt + checkpointer give us:
  1. the graph runs until it reaches the approval node
  2. interrupt() stops execution and PERSISTS the full state, keyed by thread_id
  3. the HTTP request returns immediately: "pending, id=X"
  4. hours later, a decision is submitted against that id
  5. the graph RESUMES from exactly where it stopped, with the decision injected

Persistence is SQLite here: durable, file-based, no server. Same tradeoff as
DuckDB vs. Databricks -- right-sized now, swappable for Postgres later by
changing the checkpointer.

DECISION TYPES (what real approval systems support)
  approve              execute as proposed
  reject               do not execute; reason recorded
  escalate             route to a higher authority (clinician, compliance)
  approve_with_edits   reviewer modifies the proposal, THEN it executes
                       -- very common clinically: the agent drafts, the human
                          corrects a detail, then it goes

Deliberately NOT included: timeout auto-reject. An automatic decision on a
consequential clinical action is a poor default; better that an item sits
visible in the queue than is silently rejected.

Every decision records who, when, why, and how long it sat in the queue.
Queue latency is a real operations metric, not decoration.
"""

from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, TypedDict

APPROVALS_DB = os.environ.get("APPROVALS_DB", "logs/approvals.sqlite")

# decision vocabulary
APPROVE = "approve"
REJECT = "reject"
ESCALATE = "escalate"
APPROVE_WITH_EDITS = "approve_with_edits"
DECISIONS = {APPROVE, REJECT, ESCALATE, APPROVE_WITH_EDITS}

# Which decisions let the action execute. The other two do not.
#
# NOTE on escalate: the intent was "reassign, don't resolve", but `decide()` sets
# status='escalated', which drops the row out of `pending()`. So today escalation
# CLOSES the item -- the person named in escalated_to has no queue of their own,
# and the paused graph thread is never resumed. Re-queueing escalated items with
# an owner is the follow-up; until then the UI says so plainly rather than
# repeating the intent as if it were the behaviour.
EXECUTES = {APPROVE, APPROVE_WITH_EDITS}


class ApprovalStore:
    """Durable record of every proposal and every decision.

    Separate from the graph checkpointer on purpose. The checkpointer holds
    EXECUTION state (how to resume); this holds the AUDIT record (what was
    proposed, who decided, why, how long it waited). Different lifetimes,
    different consumers -- the audit record outlives the execution.
    """

    def __init__(self, path: str = APPROVALS_DB):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.path = path
        self._init()

    def _conn(self):
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        return con

    def _init(self) -> None:
        with self._conn() as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id   TEXT PRIMARY KEY,
                    thread_id     TEXT NOT NULL,
                    capability    TEXT NOT NULL,
                    question      TEXT,
                    proposal      TEXT,
                    evidence      TEXT,
                    status        TEXT NOT NULL,     -- pending | approved | rejected | escalated
                    proposed_at   TEXT NOT NULL,
                    decided_at    TEXT,
                    decided_by    TEXT,
                    decision      TEXT,
                    reason        TEXT,
                    edited_proposal TEXT,
                    escalated_to  TEXT,
                    queue_seconds REAL
                )
            """)

    # ---- proposing ----

    def propose(self, thread_id: str, capability: str, question: str,
                proposal: str, evidence: str | None = None) -> str:
        approval_id = str(uuid.uuid4())[:8]
        with self._conn() as con:
            con.execute(
                "INSERT INTO approvals (approval_id, thread_id, capability, question, "
                "proposal, evidence, status, proposed_at) VALUES (?,?,?,?,?,?,?,?)",
                (approval_id, thread_id, capability, question, proposal, evidence,
                 "pending", datetime.now(timezone.utc).isoformat()),
            )
        return approval_id

    # ---- reviewing ----

    def pending(self) -> list[dict]:
        with self._conn() as con:
            rows = con.execute(
                "SELECT * FROM approvals WHERE status = 'pending' ORDER BY proposed_at"
            ).fetchall()
        return [dict(r) for r in rows]

    def get(self, approval_id: str) -> Optional[dict]:
        with self._conn() as con:
            row = con.execute(
                "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
        return dict(row) if row else None

    def find_by_thread(self, thread_id: str, status: str | None = None) -> Optional[str]:
        """Most recent approval_id for a thread, optionally filtered by status.

        Used to keep the propose node IDEMPOTENT: LangGraph re-executes a node on
        resume, and without this the store would mint a duplicate approval record
        for the same thread every time a decision came in.
        """
        q = "SELECT approval_id FROM approvals WHERE thread_id = ?"
        args: list = [thread_id]
        if status:
            q += " AND status = ?"
            args.append(status)
        q += " ORDER BY proposed_at DESC LIMIT 1"
        with self._conn() as con:
            row = con.execute(q, args).fetchone()
        return row["approval_id"] if row else None

    def decide(self, approval_id: str, decision: str, decided_by: str,
               reason: str | None = None, edited_proposal: str | None = None,
               escalated_to: str | None = None) -> dict:
        if decision not in DECISIONS:
            raise ValueError(f"unknown decision {decision!r}; expected one of {sorted(DECISIONS)}")
        item = self.get(approval_id)
        if item is None:
            raise KeyError(f"no approval {approval_id!r}")
        if item["status"] != "pending":
            raise ValueError(f"approval {approval_id} already {item['status']}")
        if decision == APPROVE_WITH_EDITS and not edited_proposal:
            raise ValueError("approve_with_edits requires edited_proposal")
        if decision == ESCALATE and not escalated_to:
            raise ValueError("escalate requires escalated_to")

        now = datetime.now(timezone.utc)
        proposed = datetime.fromisoformat(item["proposed_at"])
        queue_seconds = (now - proposed).total_seconds()
        status = {APPROVE: "approved", APPROVE_WITH_EDITS: "approved",
                  REJECT: "rejected", ESCALATE: "escalated"}[decision]

        with self._conn() as con:
            con.execute(
                "UPDATE approvals SET status=?, decided_at=?, decided_by=?, decision=?, "
                "reason=?, edited_proposal=?, escalated_to=?, queue_seconds=? "
                "WHERE approval_id=?",
                (status, now.isoformat(), decided_by, decision, reason,
                 edited_proposal, escalated_to, queue_seconds, approval_id),
            )
        return self.get(approval_id)

    # ---- ops metrics ----

    def metrics(self) -> dict:
        """Approval-queue health. Escalation rate and queue latency are the
        signals that matter operationally -- the original spec called for
        escalation rate as an AIOps metric."""
        with self._conn() as con:
            total = con.execute("SELECT count(*) c FROM approvals").fetchone()["c"]
            by_status = {r["status"]: r["c"] for r in con.execute(
                "SELECT status, count(*) c FROM approvals GROUP BY status").fetchall()}
            decided = con.execute(
                "SELECT count(*) c, avg(queue_seconds) a FROM approvals "
                "WHERE queue_seconds IS NOT NULL").fetchone()
            by_decision = {r["decision"]: r["c"] for r in con.execute(
                "SELECT decision, count(*) c FROM approvals "
                "WHERE decision IS NOT NULL GROUP BY decision").fetchall()}
        n_decided = decided["c"] or 0
        n_esc = by_decision.get(ESCALATE, 0)
        return {
            "total_proposals": total,
            "by_status": by_status,
            "by_decision": by_decision,
            "pending": by_status.get("pending", 0),
            "avg_queue_seconds": round(decided["a"], 2) if decided["a"] is not None else None,
            "escalation_rate": round(n_esc / n_decided, 4) if n_decided else None,
            "approval_rate": round(
                (by_decision.get(APPROVE, 0) + by_decision.get(APPROVE_WITH_EDITS, 0)) / n_decided, 4
            ) if n_decided else None,
        }
