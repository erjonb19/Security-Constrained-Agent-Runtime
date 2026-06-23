"""
aiops_metrics.py
================
Pure functions that read the runtime's JSONL audit logs and turn them into the
AIOps signals the panel displays. No Streamlit here, so this stays testable.

Each audit event is one terminal outcome of an execute_tool call. We classify
every denied call by which control stopped it:
    guard        - SQL guard rejected the query (sql_guard in the reason)
    groundedness - brief blocked because a number had no source row
    taint        - tainted read-data flowed toward a sink
    parameter    - parameter validation failed
    injection    - injection detector fired
    policy       - capability denied at the policy layer
    tool_error   - tool failed for some other reason
Allowed calls are 'allowed'.
"""

from __future__ import annotations

import glob
import json
import os
from datetime import datetime
from typing import Any, Dict, List


def load_events(log_dir: str = "logs") -> List[Dict[str, Any]]:
    """Read every audit_*.jsonl file in log_dir into a flat list of events."""
    events: List[Dict[str, Any]] = []
    for path in sorted(glob.glob(os.path.join(log_dir, "audit_*.jsonl"))):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return events


def _reason_text(ev: Dict[str, Any]) -> str:
    parts = [str(ev.get("reason", ""))]
    er = (ev.get("execution_result") or {}).get("error")
    if er:
        parts.append(str(er))
    return " ".join(parts).lower()


def classify(ev: Dict[str, Any]) -> str:
    """Return the outcome category for one event."""
    etype = ev.get("event_type", "")
    decision = ev.get("decision", "")

    if etype == "taint_violation":
        return "taint"
    if etype == "parameter_validation":
        return "parameter"
    if etype == "injection_detected":
        return "injection"
    if etype == "policy_evaluation":
        return "allowed" if decision == "allow" else "policy"

    # tool_execution (and sandbox_execution)
    if decision == "allow":
        return "allowed"
    text = _reason_text(ev)
    if "sql_guard" in text:
        return "guard"
    if "groundedness" in text:
        return "groundedness"
    if "taint" in text:
        return "taint"
    return "tool_error"


def terminal_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drop policy 'allow' events so each call is counted once.

    A policy-allow is followed by a tool_execution for the same call, so keeping
    both would double count. Every other event is a terminal outcome.
    """
    out = []
    for ev in events:
        if ev.get("event_type") == "policy_evaluation" and ev.get("decision") == "allow":
            continue
        out.append(ev)
    return out


def build_records(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Flatten terminal events into rows for charting."""
    rows = []
    for ev in terminal_events(events):
        cat = classify(ev)
        ts = ev.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(ts)
        except (ValueError, TypeError):
            dt = None
        lat = (ev.get("performance_metrics") or {}).get("execution_time_ms")
        rows.append({
            "timestamp": dt,
            "capability": ev.get("capability", ""),
            "category": cat,
            "allowed": cat == "allowed",
            "latency_ms": float(lat) if isinstance(lat, (int, float)) else None,
            "reason": ev.get("reason", ""),
        })
    return rows


def summarize(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Top-line KPIs from the flattened rows."""
    total = len(rows)
    allowed = sum(1 for r in rows if r["allowed"])
    denied = total - allowed
    by_cat: Dict[str, int] = {}
    for r in rows:
        by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1
    lats = [r["latency_ms"] for r in rows if r["latency_ms"] is not None]
    avg_lat = sum(lats) / len(lats) if lats else 0.0
    return {
        "total_calls": total,
        "allowed": allowed,
        "denied": denied,
        "allow_rate": (allowed / total) if total else 0.0,
        "taint_blocks": by_cat.get("taint", 0),
        "groundedness_blocks": by_cat.get("groundedness", 0),
        "guard_blocks": by_cat.get("guard", 0),
        "avg_latency_ms": avg_lat,
        "by_category": by_cat,
    }
