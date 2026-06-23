"""Analytics query tool (capability: analytics.query_aggregate).

The agent writes its own SQL for flexibility. Before anything runs, the SQL is
parsed and checked by sql_guard.validate_query: SELECT only, Gold table
allowlist, row cap, no catalog access, no file-reading functions. A denied
query returns a clean ToolResult failure; an allowed query runs the validator's
safe_sql (row cap already applied) and returns rows.

Two layers govern this tool:
  1. The policy engine decides whether analytics.query_aggregate may run at all.
  2. sql_guard decides whether THIS specific query is safe.
Plus the DB backstop: point this at a read-only role / PHI-excluding views.

Demo mode: with no real Gold warehouse, the tool seeds a tiny in-memory DuckDB
so allowed queries return real rows. For production, pass db_path to your real
DuckDB/Parquet store and set seed_demo=False.
"""

from __future__ import annotations

from typing import Any, Dict

import duckdb

from src.tools.base import BaseTool, ToolResult
from sql_guard import validate_query


class AnalyticsQueryTool(BaseTool):
    def __init__(self, db_path: str = ":memory:", seed_demo: bool = True,
                 row_cap: int = 1000, ledger=None):
        self._db_path = db_path
        self._row_cap = row_cap
        self._ledger = ledger          # optional QueryLedger for groundedness
        self._con = duckdb.connect(db_path)
        if seed_demo:
            self._seed_demo_gold()

    @property
    def name(self) -> str:
        return "analytics.query_aggregate"

    def execute(self, params: Dict[str, Any]) -> ToolResult:
        sql = params.get("sql")
        if not isinstance(sql, str) or not sql.strip():
            return ToolResult(success=False, output=None,
                              error="Parameter 'sql' (a SELECT query) is required.")

        # Layer 2: validate the specific query before it can run.
        decision = validate_query(sql, row_cap=self._row_cap)
        if not decision.allowed:
            return ToolResult(
                success=False,
                output={"sql": sql, "findings": decision.findings},
                error=f"DENIED by sql_guard: {decision.reason}",
            )

        # Allowed. Run the safe SQL (row cap already applied by the guard).
        try:
            cur = self._con.execute(decision.safe_sql)
            cols = [d[0] for d in cur.description] if cur.description else []
            raw = cur.fetchall()
            rows = [dict(zip(cols, r)) for r in raw]

            # Record real rows for groundedness verification (before redaction).
            query_id = self._ledger.record(cols, rows) if self._ledger is not None else None

            return ToolResult(
                success=True,
                output={
                    "query_id": query_id,
                    "safe_sql": decision.safe_sql,
                    "row_count": len(rows),
                    "columns": cols,
                    "rows": rows[: self._row_cap],
                },
            )
        except Exception as e:
            return ToolResult(success=False, output={"safe_sql": decision.safe_sql},
                              error=f"query execution failed: {e}")

    # -- demo data only; delete when you point at real Gold -----------------
    def _seed_demo_gold(self) -> None:
        self._con.execute("""
            CREATE TABLE gold_utilization (
                region VARCHAR, year INTEGER,
                admits_per_1k DOUBLE, ed_per_1k DOUBLE, readmit_per_1k DOUBLE
            );
            INSERT INTO gold_utilization VALUES
                ('Bronx', 2023, 312.4, 689.1, 18.2),
                ('Manhattan', 2023, 271.8, 540.6, 15.1),
                ('Queens', 2023, 298.0, 612.3, 16.7),
                ('Westchester', 2023, 240.5, 498.2, 13.4);

            CREATE TABLE gold_cost (
                region VARCHAR, year INTEGER, service_category VARCHAR, pmpm DOUBLE
            );
            INSERT INTO gold_cost VALUES
                ('Bronx', 2023, 'inpatient', 412.10),
                ('Bronx', 2023, 'outpatient', 188.45),
                ('Manhattan', 2023, 'inpatient', 380.22),
                ('Queens', 2023, 'inpatient', 401.77);

            CREATE TABLE gold_region_profile (
                region VARCHAR, beneficiaries INTEGER
            );
            INSERT INTO gold_region_profile VALUES
                ('Bronx', 142500), ('Manhattan', 98700),
                ('Queens', 121300), ('Westchester', 76400);

            CREATE TABLE gold_anomaly (
                region VARCHAR, metric VARCHAR, anomaly_score DOUBLE
            );
            INSERT INTO gold_anomaly VALUES
                ('Bronx', 'readmit_per_1k', 3.4),
                ('Queens', 'ed_per_1k', 2.1),
                ('Manhattan', 'pmpm', 3.9);
        """)
