"""
publish_gold_to_databricks.py
=============================
Publish the local DuckDB **Gold** tables into Databricks as Delta tables, so the
agent can run the SAME governed queries against Databricks (DATA_BACKEND=databricks)
instead of local DuckDB.

This is the missing "publish" half of the Databricks lift. Today the Gold only
lives in local `medallion/*.duckdb` files; the DatabricksBackend queries Delta
tables that must already exist. This script creates + loads them.

  DuckDB Gold  ──(this script)──►  Databricks Delta  ──(DatabricksBackend)──►  agent

Scope / governance note:
  This is an OPERATOR / ETL tool, run by a human out-of-band -- the sibling of
  build_hospital_gold.py / build_fhir_gold.py. It is NOT part of the governed
  agent path, so it is allowed to do DDL/DML. The agent path stays SELECT-only
  through the guard; nothing here changes that.

It publishes only `gold_*` tables by default (the guard's allowlist), not the
bronze staging tables.

--------------------------------------------------------------------------------
SETUP (Databricks Free Edition -- forever-free, includes a serverless SQL warehouse)
--------------------------------------------------------------------------------
1. Sign up: https://www.databricks.com/learn/free-edition  and open the workspace.
2. SQL Warehouses -> use/create a **serverless** warehouse -> "Connection details":
   copy the **Server hostname** and **HTTP path**.
3. Create a **personal access token** (Settings -> Developer -> Access tokens).
4. Pick a catalog + schema. The catalog usually already exists (e.g. `workspace`
   or `main`); this script creates the schema. Match what DatabricksBackend reads:
       DATABRICKS_CATALOG (default 'main'), DATABRICKS_SCHEMA (default 'gold')
5. Install the driver:  pip install databricks-sql-connector
6. Set env + run (PowerShell):
       $env:DATABRICKS_SERVER_HOSTNAME="dbc-xxxx.cloud.databricks.com"
       $env:DATABRICKS_HTTP_PATH="/sql/1.0/warehouses/xxxxxxxx"
       $env:DATABRICKS_TOKEN="dapi..."
       $env:DATABRICKS_CATALOG="workspace"   # an EXISTING catalog
       $env:DATABRICKS_SCHEMA="gold"
       python scripts/publish_gold_to_databricks.py --db medallion/hospital_gold.duckdb
7. Point the agent at Databricks and run it:
       $env:DATA_BACKEND="databricks"
       uvicorn app:app --port 8000      # then ask a question at /ui

Start with the hospital Gold (~750 rows -- seconds). The FHIR Gold has a 223k-row
table (gold_observation); loading it over the SQL connector via INSERT is slow --
use --max-rows for a quick smoke test, or expect several minutes for the full load.

Usage:
    python scripts/publish_gold_to_databricks.py --db medallion/hospital_gold.duckdb
    python scripts/publish_gold_to_databricks.py --db medallion/fhir_gold.duckdb --max-rows 2000
    python scripts/publish_gold_to_databricks.py --db ... --dry-run   # print SQL, no connection
    python scripts/publish_gold_to_databricks.py --db ... --tables gold_patient gold_encounter

VERIFIED against a real workspace (Databricks Free Edition, serverless SQL
warehouse): published gold_hospital_profile to workspace.gold, then
served governed agent queries from it with the guard intact.
"""

from __future__ import annotations

import argparse
import os
import sys

import duckdb

# DuckDB type -> Databricks (Spark SQL) type. Gold columns only use these.
_TYPE_MAP = {
    "VARCHAR": "STRING", "TEXT": "STRING", "CHAR": "STRING",
    "INTEGER": "INT", "INT": "INT", "SMALLINT": "SMALLINT",
    "BIGINT": "BIGINT", "HUGEINT": "BIGINT",
    "DOUBLE": "DOUBLE", "FLOAT": "DOUBLE", "REAL": "DOUBLE",
    "BOOLEAN": "BOOLEAN", "BOOL": "BOOLEAN",
    "DATE": "DATE", "TIMESTAMP": "TIMESTAMP",
}


def _spark_type(duck_type: str) -> str:
    base = duck_type.upper().split("(")[0].strip()
    if base.startswith("DECIMAL") or base.startswith("NUMERIC"):
        return "DOUBLE"
    return _TYPE_MAP.get(base, "STRING")


def _literal(v) -> str:
    """Render a Python value as a Databricks SQL literal (inline, version-agnostic)."""
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    s = str(v).replace("\\", "\\\\").replace("'", "''")
    return "'" + s + "'"


def list_gold_tables(con) -> list[str]:
    rows = con.execute(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema='main' AND table_name LIKE 'gold\\_%' ESCAPE '\\' "
        "ORDER BY table_name"
    ).fetchall()
    return [r[0] for r in rows]


def table_columns(con, table: str) -> list[tuple[str, str]]:
    rows = con.execute(
        "SELECT column_name, data_type FROM information_schema.columns "
        "WHERE table_name=? ORDER BY ordinal_position", [table]
    ).fetchall()
    return [(c, t) for c, t in rows]


def build_ddl(fq_table: str, cols: list[tuple[str, str]]) -> str:
    coldefs = ",\n  ".join(f"`{c}` {_spark_type(t)}" for c, t in cols)
    return f"CREATE OR REPLACE TABLE {fq_table} (\n  {coldefs}\n) USING DELTA"


def build_inserts(fq_table, cols, rows, batch_size):
    """Yield multi-row INSERT statements, batch_size rows each."""
    collist = ", ".join(f"`{c}`" for c, _ in cols)
    for i in range(0, len(rows), batch_size):
        chunk = rows[i:i + batch_size]
        values = ",\n  ".join("(" + ", ".join(_literal(v) for v in row) + ")" for row in chunk)
        yield f"INSERT INTO {fq_table} ({collist}) VALUES\n  {values}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default="medallion/hospital_gold.duckdb",
                    help="path to the DuckDB Gold file to publish")
    ap.add_argument("--tables", nargs="*", default=None,
                    help="specific tables (default: all gold_* tables)")
    ap.add_argument("--catalog", default=os.environ.get("DATABRICKS_CATALOG", "main"))
    ap.add_argument("--schema", default=os.environ.get("DATABRICKS_SCHEMA", "gold"))
    ap.add_argument("--batch-size", type=int, default=1000)
    ap.add_argument("--max-rows", type=int, default=None,
                    help="cap rows loaded per table (smoke test); default all")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the DDL + first INSERT per table; do not connect")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        sys.exit(f"missing DuckDB file: {args.db}")

    con = duckdb.connect(args.db, read_only=True)
    tables = args.tables or list_gold_tables(con)
    if not tables:
        sys.exit(f"no gold_* tables found in {args.db}")

    print(f"source: {args.db}")
    print(f"target: {args.catalog}.{args.schema}  ({len(tables)} tables)")
    print(f"mode:   {'DRY RUN' if args.dry_run else 'LIVE WRITE'}\n")

    # Live connection is opened lazily so --dry-run needs no driver / workspace.
    conn = cur = None
    if not args.dry_run:
        host = os.environ.get("DATABRICKS_SERVER_HOSTNAME")
        http_path = os.environ.get("DATABRICKS_HTTP_PATH")
        token = os.environ.get("DATABRICKS_TOKEN")
        if not all([host, http_path, token]):
            sys.exit("set DATABRICKS_SERVER_HOSTNAME, DATABRICKS_HTTP_PATH, DATABRICKS_TOKEN "
                     "(or use --dry-run)")
        try:
            from databricks import sql as dbsql
        except ImportError:
            sys.exit("pip install databricks-sql-connector")
        conn = dbsql.connect(server_hostname=host, http_path=http_path, access_token=token)
        cur = conn.cursor()
        cur.execute(f"CREATE SCHEMA IF NOT EXISTS `{args.catalog}`.`{args.schema}`")

    total = 0
    for t in tables:
        cols = table_columns(con, t)
        if not cols:
            print(f"  ! {t}: not found, skipping"); continue
        fq = f"`{args.catalog}`.`{args.schema}`.`{t}`"
        limit = f" LIMIT {args.max_rows}" if args.max_rows else ""
        rows = con.execute(f'SELECT * FROM "{t}"{limit}').fetchall()
        ddl = build_ddl(fq, cols)

        if args.dry_run:
            print(f"-- {t}: {len(rows)} rows, {len(cols)} cols")
            print(ddl + ";")
            first = next(build_inserts(fq, cols, rows[:2], args.batch_size), "(no rows)")
            print(first + ";\n")
            continue

        cur.execute(ddl)
        n = 0
        for stmt in build_inserts(fq, cols, rows, args.batch_size):
            cur.execute(stmt)
            n += min(args.batch_size, len(rows) - n)
        (loaded,) = cur.execute(f"SELECT count(*) FROM {fq}").fetchone()
        print(f"  OK {t}: loaded {loaded} rows")
        total += loaded

    con.close()
    if cur:
        cur.close(); conn.close()
        print(f"\ndone: {total} rows across {len(tables)} tables into "
              f"{args.catalog}.{args.schema}")
        print("next: DATA_BACKEND=databricks, then run the app / eval against Databricks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
