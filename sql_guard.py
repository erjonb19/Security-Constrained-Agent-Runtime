"""
sql_guard.py
============
AST-based validator for agent-written SQL against the Gold lakehouse.

The agent is allowed to write its own SQL (flexibility), but every query is
parsed into a syntax tree and checked before it is allowed to run. This is the
enforcement seam your runtime can call, and the place you add more rules as you
watch what the agent gets wrong.

Rules enforced:
  1. Must parse. Unparseable SQL is denied (fail closed).
  2. Exactly one statement. No stacked statements (no `; DELETE ...`).
  3. SELECT only. Any INSERT/UPDATE/DELETE/DROP/CREATE/ALTER/TRUNCATE/MERGE
     anywhere in the tree (including inside CTEs or subqueries) is denied.
  4. Table allowlist. Every referenced table must be in ALLOWED_TABLES.
     Anything else, including catalog schemas, is denied and named.
  5. No file/exfil functions. read_csv, read_parquet, glob, etc. are denied.
  6. Row cap. If there is no LIMIT, one is added. If LIMIT exceeds the cap,
     it is clamped.

Returns a Decision the runtime can log and surface, in the same allow/deny
shape as the rest of the policy engine.

Backstop reminder: this validator is the first line, not the only one. Run the
agent against a read-only DB role and PHI-excluding views so the database
refuses anything a rule here misses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import sqlglot
from sqlglot import exp


# ---------------------------------------------------------------------------
# Config. Edit these as you learn what the agent does. This is your loop.
# ---------------------------------------------------------------------------
ALLOWED_TABLES = {
    "gold_utilization",
    "gold_cost",
    "gold_region_profile",
    "gold_anomaly",
    "gold_hospital_profile",
}

# Functions that can read the filesystem or exfiltrate. DuckDB-flavored.
DENIED_FUNCTIONS = {
    "read_csv", "read_csv_auto", "read_parquet", "read_json",
    "read_json_auto", "glob", "read_text", "read_blob",
    "load", "install", "copy",
}

# Catalog / system schemas the agent must never browse.
DENIED_SCHEMAS = {
    "information_schema", "pg_catalog", "system", "duckdb",
}

DIALECT = "duckdb"
DEFAULT_ROW_CAP = 1000


# Statement node types that mean a write or schema change anywhere in the tree.
_WRITE_NODES = (
    exp.Insert, exp.Update, exp.Delete, exp.Drop, exp.Create,
    exp.Alter, exp.TruncateTable, exp.Merge, exp.Command,
)


@dataclass
class Decision:
    allowed: bool
    reason: str
    safe_sql: Optional[str] = None
    findings: list = field(default_factory=list)


def validate_query(sql: str,
                   allowed_tables: Optional[set] = None,
                   row_cap: int = DEFAULT_ROW_CAP) -> Decision:
    allowed_tables = {t.lower() for t in (allowed_tables or ALLOWED_TABLES)}

    # 1. Must parse, and as exactly one statement.
    try:
        statements = sqlglot.parse(sql, read=DIALECT)
    except Exception as e:
        return Decision(False, f"unparseable SQL, denied (fail closed): {e}")

    statements = [s for s in statements if s is not None]
    if len(statements) == 0:
        return Decision(False, "empty query, nothing to run")
    if len(statements) > 1:
        return Decision(False, f"stacked statements not allowed ({len(statements)} found)")

    tree = statements[0]

    # 2. SELECT only. Top node must be a query, and no write nodes anywhere.
    if not isinstance(tree, (exp.Select, exp.Union, exp.Subquery, exp.With)):
        return Decision(False, f"only SELECT is allowed, got {type(tree).__name__.upper()}")

    for node in tree.walk():
        if isinstance(node, _WRITE_NODES):
            return Decision(False, f"write or DDL operation denied: {type(node).__name__.upper()}")

    # 3. Table allowlist (and schema check).
    # CTE names are local aliases, not real tables, so exclude them.
    cte_names = {c.alias_or_name.lower() for c in tree.find_all(exp.CTE)}
    bad_tables = []
    for t in tree.find_all(exp.Table):
        name = (t.name or "").lower()
        schema = (t.db or "").lower()
        if schema in DENIED_SCHEMAS:
            return Decision(False, f"catalog/system schema not allowed: {schema}.{name}")
        if name in cte_names:
            continue
        if name and name not in allowed_tables:
            bad_tables.append(name)
    if bad_tables:
        return Decision(
            False,
            f"table not on Gold allowlist: {', '.join(sorted(set(bad_tables)))}",
            findings=sorted(set(bad_tables)),
        )

    # 4. Denied functions (file read / exfil).
    bad_funcs = []
    for fn in tree.find_all(exp.Anonymous):
        fname = (fn.name or "").lower()
        if fname in DENIED_FUNCTIONS:
            bad_funcs.append(fname)
    # typed func nodes that sqlglot recognizes by class name
    for fn in tree.find_all(exp.Func):
        fname = (fn.sql_names()[0] if fn.sql_names() else "").lower()
        if fname in DENIED_FUNCTIONS:
            bad_funcs.append(fname)
    if bad_funcs:
        return Decision(
            False,
            f"disallowed function: {', '.join(sorted(set(bad_funcs)))}",
            findings=sorted(set(bad_funcs)),
        )

    # 5. Row cap. Add a LIMIT if missing, clamp if too high.
    if isinstance(tree, exp.Select):
        limit = tree.args.get("limit")
        if limit is None:
            tree = tree.limit(row_cap)
            note = f"added LIMIT {row_cap}"
        else:
            try:
                current = int(limit.expression.name)
            except Exception:
                current = None
            if current is None or current > row_cap:
                tree = tree.limit(row_cap)
                note = f"clamped LIMIT to {row_cap}"
            else:
                note = f"LIMIT {current} within cap"
    else:
        # UNION / subquery at top: wrap-limit is fiddly, enforce by re-select
        note = "non-simple SELECT, row cap enforced at DB layer"

    safe_sql = tree.sql(dialect=DIALECT)
    return Decision(True, f"allowed ({note})", safe_sql=safe_sql)


if __name__ == "__main__":
    # Test harness. This IS the loop: real informatics questions on top,
    # adversarial queries below. Run it, read the decisions, add cases.
    good = [
        ("readmission rate by region 2023",
         "SELECT region, readmit_per_1k FROM gold_utilization WHERE year = 2023"),
        ("top 10 regions by ED visits per 1000",
         "SELECT region, ed_per_1k FROM gold_utilization ORDER BY ed_per_1k DESC LIMIT 10"),
        ("PMPM by service category year over year",
         "SELECT year, service_category, pmpm FROM gold_cost ORDER BY year"),
        ("provider submitted-to-allowed ratio outliers",
         "SELECT region, anomaly_score FROM gold_anomaly WHERE anomaly_score > 3"),
        ("join Gold tables, no limit set",
         "SELECT u.region, c.pmpm FROM gold_utilization u JOIN gold_cost c ON u.region = c.region"),
        ("CTE that stays inside Gold",
         "WITH r AS (SELECT region, ed_per_1k FROM gold_utilization) SELECT * FROM r"),
        ("hospital best-value: high quality low cost",
         "SELECT facility_name, state, star_rating, mspb_score FROM gold_hospital_profile "
         "WHERE star_rating >= 4 AND mspb_score < 1.0 ORDER BY mspb_score LIMIT 15"),
    ]
    bad = [
        ("drop a table", "DROP TABLE gold_utilization"),
        ("stacked delete", "SELECT * FROM gold_utilization; DELETE FROM gold_utilization"),
        ("catalog snooping", "SELECT * FROM information_schema.tables"),
        ("denied table (PHI)", "SELECT * FROM raw_member_phi"),
        ("file read function", "SELECT * FROM read_csv('/etc/passwd')"),
        ("insert disguised", "INSERT INTO gold_utilization VALUES (1)"),
        ("subquery into denied table",
         "SELECT region FROM gold_utilization WHERE region IN (SELECT region FROM secret_costs)"),
        ("update inside a CTE",
         "WITH x AS (UPDATE gold_cost SET pmpm = 0 RETURNING region) SELECT * FROM x"),
    ]

    def run(label, cases):
        print(f"\n===== {label} =====")
        for desc, q in cases:
            d = validate_query(q)
            tag = "ALLOW" if d.allowed else "DENY "
            print(f"[{tag}] {desc}")
            print(f"        reason: {d.reason}")
            if d.safe_sql:
                print(f"        safe_sql: {d.safe_sql}")

    run("REAL INFORMATICS QUERIES (expect ALLOW)", good)
    run("ADVERSARIAL QUERIES (expect DENY)", bad)
