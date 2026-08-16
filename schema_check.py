"""
schema_check.py
===============
Fails loudly when the planner's schema does not match the connected database.

THE FAILURE THIS PREVENTS
PLANNER_SCHEMA (which tables the model is told about) and the analytics tool's
db_path (which database is actually connected) are independent settings that MUST
agree. When they diverge, the agent writes perfectly good SQL against tables that
do not exist in the connected database. Every attempt fails, retries exhaust, and
the caller gets a confusing "completed" with an empty result and no explanation
of the real cause.

That is the worst kind of bug: silent, misleading, and it looks like the agent is
broken when the configuration is.

Discovered the hard way -- PLANNER_SCHEMA was left on "fhir" from an eval run
while the agent connected to the hospital database.

THE CHECK
Parse the table names the schema doc describes, list the tables actually in the
database, and require that they overlap. Raise immediately with both lists if not.
Cheap to run, and it converts a confusing multi-minute debug into one clear line.
"""

import re


def tables_in_schema_doc(schema_doc: str) -> set:
    """Table names the schema doc tells the model about.

    Matches both shapes used in the docs:
      "Table: gold_hospital_profile  (one row per hospital...)"
      "  gold_patient      patient_id, gender, ..."   (the FHIR summary block)
    """
    names = set(re.findall(r"^Table:\s+(\w+)", schema_doc, re.M))
    names |= set(re.findall(r"^\s{2,}(gold_\w+)\s", schema_doc, re.M))
    return names


def tables_in_database(con) -> set:
    """Tables actually present in the connected DuckDB database."""
    rows = con.execute(
        "SELECT table_name FROM information_schema.tables"
    ).fetchall()
    return {r[0] for r in rows}


def verify(schema_doc: str, con, *, schema_label: str = "?",
           db_label: str = "?", strict: bool = True) -> dict:
    """Check the schema doc against the database.

    strict=True  -> raise on mismatch (use at startup)
    strict=False -> return the report, caller decides
    """
    described = tables_in_schema_doc(schema_doc)
    present = tables_in_database(con)
    missing = described - present
    overlap = described & present

    report = {
        "schema": schema_label,
        "database": db_label,
        "described": sorted(described),
        "missing_from_db": sorted(missing),
        "matched": sorted(overlap),
        "ok": bool(overlap) and not missing,
    }

    if strict and not overlap:
        raise SystemExit(
            f"\nSCHEMA/DATABASE MISMATCH\n"
            f"  PLANNER_SCHEMA describes: {sorted(described)}\n"
            f"  connected database has:   {sorted(present)}\n"
            f"  schema='{schema_label}'  db='{db_label}'\n"
            f"  NOTHING overlaps -- every query would fail.\n"
            f"  Fix: set PLANNER_SCHEMA to match the database you connected to.\n"
        )
    if strict and missing:
        # partial overlap: usable, but the model will be told about tables that
        # are not there, so warn rather than fail
        print(f"WARNING: schema '{schema_label}' describes tables not in "
              f"{db_label}: {sorted(missing)}")
    return report
