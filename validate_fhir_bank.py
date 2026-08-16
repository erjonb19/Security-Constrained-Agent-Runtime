"""
validate_fhir_bank.py
=====================
Sanity-checks every reference query in eval_bank_fhir.py against the real FHIR
Gold BEFORE any of it is used to score an agent.

Why this matters: a reference query IS the answer key. If it errors, returns
nothing, or returns something implausible, every case built on it is worthless
and the eval silently measures the wrong thing. Verify the answer key first.

    python validate_fhir_bank.py
"""

import duckdb
from eval_bank_fhir import CASES

DB = "medallion/fhir_gold.duckdb"

con = duckdb.connect(DB, read_only=True)
ok = bad = 0
print(f"validating {len(CASES)} reference queries against {DB}\n")
for c in CASES:
    try:
        rows = con.execute(c["reference_sql"]).fetchall()
    except Exception as e:
        print(f"[ERROR] t{c['tier']} {c['id']:32} {str(e)[:70]}")
        bad += 1
        continue
    if not rows:
        print(f"[EMPTY] t{c['tier']} {c['id']:32} returned no rows")
        bad += 1
        continue
    if c["mode"] == "scalar":
        val = rows[0][0]
        flag = "" if val is not None else "  <- NULL"
        print(f"[ok]    t{c['tier']} {c['id']:32} = {val}{flag}")
        if val is None:
            bad += 1
            continue
    else:
        vals = [r[0] for r in rows]
        print(f"[ok]    t{c['tier']} {c['id']:32} {len(vals)} rows: {vals[:2]}")
    ok += 1

print(f"\n{ok} valid, {bad} problem(s)")
con.close()
