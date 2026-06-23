"""
peek_measures.py
================
Dumps the distinct measure names in the two long CMS hospital files, plus the
hospital count per state. Run from the repo root after fetching the files:

    python peek_measures.py
"""

import duckdb

con = duckdb.connect()

for label, path in [("UNPLANNED VISITS", "data/unplanned_visits.csv"),
                    ("TIMELY & EFFECTIVE", "data/timely_effective_care.csv")]:
    print(f"--- {label} ---")
    rows = con.execute(
        f'SELECT DISTINCT "Measure Name" FROM read_csv_auto(\'{path}\', all_varchar=true) ORDER BY 1'
    ).fetchall()
    for r in rows:
        print("  ", r[0])
    print()

print("--- HOSPITALS BY STATE ---")
for r in con.execute(
    "SELECT State, count(*) FROM read_csv_auto('data/hospital_general.csv', all_varchar=true) "
    "GROUP BY State ORDER BY 2 DESC"
).fetchall():
    print("  ", r[0], r[1])
