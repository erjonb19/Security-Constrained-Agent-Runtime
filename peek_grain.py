"""
peek_grain.py
=============
Throwaway helper: finds conditions where the RECORD count meaningfully exceeds
the DISTINCT PATIENT count -- i.e. recurring illnesses a patient gets more than
once.

Why: the eval case f5_grain_records_vs_patients is supposed to test whether the
agent understands the difference between "how many patients" and "how many
records". It currently uses Hypertension, where both counts are 330 -- so the
case cannot tell a right answer from a wrong one. This finds a condition where
the two genuinely differ, so the case actually tests what it claims.

    python peek_grain.py
"""

import duckdb

con = duckdb.connect("medallion/fhir_gold.duckdb", read_only=True)
rows = con.execute("""
    SELECT condition_name,
           count(*)                    AS recs,
           count(DISTINCT patient_id)  AS pts
    FROM gold_condition
    GROUP BY 1
    HAVING count(*) > count(DISTINCT patient_id) * 1.5
    ORDER BY recs DESC
    LIMIT 8
""").fetchall()

if not rows:
    print("no conditions where records meaningfully exceed patients")
else:
    print(f"{'condition_name':45} {'records':>8} {'patients':>9}  ratio")
    for name, recs, pts in rows:
        print(f"{name:45} {recs:>8} {pts:>9}  {recs/pts:.2f}x")

con.close()
