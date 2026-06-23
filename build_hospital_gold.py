"""
build_hospital_gold.py
======================
Hospital-level medallion. Lands five CMS Provider Data files, pivots the two
long ones (Unplanned Visits, Timely & Effective Care) to the measures we chose,
joins everything on Facility ID, and writes a provider-profile Gold.

Run from the repo root (after fetching the five CSVs into data\\) with venv311:
    python build_hospital_gold.py

Output:
    medallion\\hospital_gold.duckdb   table: gold_hospital_profile

State filter: edit STATES below. Empty list = all states.
"""

from __future__ import annotations

import os
import duckdb

DATA = "data"
OUT_DIR = "medallion"
GOLD_DB = os.path.join(OUT_DIR, "hospital_gold.duckdb")

# One-line geography switch. [] = all states. e.g. ["NY","NJ","CT","PA","MA"]
STATES: list[str] = ["NY", "NJ", "PA", "DE", "MD", "DC", "MA", "CT", "RI", "VT", "NH", "ME"]

# Measures to pull from the two long files, mapped to clean column names.
UNPLANNED_MEASURES = {
    "Hybrid Hospital-Wide All-Cause Readmission Measure (HWR)": "readmit_hwr",
    "Heart failure (HF) 30-Day Readmission Rate": "readmit_hf",
    "Pneumonia (PN) 30-Day Readmission Rate": "readmit_pn",
    "Acute Myocardial Infarction (AMI) 30-Day Readmission Rate": "readmit_ami",
    "Rate of readmission for chronic obstructive pulmonary disease (COPD) patients": "readmit_copd",
}
TIMELY_MEASURES = {
    "Average (median) time all patients spent in the emergency department before leaving from the visit, including psychiatric/mental health patients and patients who were transferred to another facility. A lower number of minutes is better": "ed_median_min",
    "Average (median) time psychiatric/mental health patients spent in the emergency department before leaving from the visit. A lower number of minutes is better": "ed_psych_median_min",
    "Left before being seen": "ed_left_before_seen_pct",
    "Emergency department volume": "ed_volume",
}

NUM = lambda c: (f"TRY_CAST(NULLIF(NULLIF(NULLIF(NULLIF(CAST({c} AS VARCHAR),"
                f"'Not Available'),'Not Applicable'),'N/A'),'') AS DOUBLE)")


def _state_clause(col: str = "state") -> str:
    if not STATES:
        return ""
    inlist = ", ".join(f"'{s}'" for s in STATES)
    return f"WHERE {col} IN ({inlist})"


def _pivot_select(measures: dict) -> str:
    # builds: max(CASE WHEN "Measure Name"=... THEN Score END) AS col, ...
    parts = []
    for mname, col in measures.items():
        safe = mname.replace("'", "''")
        parts.append(f"max(CASE WHEN \"Measure Name\" = '{safe}' THEN {NUM('Score')} END) AS {col}")
    return ",\n        ".join(parts)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    if os.path.exists(GOLD_DB):
        os.remove(GOLD_DB)
    con = duckdb.connect(GOLD_DB)
    con.execute("SET preserve_insertion_order=false")

    # --- spine: hospital general info ---
    con.execute(f"""
        CREATE TABLE spine AS
        SELECT
            "Facility ID"   AS facility_id,
            "Facility Name" AS facility_name,
            "City/Town"     AS city,
            "State"         AS state,
            "ZIP Code"      AS zip,
            {NUM('"Hospital overall rating"')} AS star_rating
        FROM read_csv_auto('{DATA}/hospital_general.csv', all_varchar=true)
    """)

    # --- MSPB: one cost number per hospital ---
    con.execute(f"""
        CREATE TABLE mspb AS
        SELECT "Facility ID" AS facility_id, {NUM('Score')} AS mspb_score
        FROM read_csv_auto('{DATA}/mspb.csv', all_varchar=true)
    """)

    # --- pivot the long files to chosen measures ---
    con.execute(f"""
        CREATE TABLE readmissions AS
        SELECT "Facility ID" AS facility_id,
            {_pivot_select(UNPLANNED_MEASURES)}
        FROM read_csv_auto('{DATA}/unplanned_visits.csv', all_varchar=true)
        GROUP BY "Facility ID"
    """)
    con.execute(f"""
        CREATE TABLE ed AS
        SELECT "Facility ID" AS facility_id,
            {_pivot_select(TIMELY_MEASURES)}
        FROM read_csv_auto('{DATA}/timely_effective_care.csv', all_varchar=true)
        GROUP BY "Facility ID"
    """)

    # --- join into the profile, filter to states ---
    con.execute(f"""
        CREATE TABLE gold_hospital_profile AS
        SELECT s.*,
               m.mspb_score,
               r.readmit_hwr, r.readmit_hf, r.readmit_pn, r.readmit_ami, r.readmit_copd,
               e.ed_median_min, e.ed_psych_median_min, e.ed_left_before_seen_pct, e.ed_volume
        FROM spine s
        LEFT JOIN mspb m USING (facility_id)
        LEFT JOIN readmissions r USING (facility_id)
        LEFT JOIN ed e USING (facility_id)
        {_state_clause('s.state')}
    """)
    for t in ("spine", "mspb", "readmissions", "ed"):
        con.execute(f"DROP TABLE {t}")

    n = con.execute("SELECT count(*) FROM gold_hospital_profile").fetchone()[0]
    rated = con.execute("SELECT count(*) FROM gold_hospital_profile WHERE star_rating IS NOT NULL").fetchone()[0]
    hwr = con.execute("SELECT count(*) FROM gold_hospital_profile WHERE readmit_hwr IS NOT NULL").fetchone()[0]
    scope = ", ".join(STATES) if STATES else "all states"
    print(f"gold_hospital_profile: {n} hospitals ({scope})")
    print(f"  with star rating: {rated}")
    print(f"  with HWR readmission: {hwr}")
    print(f"-> {GOLD_DB}")
    con.close()


if __name__ == "__main__":
    main()
