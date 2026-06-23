"""
build_medallion.py
==================
Local medallion pipeline for the CMS Medicare Geographic Variation data, using
DuckDB. Bronze lands raw, Silver cleans and types, Gold builds the region-level
tables the analytics agent queries.

Stages:
    inspect <csv>   print real columns + sample rows
    bronze  <csv>   land raw CSV as parquet (all text; suppressed cells survive)
    silver          clean/type the State + All-ages slice -> silver.parquet
    gold            build gold tables -> medallion\\gold.duckdb

Typical run:
    python fetch_cms.py
    python build_medallion.py bronze data\\cms_gv.csv
    python build_medallion.py silver
    python build_medallion.py gold

Then point the analytics tool at real Gold:
    AnalyticsQueryTool(db_path="medallion/gold.duckdb", seed_demo=False)

CMS suppression markers ('NA', '*', '.', blank) are nulled before typing, which
is exactly why Bronze lands raw strings and typing happens here in Silver.
"""

from __future__ import annotations

import os
import sys

import duckdb

OUT_DIR = "medallion"
BRONZE = os.path.join(OUT_DIR, "bronze.parquet")
SILVER = os.path.join(OUT_DIR, "silver.parquet")
GOLD_DB = os.path.join(OUT_DIR, "gold.duckdb")


def _connect() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect()
    con.execute("PRAGMA threads=4")
    con.execute("SET preserve_insertion_order=false")
    return con


def _num(col: str) -> str:
    # null the CMS suppression markers, then cast to double
    return (f"TRY_CAST(NULLIF(NULLIF(NULLIF(NULLIF(CAST({col} AS VARCHAR),"
            f"'NA'),'*'),'.'),'') AS DOUBLE)")


def inspect(csv_path: str) -> None:
    if not os.path.exists(csv_path):
        sys.exit(f"file not found: {csv_path}")
    con = _connect()
    con.execute(f"CREATE TABLE t AS SELECT * FROM read_csv_auto('{csv_path}', "
                f"all_varchar=true, header=true, sample_size=-1)")
    cols = con.execute("DESCRIBE t").fetchall()
    n = con.execute("SELECT count(*) FROM t").fetchone()[0]
    print(f"\nrows: {n}\ncolumns: {len(cols)}\n")
    print("=== COLUMNS ===")
    for c in cols:
        print(f"  {c[0]}")
    print("\n=== 2 SAMPLE ROWS ===")
    colnames = [c[0] for c in cols]
    for i, row in enumerate(con.execute("SELECT * FROM t LIMIT 2").fetchall(), 1):
        print(f"\n-- row {i} --")
        for name, val in zip(colnames, row):
            print(f"  {name}: {val}")


def bronze(csv_path: str) -> None:
    if not os.path.exists(csv_path):
        sys.exit(f"file not found: {csv_path}")
    os.makedirs(OUT_DIR, exist_ok=True)
    con = _connect()
    con.execute(f"CREATE TABLE bronze AS SELECT * FROM read_csv_auto('{csv_path}', "
                f"all_varchar=true, header=true, sample_size=-1)")
    n = con.execute("SELECT count(*) FROM bronze").fetchone()[0]
    con.execute(f"COPY bronze TO '{BRONZE}' (FORMAT parquet)")
    print(f"bronze landed: {n} rows -> {BRONZE}")


def silver() -> None:
    if not os.path.exists(BRONZE):
        sys.exit(f"missing {BRONZE}; run bronze first")
    con = _connect()
    con.execute(f"""
        CREATE TABLE silver AS
        SELECT
            CAST(YEAR AS INTEGER)                       AS year,
            BENE_GEO_DESC                               AS region,
            {_num('BENES_TOTAL_CNT')}                   AS beneficiaries,
            {_num('IP_CVRD_STAYS_PER_1000_BENES')}      AS admits_per_1k,
            {_num('ER_VISITS_PER_1000_BENES')}          AS ed_per_1k,
            {_num('ACUTE_HOSP_READMSN_PCT')} * 100      AS readmit_pct,
            {_num('TOT_MDCR_STDZD_PYMT_PC')}            AS tot_pc,
            {_num('IP_MDCR_STDZD_PYMT_PC')}             AS ip_pc,
            {_num('OP_MDCR_STDZD_PYMT_PC')}             AS op_pc,
            {_num('SNF_MDCR_STDZD_PYMT_PC')}            AS snf_pc,
            {_num('HH_MDCR_STDZD_PYMT_PC')}             AS hh_pc,
            {_num('HOSPC_MDCR_STDZD_PYMT_PC')}          AS hospc_pc
        FROM read_parquet('{BRONZE}')
        WHERE BENE_GEO_LVL = 'State' AND BENE_AGE_LVL = 'All'
    """)
    # data-quality checks: fail loudly
    n = con.execute("SELECT count(*) FROM silver").fetchone()[0]
    nulls = con.execute("SELECT count(*) FROM silver WHERE region IS NULL OR year IS NULL").fetchone()[0]
    if n == 0:
        sys.exit("silver is empty; check BENE_GEO_LVL/BENE_AGE_LVL filter against your file")
    if nulls > 0:
        sys.exit(f"silver has {nulls} rows missing region/year; aborting")
    con.execute(f"COPY silver TO '{SILVER}' (FORMAT parquet)")
    yrs = con.execute("SELECT min(year), max(year) FROM silver").fetchone()
    print(f"silver built: {n} state rows, years {yrs[0]}-{yrs[1]} -> {SILVER}")


def gold() -> None:
    if not os.path.exists(SILVER):
        sys.exit(f"missing {SILVER}; run silver first")
    if os.path.exists(GOLD_DB):
        os.remove(GOLD_DB)
    g = duckdb.connect(GOLD_DB)
    g.execute("SET preserve_insertion_order=false")
    g.execute(f"CREATE TABLE s AS SELECT * FROM read_parquet('{SILVER}')")

    g.execute("""
        CREATE TABLE gold_utilization AS
        SELECT region, year, admits_per_1k, ed_per_1k, readmit_pct FROM s
    """)
    g.execute("""
        CREATE TABLE gold_region_profile AS
        SELECT region, year, CAST(beneficiaries AS BIGINT) AS beneficiaries FROM s
    """)
    g.execute("""
        CREATE TABLE gold_cost AS
        SELECT region, year, 'total'      AS service_category, tot_pc/12   AS pmpm FROM s
        UNION ALL SELECT region, year, 'inpatient',  ip_pc/12    FROM s
        UNION ALL SELECT region, year, 'outpatient', op_pc/12    FROM s
        UNION ALL SELECT region, year, 'snf',        snf_pc/12   FROM s
        UNION ALL SELECT region, year, 'home_health',hh_pc/12    FROM s
        UNION ALL SELECT region, year, 'hospice',    hospc_pc/12 FROM s
    """)
    g.execute("""
        CREATE TABLE gold_anomaly AS
        WITH base AS (SELECT region, year, readmit_pct, ed_per_1k FROM s),
        stats AS (
            SELECT year,
                   avg(readmit_pct) m_r, stddev_pop(readmit_pct) s_r,
                   avg(ed_per_1k)   m_e, stddev_pop(ed_per_1k)   s_e
            FROM base GROUP BY year
        )
        SELECT b.region, b.year, 'readmit_pct' AS metric,
               (b.readmit_pct - st.m_r) / NULLIF(st.s_r, 0) AS anomaly_score
        FROM base b JOIN stats st USING (year)
        UNION ALL
        SELECT b.region, b.year, 'ed_per_1k',
               (b.ed_per_1k - st.m_e) / NULLIF(st.s_e, 0)
        FROM base b JOIN stats st USING (year)
    """)
    g.execute("DROP TABLE s")
    for t in ("gold_utilization", "gold_cost", "gold_region_profile", "gold_anomaly"):
        c = g.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
        print(f"  {t}: {c} rows")
    g.close()
    print(f"gold built -> {GOLD_DB}")


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit("usage: python build_medallion.py [inspect|bronze|silver|gold] [csv_path]")
    cmd = sys.argv[1]
    if cmd in ("inspect", "bronze"):
        if len(sys.argv) < 3:
            sys.exit(f"usage: python build_medallion.py {cmd} <csv_path>")
        (inspect if cmd == "inspect" else bronze)(sys.argv[2])
    elif cmd == "silver":
        silver()
    elif cmd == "gold":
        gold()
    else:
        sys.exit(f"unknown command: {cmd}")


if __name__ == "__main__":
    main()
