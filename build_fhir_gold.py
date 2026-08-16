"""
build_fhir_gold.py
==================
Flattens ~1,180 nested Synthea FHIR R4 bundles (~295k resources) into a
queryable DuckDB lakehouse. This is the part that matters: a real bulk FHIR
export is deeply nested JSON with cross-resource references and coded values --
turning that into something an analyst (or an agent) can query is the actual
data-engineering work.

MEDALLION SHAPE (consistent with the CMS pipeline):

  BRONZE  faithful-to-FHIR tables, one per resource type. FHIR field names and
          structure preserved, plus the raw coding arrays. If a question needs a
          field the Gold did not surface, it is still here.

  GOLD    curated, analytics-friendly views: clean typed columns, resolved
          references, primary code + display lifted out of the CodeableConcept
          nesting, patient age computed, etc.

THE REAL ENGINEERING PROBLEMS THIS SOLVES
  1. REFERENCE RESOLUTION. FHIR references look like "urn:uuid:abc-123" or
     "Patient/abc-123". Both forms appear. Every resource points at its subject
     and encounter this way, so every reference must be normalized to a bare id
     before anything joins.
  2. CODEABLECONCEPT NESTING. A diagnosis is not a string -- it is
     code.coding[0].code + .system + .display, with an optional code.text.
     Three coding systems appear here: SNOMED (conditions/procedures),
     LOINC (observations), RxNorm (medications).
  3. POLYMORPHIC VALUES. Observation.value can be valueQuantity (number+unit),
     valueCodeableConcept (a code), or valueString. Real exports mix all three
     in the same table.
  4. VARYING CARDINALITY. name, address, telecom, category are arrays that may
     be absent, single, or multiple. Blind indexing crashes on real data.
  5. SCALE. ~295k resources means streaming file-by-file, not loading it all
     into memory.

Usage:
    python build_fhir_gold.py                 # full build
    python build_fhir_gold.py --limit 50      # quick iteration on 50 bundles
    python build_fhir_gold.py --inspect       # report row counts only

Output: medallion/fhir_gold.duckdb
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date, datetime

import duckdb

BUNDLE_DIR = os.path.join("data", "synthea", "fhir")
OUT_DIR = "medallion"
DB_PATH = os.path.join(OUT_DIR, "fhir_gold.duckdb")

WANTED = {"Patient", "Encounter", "Condition", "Observation",
          "Procedure", "MedicationRequest"}


# ---------------------------------------------------------------------------
# FHIR parsing helpers. Every one of these exists because real bundles break
# the naive version.
# ---------------------------------------------------------------------------

def ref_id(ref: dict | None) -> str | None:
    """Normalize a FHIR reference to a bare id.

    References appear as BOTH "urn:uuid:abc-123" and "Patient/abc-123" in the
    same export. Without normalizing, half your joins silently miss.
    """
    if not ref:
        return None
    s = ref.get("reference") if isinstance(ref, dict) else ref
    if not isinstance(s, str):
        return None
    if s.startswith("urn:uuid:"):
        return s[len("urn:uuid:"):]
    if "/" in s:
        return s.rsplit("/", 1)[1]
    return s


def coding(concept: dict | None) -> tuple[str | None, str | None, str | None]:
    """Lift (system, code, display) out of a CodeableConcept.

    A clinical concept is never a plain string in FHIR. It is
    code.coding[<n>].{system,code,display} with an optional code.text fallback.
    coding may be missing or empty -- both happen.
    """
    if not concept:
        return None, None, None
    codings = concept.get("coding") or []
    if codings:
        c = codings[0]
        return c.get("system"), c.get("code"), c.get("display") or concept.get("text")
    return None, None, concept.get("text")


def system_name(system: str | None) -> str | None:
    """Human-readable terminology name from the coding system URI."""
    if not system:
        return None
    s = system.lower()
    if "snomed" in s:
        return "SNOMED"
    if "loinc" in s:
        return "LOINC"
    if "rxnorm" in s:
        return "RxNorm"
    if "cvx" in s:
        return "CVX"
    if "icd" in s:
        return "ICD"
    return system.rsplit("/", 1)[-1][:24]


def obs_value(res: dict) -> tuple[float | None, str | None, str | None]:
    """Observation.value is POLYMORPHIC. Return (numeric, unit, text).

    valueQuantity -> number + unit; valueCodeableConcept -> coded text;
    valueString -> text. Real exports contain all three in one table, so a
    flattener that assumes valueQuantity loses a large share of the rows.
    """
    if "valueQuantity" in res:
        vq = res["valueQuantity"] or {}
        v = vq.get("value")
        return (float(v) if isinstance(v, (int, float)) else None), vq.get("unit"), None
    if "valueCodeableConcept" in res:
        _, _, disp = coding(res["valueCodeableConcept"])
        return None, None, disp
    if "valueString" in res:
        return None, None, res.get("valueString")
    return None, None, None


def first(seq, default=None):
    """Safe first element -- FHIR arrays are frequently absent or empty."""
    if not seq:
        return default
    try:
        return seq[0]
    except (IndexError, TypeError):
        return default


def patient_name(res: dict) -> tuple[str | None, str | None]:
    """name is an array of HumanName, each with an array of given names."""
    n = first(res.get("name")) or {}
    given = first(n.get("given"))
    return given, n.get("family")


def patient_address(res: dict) -> tuple[str | None, str | None, str | None]:
    a = first(res.get("address")) or {}
    return a.get("city"), a.get("state"), a.get("postalCode")


def synthea_extension(res: dict, url_fragment: str) -> str | None:
    """Synthea stores race/ethnicity in nested extensions."""
    for ext in res.get("extension") or []:
        if url_fragment in (ext.get("url") or ""):
            for sub in ext.get("extension") or []:
                vc = sub.get("valueCoding") or {}
                if vc.get("display"):
                    return vc["display"]
            if ext.get("valueString"):
                return ext["valueString"]
    return None


def to_date(s: str | None) -> str | None:
    """FHIR datetimes are ISO-ish with timezone; keep the date part."""
    if not s or not isinstance(s, str):
        return None
    return s[:10]


def age_at(birth: str | None, when: str | None) -> int | None:
    if not birth or not when:
        return None
    try:
        b = datetime.strptime(birth[:10], "%Y-%m-%d").date()
        w = datetime.strptime(when[:10], "%Y-%m-%d").date()
    except ValueError:
        return None
    return w.year - b.year - ((w.month, w.day) < (b.month, b.day))


# ---------------------------------------------------------------------------
# Extraction: one row-dict per resource type
# ---------------------------------------------------------------------------

def extract(res: dict, rows: dict) -> None:
    rt = res.get("resourceType")
    if rt not in WANTED:
        return
    rid = res.get("id")

    if rt == "Patient":
        given, family = patient_name(res)
        city, state, postal = patient_address(res)
        rows["patient"].append({
            "patient_id": rid,
            "given_name": given,
            "family_name": family,
            "gender": res.get("gender"),
            "birth_date": to_date(res.get("birthDate")),
            "deceased_date": to_date(res.get("deceasedDateTime")),
            "marital_status": (res.get("maritalStatus") or {}).get("text"),
            "city": city, "state": state, "postal_code": postal,
            "race": synthea_extension(res, "us-core-race"),
            "ethnicity": synthea_extension(res, "us-core-ethnicity"),
        })

    elif rt == "Encounter":
        period = res.get("period") or {}
        sys_, code, disp = coding(first(res.get("type")))
        rows["encounter"].append({
            "encounter_id": rid,
            "patient_id": ref_id(res.get("subject")),
            "status": res.get("status"),
            "class_code": (res.get("class") or {}).get("code"),
            "type_system": system_name(sys_), "type_code": code, "type_display": disp,
            "start_date": to_date(period.get("start")),
            "end_date": to_date(period.get("end")),
            "organization_id": ref_id(res.get("serviceProvider")),
        })

    elif rt == "Condition":
        sys_, code, disp = coding(res.get("code"))
        _, cs_code, _ = coding(res.get("clinicalStatus"))
        _, vs_code, _ = coding(res.get("verificationStatus"))
        rows["condition"].append({
            "condition_id": rid,
            "patient_id": ref_id(res.get("subject")),
            "encounter_id": ref_id(res.get("encounter")),
            "code_system": system_name(sys_), "code": code, "display": disp,
            "clinical_status": cs_code, "verification_status": vs_code,
            "onset_date": to_date(res.get("onsetDateTime")),
            "recorded_date": to_date(res.get("recordedDate")),
            "abatement_date": to_date(res.get("abatementDateTime")),
        })

    elif rt == "Observation":
        sys_, code, disp = coding(res.get("code"))
        num, unit, text = obs_value(res)
        _, _, cat = coding(first(res.get("category")))
        rows["observation"].append({
            "observation_id": rid,
            "patient_id": ref_id(res.get("subject")),
            "encounter_id": ref_id(res.get("encounter")),
            "category": cat,
            "code_system": system_name(sys_), "code": code, "display": disp,
            "value_num": num, "value_unit": unit, "value_text": text,
            "status": res.get("status"),
            "effective_date": to_date(res.get("effectiveDateTime")),
        })

    elif rt == "Procedure":
        sys_, code, disp = coding(res.get("code"))
        period = res.get("performedPeriod") or {}
        rows["procedure"].append({
            "procedure_id": rid,
            "patient_id": ref_id(res.get("subject")),
            "encounter_id": ref_id(res.get("encounter")),
            "code_system": system_name(sys_), "code": code, "display": disp,
            "status": res.get("status"),
            "performed_date": to_date(period.get("start") or res.get("performedDateTime")),
        })

    elif rt == "MedicationRequest":
        sys_, code, disp = coding(res.get("medicationCodeableConcept"))
        di = first(res.get("dosageInstruction")) or {}
        rows["medication_request"].append({
            "medication_request_id": rid,
            "patient_id": ref_id(res.get("subject")),
            "encounter_id": ref_id(res.get("encounter")),
            "code_system": system_name(sys_), "code": code, "display": disp,
            "status": res.get("status"), "intent": res.get("intent"),
            "authored_date": to_date(res.get("authoredOn")),
            "dosage_text": di.get("text"),
        })


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

TABLES = ["patient", "encounter", "condition", "observation",
          "procedure", "medication_request"]


def build(limit: int | None = None) -> None:
    if not os.path.isdir(BUNDLE_DIR):
        sys.exit(f"missing {BUNDLE_DIR} -- run fetch_synthea.py first")
    files = sorted(f for f in os.listdir(BUNDLE_DIR) if f.endswith(".json"))
    if limit:
        files = files[:limit]

    rows = {t: [] for t in TABLES}
    skipped = 0
    print(f"parsing {len(files)} bundles from {BUNDLE_DIR}")
    for i, fn in enumerate(files, 1):
        try:
            with open(os.path.join(BUNDLE_DIR, fn), encoding="utf-8") as f:
                bundle = json.load(f)
        except (json.JSONDecodeError, OSError):
            skipped += 1
            continue
        for entry in bundle.get("entry") or []:
            res = entry.get("resource") or {}
            try:
                extract(res, rows)
            except Exception:
                # one malformed resource must not kill a 295k-resource run
                skipped += 1
        if i % 100 == 0:
            print(f"  {i}/{len(files)} bundles", end="\r")
    print(f"  {len(files)}/{len(files)} bundles parsed"
          + (f" ({skipped} resources skipped)" if skipped else ""))

    os.makedirs(OUT_DIR, exist_ok=True)
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    con = duckdb.connect(DB_PATH)

    # ---- BRONZE: faithful per-resource tables ----
    print("\nwriting bronze tables:")
    for t in TABLES:
        data = rows[t]
        if not data:
            print(f"  bronze_{t:20} 0 rows (none found)")
            continue
        con.register("_tmp", _to_arrow(data))
        con.execute(f"CREATE TABLE bronze_{t} AS SELECT * FROM _tmp")
        con.unregister("_tmp")
        n = con.execute(f"SELECT count(*) FROM bronze_{t}").fetchone()[0]
        print(f"  bronze_{t:20} {n:>7} rows")

    # ---- DEDUPLICATE before joining ----
    # A duplicate primary key silently FANS OUT every downstream join and
    # corrupts every count in the Gold. Real exports produce duplicates via
    # merged records, re-exports, or overlapping bulk pulls. Dedupe first, and
    # report what was removed rather than hiding it.
    print("\ndeduplicating bronze on primary keys:")
    PKS = {
        "patient": "patient_id",
        "encounter": "encounter_id",
        "condition": "condition_id",
        "observation": "observation_id",
        "procedure": "procedure_id",
        "medication_request": "medication_request_id",
    }
    for t, pk in PKS.items():
        if not con.execute(
            "SELECT count(*) FROM information_schema.tables WHERE table_name = ?",
            [f"bronze_{t}"]).fetchone()[0]:
            continue
        before = con.execute(f"SELECT count(*) FROM bronze_{t}").fetchone()[0]
        con.execute(f"""
            CREATE OR REPLACE TABLE bronze_{t} AS
            SELECT * FROM bronze_{t} QUALIFY row_number() OVER (PARTITION BY {pk}) = 1
        """)
        after = con.execute(f"SELECT count(*) FROM bronze_{t}").fetchone()[0]
        if before != after:
            print(f"  bronze_{t:20} {before} -> {after}  ({before-after} duplicate {pk} removed)")
    print("  done")

    # ---- GOLD: curated analytics views ----
    print("\nbuilding gold tables:")

    con.execute("""
        CREATE TABLE gold_patient AS
        SELECT patient_id, given_name, family_name, gender, birth_date,
               deceased_date IS NOT NULL AS is_deceased,
               marital_status, city, state, postal_code,
               date_diff('year', CAST(birth_date AS DATE),
                         COALESCE(CAST(deceased_date AS DATE), CURRENT_DATE)) AS age_years
        FROM bronze_patient
    """)

    # encounters enriched with patient context + age at encounter
    con.execute("""
        CREATE TABLE gold_encounter AS
        SELECT e.encounter_id, e.patient_id, p.gender, p.state,
               e.class_code, e.type_display AS encounter_type,
               e.start_date, e.end_date,
               date_diff('day', CAST(e.start_date AS DATE), CAST(e.end_date AS DATE)) AS length_of_stay_days,
               date_diff('year', CAST(p.birth_date AS DATE), CAST(e.start_date AS DATE)) AS age_at_encounter
        FROM bronze_encounter e
        LEFT JOIN bronze_patient p USING (patient_id)
    """)

    # active diagnoses with patient context -- the care-coordination table
    con.execute("""
        CREATE TABLE gold_condition AS
        SELECT c.condition_id, c.patient_id, c.encounter_id,
               c.code_system, c.code, c.display AS condition_name,
               c.clinical_status, c.onset_date, c.abatement_date,
               c.abatement_date IS NULL AND c.clinical_status = 'active' AS is_active,
               p.gender, p.state,
               date_diff('year', CAST(p.birth_date AS DATE), CAST(c.onset_date AS DATE)) AS age_at_onset
        FROM bronze_condition c
        LEFT JOIN bronze_patient p USING (patient_id)
    """)

    # numeric observations only -- the measurable clinical facts
    con.execute("""
        CREATE TABLE gold_observation AS
        SELECT o.observation_id, o.patient_id, o.encounter_id,
               o.category, o.code_system, o.code, o.display AS measure_name,
               o.value_num, o.value_unit, o.effective_date,
               p.gender, p.state,
               date_diff('year', CAST(p.birth_date AS DATE), CAST(o.effective_date AS DATE)) AS age_at_observation
        FROM bronze_observation o
        LEFT JOIN bronze_patient p USING (patient_id)
        WHERE o.value_num IS NOT NULL
    """)

    con.execute("""
        CREATE TABLE gold_medication AS
        SELECT m.medication_request_id, m.patient_id, m.encounter_id,
               m.code_system, m.code, m.display AS medication_name,
               m.status, m.authored_date, m.dosage_text,
               p.gender, p.state
        FROM bronze_medication_request m
        LEFT JOIN bronze_patient p USING (patient_id)
    """)

    con.execute("""
        CREATE TABLE gold_procedure AS
        SELECT pr.procedure_id, pr.patient_id, pr.encounter_id,
               pr.code_system, pr.code, pr.display AS procedure_name,
               pr.status, pr.performed_date, p.gender, p.state
        FROM bronze_procedure pr
        LEFT JOIN bronze_patient p USING (patient_id)
    """)

    for t in ["gold_patient", "gold_encounter", "gold_condition",
              "gold_observation", "gold_medication", "gold_procedure"]:
        n = con.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
        print(f"  {t:22} {n:>7} rows")

    # data-quality gates: fail loudly, not silently
    print("\ndata quality:")
    orphan_enc = con.execute(
        "SELECT count(*) FROM bronze_encounter WHERE patient_id NOT IN "
        "(SELECT patient_id FROM bronze_patient)").fetchone()[0]
    unresolved = con.execute(
        "SELECT count(*) FROM bronze_observation WHERE patient_id IS NULL").fetchone()[0]
    coded = con.execute(
        "SELECT count(DISTINCT code_system) FROM bronze_condition "
        "WHERE code_system IS NOT NULL").fetchone()[0]
    print(f"  encounters with unresolvable patient ref: {orphan_enc}")
    print(f"  observations with null patient ref:       {unresolved}")
    print(f"  distinct coding systems in conditions:    {coded}")
    systems = con.execute(
        "SELECT code_system, count(*) c FROM bronze_observation "
        "WHERE code_system IS NOT NULL GROUP BY 1 ORDER BY c DESC").fetchall()
    print(f"  observation coding systems: {systems}")

    # FAN-OUT GATE: a gold table must never have MORE rows than its bronze
    # source. If it does, a join multiplied rows and every downstream number is
    # wrong. Fail loudly -- this is the failure mode that silently corrupts
    # analytics.
    print("\n  fan-out check (gold must not exceed bronze):")
    pairs = [("gold_encounter", "bronze_encounter"),
             ("gold_condition", "bronze_condition"),
             ("gold_procedure", "bronze_procedure"),
             ("gold_medication", "bronze_medication_request"),
             ("gold_patient", "bronze_patient")]
    fanout = False
    for gold, bronze in pairs:
        g = con.execute(f"SELECT count(*) FROM {gold}").fetchone()[0]
        b = con.execute(f"SELECT count(*) FROM {bronze}").fetchone()[0]
        flag = "FAN-OUT" if g > b else "ok"
        if g > b:
            fanout = True
        print(f"    {gold:22} {g:>7} vs bronze {b:>7}  {flag}")
    if fanout:
        print("\n  WARNING: join fan-out detected -- counts in the Gold are NOT trustworthy")

    con.close()
    print(f"\n-> {DB_PATH}")


def _to_arrow(rows: list[dict]):
    """Rows -> a DuckDB-registerable table without a pandas dependency."""
    import pyarrow as pa
    cols = {}
    keys = rows[0].keys()
    for k in keys:
        cols[k] = [r.get(k) for r in rows]
    return pa.table(cols)


def inspect_db() -> None:
    if not os.path.exists(DB_PATH):
        sys.exit(f"missing {DB_PATH} -- build it first")
    con = duckdb.connect(DB_PATH)
    for (name,) in con.execute(
            "SELECT table_name FROM information_schema.tables ORDER BY 1").fetchall():
        n = con.execute(f"SELECT count(*) FROM {name}").fetchone()[0]
        print(f"{name:24} {n:>8} rows")
    con.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, help="only parse the first N bundles")
    ap.add_argument("--inspect", action="store_true", help="report row counts only")
    args = ap.parse_args()
    if args.inspect:
        inspect_db()
    else:
        build(args.limit)


if __name__ == "__main__":
    main()
