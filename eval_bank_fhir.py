"""
eval_bank_fhir.py
=================
Ground-truth evaluation cases for the FHIR clinical lakehouse.

Companion to eval_bank.py (which covers the CMS hospital-quality dataset). The
harness selects between them with EVAL_DATASET=fhir|hospital, matching the
dataset the analytics tool is actually connected to.

Same tiering, same comparison modes, same tie-break convention (ORDER BY the
measure, then a stable id ASC) so ranked answers are deterministic.

Schema (medallion/fhir_gold.duckdb, curated Gold views only):
  gold_patient      patient_id, gender, birth_date, is_deceased, marital_status,
                    city, state, postal_code, age_years
  gold_encounter    encounter_id, patient_id, gender, state, class_code,
                    encounter_type, start_date, end_date, length_of_stay_days,
                    age_at_encounter
  gold_condition    condition_id, patient_id, encounter_id, code_system, code,
                    condition_name, clinical_status, is_active, onset_date,
                    abatement_date, gender, state, age_at_onset
  gold_observation  observation_id, patient_id, encounter_id, category,
                    code_system, code, measure_name, value_num, value_unit,
                    effective_date, gender, state, age_at_observation
  gold_medication   medication_request_id, patient_id, encounter_id, code_system,
                    code, medication_name, status, authored_date, dosage_text,
                    gender, state
  gold_procedure    procedure_id, patient_id, encounter_id, code_system, code,
                    procedure_name, status, performed_date, gender, state

NOTE ON GRAIN: a patient can have many condition/observation/medication rows.
Questions about PATIENTS use COUNT(DISTINCT patient_id); questions about
RECORDS use COUNT(*). Several cases test exactly this distinction, because
getting it wrong is the most common clinical-analytics error.
"""

CASES = [
    # ===================== tier 1: simple aggregates =====================
    {
        "id": "f1_count_patients", "tier": 1,
        "question": "How many patients are in the dataset in total?",
        "reference_sql": "SELECT count(*) AS n FROM gold_patient",
        "mode": "scalar",
    },
    {
        "id": "f1_count_female", "tier": 1,
        "question": "How many patients are female?",
        "reference_sql": "SELECT count(*) AS n FROM gold_patient WHERE gender = 'female'",
        "mode": "scalar",
    },
    {
        "id": "f1_avg_age", "tier": 1,
        "question": "What is the average age of patients in years? Round to 1 decimal.",
        "reference_sql": "SELECT round(avg(age_years), 1) AS v FROM gold_patient",
        "mode": "scalar",
    },
    {
        "id": "f1_count_encounters", "tier": 1,
        "question": "How many encounters are recorded in total?",
        "reference_sql": "SELECT count(*) AS n FROM gold_encounter",
        "mode": "scalar",
    },
    {
        "id": "f1_count_active_conditions", "tier": 1,
        "question": "How many condition records are currently active?",
        "reference_sql": "SELECT count(*) AS n FROM gold_condition WHERE is_active",
        "mode": "scalar",
    },
    {
        "id": "f1_max_bmi", "tier": 1,
        "question": "What is the highest recorded Body Mass Index value?",
        "reference_sql": ("SELECT max(value_num) AS v FROM gold_observation "
                          "WHERE measure_name = 'Body Mass Index'"),
        "mode": "scalar",
    },

    # ===================== tier 2: filtered aggregates =====================
    {
        "id": "f2_count_hypertension_patients", "tier": 2,
        "question": "How many distinct patients have an active hypertension diagnosis?",
        "reference_sql": ("SELECT count(DISTINCT patient_id) AS n FROM gold_condition "
                          "WHERE condition_name = 'Hypertension' AND is_active"),
        "mode": "scalar",
    },
    {
        "id": "f2_count_emergency_encounters", "tier": 2,
        "question": "How many emergency encounters are there? Emergency encounters have class_code 'EMER'.",
        "reference_sql": "SELECT count(*) AS n FROM gold_encounter WHERE class_code = 'EMER'",
        "mode": "scalar",
    },
    {
        "id": "f2_avg_glucose", "tier": 2,
        "question": "What is the average Glucose value across all glucose observations? Round to 2 decimals.",
        "reference_sql": ("SELECT round(avg(value_num), 2) AS v FROM gold_observation "
                          "WHERE measure_name = 'Glucose'"),
        "mode": "scalar",
    },
    {
        "id": "f2_count_prediabetes", "tier": 2,
        "question": "How many distinct patients have a prediabetes diagnosis?",
        "reference_sql": ("SELECT count(DISTINCT patient_id) AS n FROM gold_condition "
                          "WHERE condition_name = 'Prediabetes'"),
        "mode": "scalar",
    },
    {
        "id": "f2_count_dialysis", "tier": 2,
        "question": "How many distinct patients have had a renal dialysis procedure? The procedure is named 'Renal dialysis (procedure)'.",
        "reference_sql": ("SELECT count(DISTINCT patient_id) AS n FROM gold_procedure "
                          "WHERE procedure_name = 'Renal dialysis (procedure)'"),
        "mode": "scalar",
    },
    {
        "id": "f2_avg_bmi_female", "tier": 2,
        "question": "What is the average Body Mass Index among female patients? Round to 2 decimals.",
        "reference_sql": ("SELECT round(avg(value_num), 2) AS v FROM gold_observation "
                          "WHERE measure_name = 'Body Mass Index' AND gender = 'female'"),
        "mode": "scalar",
    },

    # ===================== tier 3: rankings / ordered lists =====================
    {
        "id": "f3_top_conditions", "tier": 3,
        "question": ("List the 5 most frequently recorded condition names, most frequent first. "
                     "Return the condition_name."),
        "reference_sql": ("SELECT condition_name FROM gold_condition GROUP BY condition_name "
                          "ORDER BY count(*) DESC, condition_name ASC LIMIT 5"),
        "mode": "keyed", "key_columns": ["condition_name"],
    },
    {
        "id": "f3_top_medications", "tier": 3,
        "question": "List the 5 most frequently ordered medication names, most frequent first.",
        "reference_sql": ("SELECT medication_name FROM gold_medication GROUP BY medication_name "
                          "ORDER BY count(*) DESC, medication_name ASC LIMIT 5"),
        "mode": "keyed", "key_columns": ["medication_name"],
    },
    {
        "id": "f3_top_procedures", "tier": 3,
        "question": "List the 5 most frequently performed procedure names, most frequent first.",
        "reference_sql": ("SELECT procedure_name FROM gold_procedure GROUP BY procedure_name "
                          "ORDER BY count(*) DESC, procedure_name ASC LIMIT 5"),
        "mode": "keyed", "key_columns": ["procedure_name"],
    },
    {
        "id": "f3_oldest_patients", "tier": 3,
        "question": "List the patient_id of the 5 oldest patients by age in years, oldest first.",
        "reference_sql": ("SELECT patient_id FROM gold_patient WHERE age_years IS NOT NULL "
                          "ORDER BY age_years DESC, patient_id ASC LIMIT 5"),
        "mode": "keyed", "key_columns": ["patient_id"],
    },
    {
        "id": "f3_top_encounter_types", "tier": 3,
        "question": "List the 5 most common encounter_type values, most common first.",
        "reference_sql": ("SELECT encounter_type FROM gold_encounter WHERE encounter_type IS NOT NULL "
                          "GROUP BY encounter_type ORDER BY count(*) DESC, encounter_type ASC LIMIT 5"),
        "mode": "keyed", "key_columns": ["encounter_type"],
    },

    # ===================== tier 4: multi-condition / cross-table =====================
    {
        "id": "f4_htn_and_obesity", "tier": 4,
        "question": ("How many distinct patients have BOTH an active hypertension diagnosis AND a "
                     "recorded Body Mass Index above 30?"),
        "reference_sql": ("SELECT count(DISTINCT c.patient_id) AS n FROM gold_condition c "
                          "JOIN gold_observation o ON c.patient_id = o.patient_id "
                          "WHERE c.condition_name = 'Hypertension' AND c.is_active "
                          "AND o.measure_name = 'Body Mass Index' AND o.value_num > 30"),
        "mode": "scalar",
    },
    {
        "id": "f4_patients_most_encounters", "tier": 4,
        "question": "List the patient_id of the 5 patients with the most encounters, most first.",
        "reference_sql": ("SELECT patient_id FROM gold_encounter GROUP BY patient_id "
                          "ORDER BY count(*) DESC, patient_id ASC LIMIT 5"),
        "mode": "keyed", "key_columns": ["patient_id"],
    },
    {
        "id": "f4_emer_patient_count", "tier": 4,
        "question": ("How many distinct patients have had at least one emergency encounter "
                     "(class_code 'EMER')?"),
        "reference_sql": ("SELECT count(DISTINCT patient_id) AS n FROM gold_encounter "
                          "WHERE class_code = 'EMER'"),
        "mode": "scalar",
    },
    {
        "id": "f4_avg_glucose_prediabetic", "tier": 4,
        "question": ("Among patients who have a prediabetes diagnosis, what is the average Glucose "
                     "value? Round to 2 decimals."),
        "reference_sql": ("SELECT round(avg(o.value_num), 2) AS v FROM gold_observation o "
                          "WHERE o.measure_name = 'Glucose' AND o.patient_id IN "
                          "(SELECT patient_id FROM gold_condition WHERE condition_name = 'Prediabetes')"),
        "mode": "scalar",
    },
    {
        "id": "f4_dialysis_and_epogen", "tier": 4,
        "question": ("How many distinct patients have BOTH a renal dialysis procedure "
                     "('Renal dialysis (procedure)') AND an Epogen medication order (medication_name "
                     "contains 'Epogen')?"),
        "reference_sql": ("SELECT count(DISTINCT p.patient_id) AS n FROM gold_procedure p "
                          "JOIN gold_medication m ON p.patient_id = m.patient_id "
                          "WHERE p.procedure_name = 'Renal dialysis (procedure)' "
                          "AND m.medication_name LIKE '%Epogen%'"),
        "mode": "scalar",
    },

    # ===================== tier 5: hard / clinical reasoning =====================
    # These two cases are a PAIR, and they use viral sinusitis deliberately:
    # 1,237 records across 738 distinct patients (1.68x). Hypertension would NOT
    # work here -- it has exactly one record per patient, so a wrong answer would
    # score the same as a right one and the case would test nothing.
    # This is the most common clinical-analytics error: counting encounters or
    # diagnoses when the question asked about people.
    {
        "id": "f5_grain_records", "tier": 5,
        "question": ("How many condition RECORDS are there for viral sinusitis? Count every row, "
                     "not distinct patients. The condition is named 'Viral sinusitis (disorder)'."),
        "reference_sql": ("SELECT count(*) AS n FROM gold_condition "
                          "WHERE condition_name = 'Viral sinusitis (disorder)'"),
        "mode": "scalar",
    },
    {
        "id": "f5_grain_patients", "tier": 5,
        "question": ("How many DISTINCT PATIENTS have ever been diagnosed with viral sinusitis? "
                     "The condition is named 'Viral sinusitis (disorder)'."),
        "reference_sql": ("SELECT count(DISTINCT patient_id) AS n FROM gold_condition "
                          "WHERE condition_name = 'Viral sinusitis (disorder)'"),
        "mode": "scalar",
    },
    {
        "id": "f5_above_avg_bmi_patients", "tier": 5,
        "question": ("How many distinct patients have at least one Body Mass Index reading above the "
                     "overall average Body Mass Index across all readings?"),
        "reference_sql": ("SELECT count(DISTINCT patient_id) AS n FROM gold_observation "
                          "WHERE measure_name = 'Body Mass Index' AND value_num > "
                          "(SELECT avg(value_num) FROM gold_observation WHERE measure_name = 'Body Mass Index')"),
        "mode": "scalar",
    },
    {
        "id": "f5_elderly_active_conditions", "tier": 5,
        "question": ("Among patients aged 65 or older, how many distinct patients have at least one "
                     "active condition?"),
        "reference_sql": ("SELECT count(DISTINCT c.patient_id) AS n FROM gold_condition c "
                          "JOIN gold_patient p ON c.patient_id = p.patient_id "
                          "WHERE p.age_years >= 65 AND c.is_active"),
        "mode": "scalar",
    },
    {
        "id": "f5_condition_burden_top5", "tier": 5,
        "question": ("List the patient_id of the 5 patients with the highest number of DISTINCT active "
                     "condition names, highest first."),
        "reference_sql": ("SELECT patient_id FROM gold_condition WHERE is_active "
                          "GROUP BY patient_id "
                          "ORDER BY count(DISTINCT condition_name) DESC, patient_id ASC LIMIT 5"),
        "mode": "keyed", "key_columns": ["patient_id"],
    },
    {
        "id": "f5_emer_rate_by_gender", "tier": 5,
        "question": ("What percent of all encounters are emergency encounters (class_code 'EMER')? "
                     "Round to 2 decimals."),
        "reference_sql": ("SELECT round(100.0 * count(*) FILTER (WHERE class_code = 'EMER') "
                          "/ count(*), 2) AS v FROM gold_encounter"),
        "mode": "scalar",
    },
]

# Quick-gate subset for CI: one case per tier, spanning scalar and keyed modes.
SUBSET_IDS = {
    "f1_count_patients",
    "f2_count_hypertension_patients",
    "f3_top_conditions",
    "f4_htn_and_obesity",
    "f5_above_avg_bmi_patients",
}
