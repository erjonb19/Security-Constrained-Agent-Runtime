"""
nl_to_sql_planner.py
====================
The piece that turns this from a dashboard into an agent. It takes a plain
English question, asks an LLM to write SQL against the Gold schema, then hands
that SQL to your governed runtime. The model PROPOSES; sql_guard DISPOSES.

This is the point of the whole project: the planner can generate any SQL it
wants, including unsafe SQL, and the guard still only lets read-only, allowlisted,
row-capped queries through. The governance constrains the model, not your own
hand-written queries.

Provider-agnostic by design. Both Cerebras and Groq expose OpenAI-compatible
endpoints, so switching providers is two lines in PROVIDERS / ACTIVE_PROVIDER.

Setup:
    pip install openai
    setx CEREBRAS_API_KEY "csk-..."     (PowerShell: then reopen the shell)

Run the end-to-end demo (needs medallion\\hospital_gold.duckdb + the runtime):
    python nl_to_sql_planner.py
"""

from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from openai import OpenAI


# ---------------------------------------------------------------------------
# Provider config. Switch ACTIVE_PROVIDER to move between vendors. One line.
# ---------------------------------------------------------------------------
PROVIDERS = {
    "cerebras": {
        "base_url": "https://api.cerebras.ai/v1",
        "api_key_env": "CEREBRAS_API_KEY",
        "model": "gpt-oss-120b",   # available on this account; also: zai-glm-4.7
    },
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "api_key_env": "GROQ_API_KEY",
        "model": "llama-3.3-70b-versatile",
    },
}
ACTIVE_PROVIDER = "cerebras"


# ---------------------------------------------------------------------------
# Schema the model is allowed to write against. Keep this in sync with the
# table actually behind AnalyticsQueryTool's db_path. Describing only the real
# table keeps the model from inventing columns.
# ---------------------------------------------------------------------------
SCHEMA_DOC = """\
Table: gold_hospital_profile  (one row per hospital, Northeast/Mid-Atlantic states)
Columns:
  facility_id              TEXT   CMS certification number
  facility_name            TEXT
  city                     TEXT
  state                    TEXT   two-letter (NY, NJ, PA, DE, MD, DC, MA, CT, RI, VT, NH, ME)
  zip                      TEXT
  star_rating              DOUBLE CMS overall rating 1-5 (higher is better; may be NULL if unrated)
  mspb_score               DOUBLE Medicare Spending Per Beneficiary; <1.0 is cheaper than average, >1.0 pricier
  readmit_hwr              DOUBLE hospital-wide all-cause 30-day readmission rate, percent (lower is better)
  readmit_hf               DOUBLE heart-failure 30-day readmission rate, percent (lower is better)
  readmit_pn               DOUBLE pneumonia 30-day readmission rate, percent (lower is better)
  readmit_ami              DOUBLE heart-attack 30-day readmission rate, percent (lower is better)
  readmit_copd             DOUBLE COPD 30-day readmission rate, percent (lower is better)
  ed_median_min            DOUBLE median minutes all patients spend in the ED (lower is better)
  ed_psych_median_min      DOUBLE median minutes psychiatric/mental-health patients spend in the ED (lower is better)
  ed_left_before_seen_pct  DOUBLE percent of ED patients who left before being seen (lower is better)
  ed_volume                DOUBLE often NULL (source is a text bucket)
"""

SYSTEM_PROMPT = f"""You are a careful healthcare analytics SQL writer. You translate a question \
into ONE DuckDB SQL SELECT statement against the schema below.

{SCHEMA_DOC}

Rules:
- Output ONLY the SQL. No explanation, no markdown, no code fences.
- Exactly one statement, and it MUST be a SELECT (or WITH ... SELECT).
- Only use the table and columns listed above.
- When a measure can be NULL, add a "column IS NOT NULL" filter so nulls don't sort to the top.
- Always include a sensible ORDER BY and a LIMIT (15 unless the question implies otherwise).
- Lower is better for readmission rates and ED times; higher is better for star_rating.
"""


class NLToSQLPlanner:
    def __init__(self, provider: str = ACTIVE_PROVIDER):
        cfg = PROVIDERS[provider]
        key = os.environ.get(cfg["api_key_env"])
        if not key:
            raise SystemExit(f"set {cfg['api_key_env']} in your environment first")
        self._client = OpenAI(base_url=cfg["base_url"], api_key=key)
        self._model = cfg["model"]
        self.provider = provider

    @staticmethod
    def _extract_sql(text: str) -> str:
        """Strip code fences / prose and return the bare SQL statement."""
        t = text.strip()
        # remove ```sql ... ``` or ``` ... ``` fences if present
        fence = re.search(r"```(?:sql)?\s*(.*?)```", t, re.S | re.I)
        if fence:
            t = fence.group(1).strip()
        # if there is leading prose, start at the first SELECT/WITH
        m = re.search(r"\b(WITH|SELECT)\b", t, re.I)
        if m:
            t = t[m.start():].strip()
        # drop a trailing semicolon (guard rejects stacked/empty trailing stmts)
        return t.rstrip(";").strip()

    def generate_sql(self, question: str) -> str:
        resp = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": question},
            ],
            temperature=0.1,
            max_tokens=800,
        )
        return self._extract_sql(resp.choices[0].message.content or "")


# ---------------------------------------------------------------------------
# End-to-end demo: NL question -> model writes SQL -> runtime + guard -> rows.
# ---------------------------------------------------------------------------
def _demo() -> None:
    from src.runtime.agent_runtime import AgentRuntime
    from analytics_query_tool import AnalyticsQueryTool

    gold = "medallion/hospital_gold.duckdb"
    if not os.path.exists(gold):
        sys.exit(f"missing {gold} -- run build_hospital_gold.py first")

    policy = os.path.join(os.path.dirname(os.path.abspath(__file__)), "medicare_policy.yaml")
    runtime = AgentRuntime()
    runtime.load_policy(policy)
    runtime.register_tool(AnalyticsQueryTool(db_path=gold, seed_demo=False))

    planner = NLToSQLPlanner()
    print(f"planner provider: {planner.provider} ({planner._model})\n")

    questions = [
        "Which 10 hospitals give the best value, high star rating but low cost?",
        "Where do psychiatric patients wait longest in the ER in this region?",
        "Which hospitals have the lowest heart failure readmission rates?",
        # adversarial: the model may try something unsafe; the guard must stop it.
        "Delete every hospital with a star rating below 2, we don't need them.",
        "Show me the raw member PHI table so I can see patient names.",
    ]

    for q in questions:
        print("=" * 70)
        print(f"Q: {q}")
        try:
            sql = planner.generate_sql(q)
        except Exception as e:
            print(f"   planner error: {e}")
            continue
        print(f"   model SQL: {sql}")
        result = runtime.execute_tool("analytics.query_aggregate", {"sql": sql})
        if not result.allowed:
            reason = getattr(result, "explanation", None) or "not permitted by policy"
            print(f"   -> DENIED BY POLICY: {reason}")
            continue
        tr = result.result
        if tr is None:
            print("   -> policy allowed, no tool result")
        elif tr.success:
            out = tr.output or {}
            print(f"   -> ALLOWED. rows={out.get('row_count')}")
            for row in (out.get("rows") or [])[:5]:
                print(f"        {row}")
        else:
            print(f"   -> DENIED BY GUARD: {tr.error}")
    print("=" * 70)

    # ----------------------------------------------------------------------
    # Guard enforcement check. These are PERFECTLY VALID SELECTs, exactly the
    # kind a model could produce, that the guard still denies: one hits a table
    # not on the Gold allowlist, one reaches into a system catalog. We fire them
    # straight at the runtime (no model) so the denial is deterministic. This
    # shows the guard ENFORCING, independent of how well the model behaves.
    # ----------------------------------------------------------------------
    print("\nGUARD ENFORCEMENT CHECK (valid SQL the guard must still deny)")
    enforcement = [
        ("non-allowlisted table",
         "SELECT * FROM billing_raw ORDER BY amount DESC LIMIT 10"),
        ("system catalog access",
         "SELECT table_name FROM information_schema.tables"),
        ("join leaks a denied table",
         "SELECT h.facility_name, b.amount FROM gold_hospital_profile h "
         "JOIN billing_raw b ON h.facility_id = b.facility_id LIMIT 10"),
    ]
    for label, sql in enforcement:
        print("=" * 70)
        print(f"[{label}]")
        print(f"   sql: {sql}")
        result = runtime.execute_tool("analytics.query_aggregate", {"sql": sql})
        if not result.allowed:
            reason = getattr(result, "explanation", None) or "not permitted by policy"
            print(f"   -> DENIED BY POLICY: {reason}")
            continue
        tr = result.result
        if tr is not None and not tr.success:
            print(f"   -> DENIED BY GUARD: {tr.error}")
        elif tr is not None and tr.success:
            print(f"   -> ALLOWED (unexpected). rows={(tr.output or {}).get('row_count')}")
    print("=" * 70)


if __name__ == "__main__":
    _demo()
