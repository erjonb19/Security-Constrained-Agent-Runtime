# Governed Clinical Agent

A governed natural-language analytics agent for healthcare data. You ask a question in plain English; a language model writes the SQL; and a capability-based security runtime decides whether that SQL is allowed to run before it ever touches the database. The model proposes, the guardrails dispose. It runs today over real CMS Medicare data, behind an HTTP API, with the full authorization decision returned in every response.

## Why this matters

Healthtech and care-navigation companies want to put an LLM in front of their data so staff and members can ask questions without writing SQL. The blocker is trust: a model can hallucinate a query, reach for a table it should never see, or be steered by a prompt injection into exfiltrating data. In healthcare that is not a bug, it is a compliance incident. Most "AI agent for healthcare data" projects build the chatbot and bolt on governance later, if at all. This one is built the other way around. The governance is the product, and the analytics agent is the proof that it works on real data. The guarantee it offers is simple: the agent can only ever run a read-only, allow-listed, row-capped query, no matter what the model is convinced to write.

## Architecture

The system is two layers: a reusable security runtime, and a reference application built on top of it.

**The security runtime** mediates every tool call an agent makes through a default-deny policy. Its components:

- **Policy engine** — risk-tiered, default-deny. Capabilities are autonomous, gated (require approval), or denied outright. Defined in `medicare_policy.yaml`.
- **SQL guard** (`sql_guard.py`) — an AST validator (sqlglot) that is the enforcement seam for agent-written SQL. SELECT-only, Gold-table allowlist, automatic row cap, no stacked statements, no catalog/system schemas, no file-reading functions. Denies fail closed.
- **Groundedness check** (`groundedness.py`) — verifies that every claim in a generated brief traces back to a real returned row, so the agent cannot state a number it did not retrieve.
- **Taint tracking** (`src/security/`) — blocks data from a tainted source flowing into a denied sink, the defense against prompt-injection-driven exfiltration.
- **Audit logger** — every decision (allow / deny / require-approval) is written to JSONL with capability, reason, and latency, the compliance trail.

**The reference application** is a governed CMS Medicare analytics agent:

- **NL-to-SQL planner** (`nl_to_sql_planner.py`) — turns a plain-English question into one DuckDB SELECT against the Gold schema. Provider-agnostic via an OpenAI-compatible client; defaults to Cerebras (`gpt-oss-120b`), one config line to switch to Groq.
- **Analytics tool** (`analytics_query_tool.py`) — runs the planner's SQL through the guard, then executes the validated query against the Gold lakehouse.
- **HTTP service** (`app.py`) — FastAPI. Natural-language and raw-SQL endpoints, API-key auth on the data routes, the governance decision returned in every response.
- **AIOps panel** (`aiops_panel.py`) — a Streamlit dashboard over the audit logs: outcomes by control, denial reasons, latency, decisions over time.

## The data

Built from public CMS data with a two-catalog fetcher (`fetch_cms.py`) and a DuckDB medallion pipeline (`build_hospital_gold.py`):

- **Hospital-profile Gold** (`gold_hospital_profile`) — 750 hospitals across twelve Northeast and Mid-Atlantic states, one row each, joined on CMS facility ID: overall star rating, Medicare spending per beneficiary, five condition-level 30-day readmission rates, and four ED-flow measures including median psychiatric ED wait time.
- **Geographic Gold** — region-level utilization, cost, and anomaly tables from the CMS Geographic Variation file.

Both are queried through the same guardrails.

## What it looks like

A natural-language request to `/query`:

```json
{ "question": "Which hospitals give the best value, high quality and low cost?" }
```

returns the SQL the model wrote, the SQL the guard actually ran, the decision, and the rows:

```json
{
  "allowed": true,
  "decided_by": "executed",
  "safe_sql": "SELECT facility_name, state, star_rating, mspb_score ... LIMIT 15",
  "row_count": 15,
  "rows": [ { "facility_name": "NEWTON-WELLESLEY HOSPITAL", "state": "MA", "star_rating": 5, "mspb_score": 0.88 } ]
}
```

A disallowed query, even one that is perfectly valid SQL, is refused at the boundary:

```json
{ "allowed": false, "decided_by": "guard", "reason": "table not on Gold allowlist: billing_raw" }
```

The model is also free to be adversarial. Asked to delete low-rated hospitals or read a PHI table, it never produces a query the guard will run; the guard's enforcement is demonstrated independently against valid-but-disallowed SQL that hits a non-allowlisted table or a system catalog.

## Run it

```bash
pip install -r requirements-api.txt
$env:CEREBRAS_API_KEY="..."     # the planner's model
$env:API_KEY="..."              # require a key on the data endpoints
uvicorn app:app --port 8000
```

Open `http://localhost:8000/docs` for the interactive API. `/health` reports readiness, `/schema` returns the queryable schema, `/query` takes natural language, `/raw-sql` takes guarded SQL.

The governed pipeline can also be exercised directly:

```bash
python nl_to_sql_planner.py      # NL question -> model SQL -> guard -> rows, plus the guard-enforcement check
python run_hospital_query.py     # the same four care-navigation queries through the runtime
```

## Scope and honest limitations

This is a working reference implementation, described plainly:

- It runs single-instance and serializes queries under a lock. Correct for one instance; horizontal scaling is future work.
- Auth is enforced when `API_KEY` is set, and the service runs open in dev mode when it is not (flagged loudly at startup and in `/health`). Always set the key before exposing it.
- The data is public CMS data. There is no PHI here, and the system is not yet hardened for PHI or production load.
- The Gold is built on demand, not on a schedule. A self-refreshing pipeline is on the roadmap.

## Roadmap

- Cloud lift: ADLS Gen2 + Databricks Workflows, repoint the analytics tool at a cloud Gold.
- Scheduled monthly data refresh via GitHub Actions, turning the pipeline self-maintaining.
- A thin query UI over the API for non-technical users.
- Fail-closed auth and per-key rate limiting before any public, sensitive deployment.

## License

MIT.
