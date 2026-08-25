# CLAUDE.md — Security-Constrained-Agent-Runtime

## What this project is
A governed agentic AI runtime: a FastAPI NL-to-SQL service with a security guard layer, plus a Guarded MCP server (FastMCP) built on top. The planner is a LangGraph state graph — `plan` and `execute` nodes plus a `finish` node, with a conditional route edge out of `execute` (`_route` → back to `plan` or on to `finish`) that drives bounded self-correction: guard denials feed back into retries, with a retry cap.

> MCP server status: `mcp_server.py` is Milestone 1 — FastMCP over **stdio**, mediating every tool call through the real policy engine (`execute_tool`). Streamable HTTP + OAuth 2.1 are planned (docs/plan.md, docs/DESIGN.md), **not yet implemented** — do not claim they work.

Deployed at: https://governed-clinical-agent.onrender.com (API-key auth).
Repo: github.com/erjonb19/Security-Constrained-Agent-Runtime

## Architecture
- **API layer:** FastAPI service, API-key auth
- **Planner:** LangGraph state graph with bounded self-correction; multi-provider LLM abstraction selectable via `PLANNER_PROVIDER` (Cerebras gpt-oss-120b, Groq gpt-oss-120b, xAI/Grok, Anthropic). CI evals default to Groq (gpt-oss-120b, free tier). Notes: Groq's llama-3.3-70b-versatile is deprecated — do not reintroduce it. `xai` (`api.x.ai`, `XAI_API_KEY` starting `xai-`) is a *different vendor* from `groq` (`api.groq.com`, `GROQ_API_KEY` starting `gsk_`); don't conflate them.
- **Guard layer:** validates all generated SQL before execution. SELECT-only, table allow-list, row caps, PHI redaction.
- **Data layer:** backend-agnostic — LocalDuckDBBackend and DatabricksBackend. The query path (`AnalyticsQueryTool`) now routes execution through the selected backend (`DATA_BACKEND=databricks` switches to Delta); the guard still validates SQL first. The Databricks path is **wired but UNVERIFIED** — no workspace has been tested against; do not claim it works.
- **Web UI:** `web/index.html` served at `/ui` (root `/` redirects there) — a self-contained page calling `/query` and `/raw-sql` with `X-API-Key`.
- **Data:** CMS hospital-quality lakehouse in DuckDB (750 hospitals, 12 states) + FHIR lakehouse from 1,180 Synthea R4 bundles, medallion architecture
- **Human-in-the-loop:** approval checkpoint with SQLite persistence
- **Cost/latency tracking:** per-call and aggregate

## Hard rules — never violate
1. **Never bypass or weaken the guard layer.** All SQL goes through the validator. No raw execution paths, no debug backdoors left in code.
2. **SELECT-only** against data backends. No DDL/DML from the agent path.
3. **PHI protection stays intact.** Redaction logic must not be removed or short-circuited, even in tests.
4. **No real credentials or API keys in code, tests, or fixtures.** Env vars only.
5. **Push to the `myfork` remote**, never directly to upstream main.
6. **Schema and planner must agree.** Any change to database schema requires updating PLANNER_SCHEMA (and `SCHEMA_DOC` in `nl_to_sql_planner.py`) in the same commit — mismatch causes silent failures. The schema validator now exists (`schema_check.py`) and runs at graph startup (`agent_graph.py:103`, strict); exercise it by constructing the graph, e.g. `python eval_harness.py --graph` or `python agent_graph.py`. It raises on zero overlap and warns on partial overlap.

## Validation — required before reporting any task done
1. Run the full test suite: `pytest` (config in `pytest.ini`; runs `tests/` — `unit/`, `security/`, `integration/`, 26 files). Requires dev deps: `pip install -e ".[dev]"`. Quick guard-only check with no API calls: `python sql_guard.py` (adversarial harness).
2. Run both eval suites. Each needs `CEREBRAS_API_KEY` set and the Gold DBs built (`medallion/hospital_gold.duckdb`, `medallion/fhir_gold.duckdb`):
   - 35-case hospital eval: `python eval_harness.py`
   - 28-case FHIR eval: `$env:EVAL_DATASET="fhir"; python eval_harness.py`  (PowerShell; bash: `EVAL_DATASET=fhir python eval_harness.py`)
   - Add `--graph` to run through the self-correcting LangGraph path instead of single-shot. Env knobs: `EVAL_RUNS=N`, `EVAL_SUBSET=1` (quick tagged subset). Gate threshold is run-level accuracy ≥ 80% (`THRESHOLD` in `eval_harness.py`).
   - **Exit codes distinguish infra from regression:** `0` pass, `1` accuracy regression (real — investigate), `2` provider unavailable (inconclusive — the LLM provider returned 402/429/5xx for most runs; NOT a regression). Don't "fix" a code-2 run by touching eval cases — it means the provider was down.
   - **Provider + pacing:** CI evals run on Groq (gpt-oss-120b, free tier) by default; `--provider {cerebras,groq,xai,anthropic}` (or `PLANNER_PROVIDER`) switches, each needing that provider's API key. Groq's free tier is rate-limited (~30 RPM / 8K TPM / 1K RPD), so the workflows set `PLANNER_MIN_INTERVAL_SEC=12` (TPM is the binding limit); use `--min-interval <sec>` locally. Do not reintroduce the deprecated Groq `llama-3.3-70b-versatile` model.
3. All evals must pass ground-truth validation. If a case fails, fix or explain — never lower the threshold or delete the case to pass.
4. CI runs three workflows, all on Groq: `tests.yml` (pytest on push/PR — full unit/integration/security suite, minus 6 **deselected pre-existing failures** that need triage: 4 test-vs-code drift incl. a redaction one that must be fixed WITHOUT weakening redaction, and 2 that hardcode a Windows path so they only run on Windows), `eval-on-push.yml` (6-case hospital gate), and `eval-nightly.yml` (two jobs: 35-case hospital + 28-case FHIR, the latter building its Gold from Synthea with a cache). A task is not complete if any of these would fail. When you fix a deselected test, remove its `--deselect` in `tests.yml`.

## Development workflow
- PR-driven: changes go through a branch and PR, not direct commits to main
- Small, reviewable diffs preferred over large rewrites
- When adding features, mirror existing patterns (guard checks, eval cases, cost tracking hooks) rather than inventing new structures
- Every new capability gets eval cases added in the same PR

## Current roadmap (in priority order)
1. Reframe demo questions as provider workflows
2. Measure graph vs single-shot performance using the eval suite
3. RAG + vector retrieval over FHIR data
4. Databricks lift
5. Approval queue UI + expanded README
6. MCP server: Streamable HTTP transport + OAuth 2.1 (currently stdio, Milestone 1)

Done: schema validator (`schema_check.py`, catches PLANNER_SCHEMA/database drift — wired into graph startup).

## Conventions
- Python; follow existing code style in the repo
- DuckDB patterns already in use: memory caps and disk spill for large operations — keep them
- Config via environment variables, documented in README when added
