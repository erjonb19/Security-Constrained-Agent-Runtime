# `tests/security/data/`

Adversarial test data for **Phase 2 (PR-3)** of `PHASED_CODE_UPDATE_PLAN_FROM_STAFF_FEEDBACK.md`.

## Files

### `jailbreak_handcrafted.jsonl`
Project-authored prompts spanning eight categories:

- `prompt_override` - "ignore previous instructions" style overrides
- `system_role_override` - fake `system:` / `[SYSTEM]` role injection
- `command_chain` - shell command chaining (`;`, `&&`, backticks, pipe-to-shell)
- `exfiltration` - "leak file X to URL Y"
- `obfuscation` - zero-width / RTL / base64-wrapped variants
- `unicode_homoglyph` - Cyrillic / fullwidth lookalikes for ASCII letters
- `delimiter_trick` - HTML/XML/code-fence wrappers
- `roleplay` - "pretend / imagine / act as" framing

Each row has `{id, category, prompt, expected, source}`.
`expected` is always `"block"` for this file. `source` is `"handcrafted"`.

### `jailbreak_public_subset.jsonl`
Prompts **modeled after** publicly documented attack taxonomies. We do **not**
verbatim-vendor any third-party dataset; every entry was rewritten from the
patterns described in:

- OWASP Top 10 for Large Language Model Applications (LLM01: Prompt Injection,
  LLM02: Insecure Output Handling, LLM06: Sensitive Information Disclosure,
  LLM08: Excessive Agency). Cited in `tex/final_tex/refs.bib` as
  `owasp_llm_top10`.
- Greshake et al., *Not What You've Signed Up For: Compromising Real-World
  LLM-Integrated Applications with Indirect Prompt Injection* (arXiv:2302.12173).
  Cited in `tex/final_tex/refs.bib` as `greshake2023not`.

`source` is set to either `owasp_llm01_modeled`, `owasp_llm02_modeled`,
`owasp_llm06_modeled`, `owasp_llm08_modeled`, or `greshake_indirect_modeled`,
so a reader can audit provenance per row. No copyrighted prompt text is
included verbatim.

### `coverage_targets.json`
Per-category minimum block rates the suite must hit. CI fails on regression
**below** the target, not on individual prompts. Targets start conservative
to reflect known limits of pure pattern-based detection (e.g. unicode
homoglyphs). Raise as `src/security/injection_detector.py` improves.

### `_last_run_summary.json`
Written by `test_jailbreak_corpus.py` and `test_param_mutations.py` as
informational output only (per-category block rates, sample size, missed
prompt IDs). Not consumed by CI. Safe to delete.

## Why a metric, not a hard pass?

Pattern-based detectors cannot catch every novel jailbreak; pretending
otherwise would be construct-invalid (see `tex/final_tex/limitations.tex`).
A per-category block-rate target gives us a regression net for the patterns
the detector **does** know about, while keeping the paper's claims honest
(see `tex/final_tex/evaluation.tex`).
