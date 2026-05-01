"""
Phase 2 (PR-3) -- adversarial realism: jailbreak corpus tests.

WHAT THIS TEST DOES
-------------------
Loads two adversarial corpora from ``tests/security/data/`` and runs each
prompt through two probes:

1. **Detector probe.** Pure pattern check via
   :class:`src.security.injection_detector.InjectionDetector` with the
   default ``medium`` sensitivity, scanning the prompt as a ``git`` parameter
   (the strict tier in the detector). This isolates whether the static
   pattern set catches the payload.

2. **Runtime probe.** End-to-end check via
   :meth:`src.runtime.agent_runtime.AgentRuntime.execute_tool` against the
   example policy ``examples/policies/Policy.yaml``, with the prompt placed
   in the ``message`` field of a stub ``git`` tool. A prompt is considered
   "blocked at runtime" if either:

   - the runtime returns ``allowed=False``, or
   - the call fails parameter validation / injection scanning before the
     tool runs.

We compute the **per-category block rate** for each probe, then assert
against per-category targets in ``tests/security/data/coverage_targets.json``
using :func:`tests.security._metrics.assert_meets_targets`.

PASS / FAIL SEMANTICS
---------------------
This is a **regression metric**, not a per-prompt assertion. It deliberately
does not claim adaptive jailbreak resistance (see
``tex/final_tex/limitations.tex``). The targets in
``coverage_targets.json`` are tuned conservatively to whatever the current
detector actually achieves; CI fails when the rate drops below those floors.

A per-run summary is written to
``tests/security/data/_last_run_summary.json`` for triage; this file is
informational only and is not consumed by CI.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

import pytest

import src.tools.base as _tool_base
from src.runtime.agent_runtime import AgentRuntime
from src.security.injection_detector import InjectionDetector
from src.tools.base import BaseTool, ToolResult

from tests.security._metrics import (
    assert_meets_targets,
    per_category,
    per_category_counts,
)


# ---------------------------------------------------------------------------
# Constants / paths
# ---------------------------------------------------------------------------

DATA_DIR = Path(__file__).resolve().parent / "data"
HANDCRAFTED_PATH = DATA_DIR / "jailbreak_handcrafted.jsonl"
PUBLIC_SUBSET_PATH = DATA_DIR / "jailbreak_public_subset.jsonl"
TARGETS_PATH = DATA_DIR / "coverage_targets.json"
SUMMARY_PATH = DATA_DIR / "_last_run_summary.json"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clear_tool_registry():
    """Tool registry is process-global; isolate each test."""
    _tool_base._TOOL_REGISTRY.clear()
    yield
    _tool_base._TOOL_REGISTRY.clear()


class _StubGitTool(BaseTool):
    """Stub `git` tool. We never expect execute() to run for jailbreak prompts."""

    @property
    def name(self) -> str:
        return "git"

    def execute(self, params: Dict[str, Any]) -> ToolResult:
        return ToolResult(success=True, output="stub")


def _runtime(policy_yaml_path: Path) -> AgentRuntime:
    rt = AgentRuntime(approval_callback=lambda *_: True)
    rt.load_policy(policy_yaml_path)
    rt.register_tool(_StubGitTool())
    return rt


# ---------------------------------------------------------------------------
# Corpus loader
# ---------------------------------------------------------------------------

def _load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                pytest.fail(f"{path.name}: invalid JSON line: {exc}: {line!r}")
            rows.append(obj)
    return rows


def _load_corpus() -> List[Dict[str, Any]]:
    rows = _load_jsonl(HANDCRAFTED_PATH) + _load_jsonl(PUBLIC_SUBSET_PATH)
    # sanity: every row has the keys we use
    for r in rows:
        for k in ("id", "category", "prompt", "expected"):
            assert k in r, f"row missing field {k!r}: {r!r}"
        assert r["expected"] == "block", (
            f"row {r['id']} has unexpected expected={r['expected']!r}; "
            "this suite only handles attacks (block)."
        )
    return rows


def _load_targets() -> Dict[str, Dict[str, float]]:
    with TARGETS_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _runtime_blocks(rt: AgentRuntime, prompt: str) -> bool:
    """Return True if the runtime blocks ``git`` with this prompt as message."""
    result = rt.execute_tool("git", {"message": prompt})
    if not result.allowed:
        return True
    # Ran but failed structurally (defense-in-depth at the tool layer).
    if result.result is not None and not result.result.success:
        return True
    return False


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def _write_summary(summary: Dict[str, Any]) -> None:
    """Best-effort write; failures must never break the test."""
    try:
        SUMMARY_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    except OSError:
        # CI sandboxes may forbid writes; the summary is informational only.
        pass


def test_corpus_files_load_and_have_categories() -> None:
    """Smoke: both files parse, contain rows, and use known categories."""
    rows = _load_corpus()
    assert len(rows) >= 50, f"corpus too small: {len(rows)} rows"
    targets = _load_targets()
    known = set(targets["jailbreak_corpus"].keys())
    seen = {r["category"] for r in rows}
    unknown = seen - known
    assert not unknown, (
        f"corpus uses categories with no target in coverage_targets.json: {unknown!r}"
    )


def test_jailbreak_detector_meets_targets() -> None:
    """Detector probe: per-category block rate vs configured targets."""
    rows = _load_corpus()
    detector = InjectionDetector(sensitivity="medium")
    records: List[Dict[str, Any]] = []
    for row in rows:
        scan = detector.scan("git", {"message": row["prompt"]})
        records.append(
            {
                "id": row["id"],
                "category": row["category"],
                "source": row.get("source"),
                "blocked": scan.clean is False,
                "probe": "detector",
            }
        )

    actual = per_category(records)
    counts = per_category_counts(records)
    targets = _load_targets()["jailbreak_corpus"]

    # Write summary BEFORE asserting so it is available even on failure.
    _write_summary(
        {
            "probe": "detector",
            "total": len(records),
            "per_category_rate": actual,
            "per_category_counts": {k: list(v) for k, v in counts.items()},
            "missed": [r["id"] for r in records if not r["blocked"]],
        }
    )

    assert_meets_targets(
        actual,
        targets,
        label="jailbreak_corpus / detector probe",
        counts=counts,
    )


def test_jailbreak_runtime_meets_targets(policy_yaml_path: Path) -> None:
    """Runtime probe: per-category block rate vs configured targets.

    The runtime probe sends each prompt as a ``message`` parameter to the
    ``git`` tool registered against the example policy. We assert per-category
    block rates against the same target table; the runtime should be at least
    as strict as the bare detector since it also runs parameter validation.
    """
    rows = _load_corpus()
    rt = _runtime(policy_yaml_path)
    records: List[Dict[str, Any]] = []
    for row in rows:
        blocked = _runtime_blocks(rt, row["prompt"])
        records.append(
            {
                "id": row["id"],
                "category": row["category"],
                "source": row.get("source"),
                "blocked": blocked,
                "probe": "runtime",
            }
        )

    actual = per_category(records)
    counts = per_category_counts(records)
    targets = _load_targets()["jailbreak_corpus"]

    _write_summary(
        {
            "probe": "runtime",
            "total": len(records),
            "per_category_rate": actual,
            "per_category_counts": {k: list(v) for k, v in counts.items()},
            "missed": [r["id"] for r in records if not r["blocked"]],
        }
    )

    assert_meets_targets(
        actual,
        targets,
        label="jailbreak_corpus / runtime probe",
        counts=counts,
    )
