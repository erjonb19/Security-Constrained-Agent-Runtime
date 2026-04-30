"""
Phase 0 (PR-1) — smoke test for the Phase 5 evaluation runner.

This test imports `scripts/eval_phase5.py` as a module, monkeypatches the
network-dependent calls so it runs offline, and checks that the printed
summary now includes the new BTSR and ASR tokens alongside the existing
`block_rate`. The goal is *not* to validate evaluation numbers (that
belongs in a dedicated eval test); it is to make sure the script keeps
emitting the metric tokens the design report references.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, Iterable, List

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
EVAL_SCRIPT = REPO_ROOT / "scripts" / "eval_phase5.py"


def _load_eval_module() -> ModuleType:
    """Import scripts/eval_phase5.py as `eval_phase5_module` (cached)."""
    name = "eval_phase5_module"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, EVAL_SCRIPT)
    assert spec and spec.loader, f"could not load {EVAL_SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class _FakeResponse:
    def __init__(self, status_code: int = 200, chunks: Iterable[bytes] = (b"{}",)) -> None:
        self.status_code = status_code
        self.headers = {"content-type": "application/json"}
        self._chunks: List[bytes] = list(chunks)

    def iter_content(self, chunk_size: int = 64 * 1024) -> Iterable[bytes]:
        for c in self._chunks:
            yield c


def test_eval_phase5_summary_contains_btsr_asr_block_rate(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    # Force the in-process path; otherwise a Docker-enabled environment would
    # bypass our requests.request stub and try to launch a sandbox container.
    monkeypatch.delenv("AGENT_RUNTIME_USE_DOCKER_SANDBOX", raising=False)

    # Patch the network-touching tool to avoid real HTTP traffic.
    import src.tools.http_fetch as http_fetch_module

    monkeypatch.setattr(
        http_fetch_module.requests,
        "request",
        lambda method, url, **kwargs: _FakeResponse(),
    )

    # Avoid registry collisions if a prior test already registered defaults.
    import src.tools.base as _tool_base
    _tool_base._TOOL_REGISTRY.clear()

    eval_mod = _load_eval_module()

    # Point CLI at a temp audit dir to keep the workspace clean.
    audit_dir = tmp_path / "audit"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "eval_phase5.py",
            "--policy",
            str(REPO_ROOT / "examples" / "policies" / "Policy.yaml"),
            "--audit-log-dir",
            str(audit_dir),
            "--agent-id",
            "phase0_smoke",
        ],
    )

    rc = eval_mod.main()
    out = capsys.readouterr().out

    assert rc == 0
    assert "block_rate=" in out, "Existing block_rate token must be preserved."
    assert "btsr=" in out, "Phase 0 must add btsr= to the summary."
    assert "asr=" in out, "Phase 0 must add asr= to the summary."
    # Sanity-check the per-case label is also present so downstream parsers can
    # split benign vs attack outcomes if they want to.
    assert "kind=benign" in out
    assert "kind=attack" in out
