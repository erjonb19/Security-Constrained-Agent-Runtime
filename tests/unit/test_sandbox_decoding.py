"""
Phase 0 (PR-1) — verify the Docker sandbox subprocess wrapper survives
non-UTF8 bytes on stdout/stderr.

On Windows hosts, Python's `subprocess.run(text=True)` decodes child output
using the OEM/ANSI codepage (e.g. cp1252). Docker images can emit bytes
that are valid UTF-8 but not valid cp1252, which previously crashed the
runtime mid-execution with a `UnicodeDecodeError` raised from a daemon
thread inside the `subprocess` module.

`run_tool_in_docker` now captures bytes and decodes with
`errors="replace"`. This test injects fabricated, undecodable bytes and
asserts that the wrapper returns a structured `ToolResult(success=False)`
instead of raising.
"""
from __future__ import annotations

from typing import Any, Dict
import subprocess

import pytest

import src.runtime.sandbox as sandbox_module
from src.runtime.sandbox import SandboxConfig, run_tool_in_docker, _decode


class _FakeProc:
    """Stand-in for `subprocess.CompletedProcess` carrying raw bytes."""

    def __init__(self, returncode: int, stdout: bytes, stderr: bytes) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_decode_handles_non_utf8_bytes() -> None:
    # 0x81 / 0xFE / 0xFF are not valid as starting bytes in many codepages.
    raw = b"\x81\x82\x83\xfe\xff"
    decoded = _decode(raw)
    assert isinstance(decoded, str)
    # No exception, and the replacement char must appear instead of bytes.
    assert "\ufffd" in decoded


def test_decode_passes_through_str() -> None:
    assert _decode("already text") == "already text"
    assert _decode(None) == ""


def test_run_tool_in_docker_does_not_crash_on_non_utf8_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Pretend the sandbox image is already present.
    monkeypatch.setattr(
        sandbox_module,
        "ensure_sandbox_image",
        lambda image=sandbox_module.SANDBOX_IMAGE: (True, "ok"),
    )

    captured: Dict[str, Any] = {}

    def fake_run(cmd, *args: Any, **kwargs: Any) -> _FakeProc:
        # Record the kwargs the wrapper used so we can assert byte mode.
        captured["cmd"] = cmd
        captured["text"] = kwargs.get("text", True)
        captured["input_type"] = type(kwargs.get("input")) if "input" in kwargs else None
        # Non-zero exit + non-UTF8 stderr previously crashed the host on Windows.
        return _FakeProc(returncode=1, stdout=b"\x81\x82\x83", stderr=b"\xff\xfe boom")

    monkeypatch.setattr(subprocess, "run", fake_run)

    cfg = SandboxConfig(network="none")
    result = run_tool_in_docker("http.fetch", {"url": "https://api.github.com/"}, cfg)

    assert result.success is False
    assert result.error == "Sandboxed tool failed."
    assert isinstance(result.output, dict)
    # stdout/stderr must be decoded into strings (with replacement chars), not bytes.
    assert isinstance(result.output["stdout"], str)
    assert isinstance(result.output["stderr"], str)
    # And the wrapper must have used byte mode + bytes stdin, never text=True.
    assert captured["text"] is False
    assert captured["input_type"] is bytes


def test_run_tool_in_docker_returns_result_when_subprocess_yields_garbage_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sandbox_module,
        "ensure_sandbox_image",
        lambda image=sandbox_module.SANDBOX_IMAGE: (True, "ok"),
    )

    def fake_run(cmd, *args: Any, **kwargs: Any) -> _FakeProc:
        # Exit cleanly but stdout is non-JSON binary noise.
        return _FakeProc(returncode=0, stdout=b"\x81not json\x82", stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)

    cfg = SandboxConfig(network="none")
    result = run_tool_in_docker("http.fetch", {"url": "https://api.github.com/"}, cfg)

    assert result.success is False
    assert result.error and "non-JSON" in result.error
