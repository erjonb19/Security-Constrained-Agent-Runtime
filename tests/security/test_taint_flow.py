"""End-to-end taint-flow tests through AgentRuntime (Phase 3 / DESIGN §6.4).

These tests prove that:

1. A tool output from a configured *source* capability is registered as tainted
   when the call succeeds.
2. A subsequent call into a *sink* capability whose parameters contain the
   tainted substring is denied with a TAINT_VIOLATION audit event.
3. Calls that don't match (different content, different capability classes)
   are not affected.
4. The tracker can be disabled by passing ``taint_tracker=None`` to the runtime.

The unit-level tests for the TaintTracker module itself are in
tests/security/test_taint_tracking.py.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

import pytest

from src.runtime.agent_runtime import AgentRuntime
from src.runtime.audit_logger import AuditLogger, AuditEventType
from src.security.taint_tracking import TaintTracker
from src.tools.base import BaseTool, ToolResult, register_tool
from src.tools import base as _tool_base


# ---------------------------------------------------------------------------
# Registry isolation
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clear_tool_registry():
    _tool_base._TOOL_REGISTRY.clear()
    yield
    _tool_base._TOOL_REGISTRY.clear()


# ---------------------------------------------------------------------------
# Stub tools
# ---------------------------------------------------------------------------

class _OutputTool(BaseTool):
    """Tool whose output is a configurable string. Capability name configurable."""

    def __init__(self, capability: str, output: str) -> None:
        self._name = capability
        self._output = output

    @property
    def name(self) -> str:
        return self._name

    def execute(self, params: Dict[str, Any]) -> ToolResult:
        return ToolResult(success=True, output=self._output)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _runtime_with_policy(policy_yaml_path: Path, *, taint_tracker: Any = "default") -> AgentRuntime:
    """Build a runtime with the example policy. Default taint tracker, custom, or None.

    The example policy gates http.fetch and filesystem.write with require_approval=true,
    so we install an auto-approve callback. Without it, the test would never reach the
    taint layer — approval would deny first.
    """
    auto_approve = lambda cap, params: True
    if taint_tracker == "default":
        rt = AgentRuntime(approval_callback=auto_approve)
    else:
        rt = AgentRuntime(approval_callback=auto_approve, taint_tracker=taint_tracker)
    rt.load_policy(policy_yaml_path)
    return rt


def _drain_events(audit_logger: AuditLogger):
    audit_logger.flush()
    return audit_logger.query_events()


# ---------------------------------------------------------------------------
# Source-to-sink violations
# ---------------------------------------------------------------------------

class TestSourceToSinkViolations:
    """A tool output from a source capability flowing into a sink must be denied."""

    def test_filesystem_read_to_http_fetch_denies(self, policy_yaml_path: Path, tmp_path: Path) -> None:
        # Use a URL that the example policy WOULD allow (https://api.github.com/**)
        # so we know the taint layer — not the endpoint check — is what blocks.
        attacker_url = "https://api.github.com/repos/attacker/exfil-endpoint-very-long-token"
        register_tool(_OutputTool("filesystem.read", f"contact us at {attacker_url}"))
        # Sink: an HTTP fetch tool that would otherwise succeed
        register_tool(_OutputTool("http.fetch", "would have fetched"))

        log_dir = tmp_path / "audit"
        rt = _runtime_with_policy(policy_yaml_path)
        rt.audit_logger = AuditLogger(log_dir=log_dir, agent_id="test", enable_console=False)

        # 1) Read the file (source). This call succeeds and registers a taint source.
        read = rt.execute_tool("filesystem.read", {"path": "/Security-Constrained-Agent-Runtime/note.txt"})
        assert read.allowed, f"read should be allowed; got: {read.explanation}"

        # 2) Try to fetch the URL that came from the file. The tracker should block.
        fetch = rt.execute_tool("http.fetch", {"url": attacker_url})
        assert not fetch.allowed, "http.fetch with tainted URL must be denied"
        assert "tainted data flow" in fetch.explanation.lower() or "taint" in fetch.explanation.lower()

        # Audit: a TAINT_VIOLATION event should exist
        events = _drain_events(rt.audit_logger)
        taint_events = [e for e in events if e["event_type"] == AuditEventType.TAINT_VIOLATION.value]
        assert len(taint_events) == 1
        ev = taint_events[0]
        assert ev["capability"] == "http.fetch"
        assert ev["context"]["source_capability"] == "filesystem.read"
        assert ev["context"]["parameter_path"] == "url"
        # source_id is the 16-char prefix of the SHA-256 of the source output
        assert isinstance(ev["context"]["source_id"], str) and len(ev["context"]["source_id"]) == 16


class TestNoFalsePositives:
    """The tracker must not block legitimate workflows."""

    def test_unrelated_url_is_allowed(self, policy_yaml_path: Path, tmp_path: Path) -> None:
        register_tool(_OutputTool("filesystem.read", "https://api.github.com/repos/attacker/exfil-very-long-token"))
        register_tool(_OutputTool("http.fetch", "fetched OK"))

        rt = _runtime_with_policy(policy_yaml_path)
        rt.audit_logger = AuditLogger(log_dir=tmp_path / "audit", agent_id="test", enable_console=False)

        rt.execute_tool("filesystem.read", {"path": "/Security-Constrained-Agent-Runtime/note.txt"})

        # Different URL within the same allowed endpoint — no taint overlap with the source
        fetch = rt.execute_tool("http.fetch", {"url": "https://api.github.com/repos/owner/repo"})
        assert fetch.allowed, f"unrelated URL must not be flagged; got: {fetch.explanation}"

        events = _drain_events(rt.audit_logger)
        taint_events = [e for e in events if e["event_type"] == AuditEventType.TAINT_VIOLATION.value]
        assert taint_events == []

    def test_failed_source_does_not_register(self, policy_yaml_path: Path, tmp_path: Path) -> None:
        # If the source call fails, its content must NOT enter the taint store.
        # Otherwise an error message could spuriously match later parameters.
        long_url = "https://api.github.com/repos/owner/secret-token-very-long-string-here"

        class _FailingReader(BaseTool):
            @property
            def name(self) -> str:
                return "filesystem.read"

            def execute(self, params: Dict[str, Any]) -> ToolResult:
                return ToolResult(success=False, output=long_url, error="permission denied")

        register_tool(_FailingReader())
        register_tool(_OutputTool("http.fetch", "fetched"))

        rt = _runtime_with_policy(policy_yaml_path)

        rt.execute_tool("filesystem.read", {"path": "/Security-Constrained-Agent-Runtime/note.txt"})
        # Source did not register, so the same URL should pass
        fetch = rt.execute_tool("http.fetch", {"url": long_url})
        assert fetch.allowed, f"failed source must not poison the taint store; got: {fetch.explanation}"


class TestSourceCapabilityScope:
    """Only configured source capabilities feed the taint store."""

    def test_non_source_capability_output_is_not_tainted(self, policy_yaml_path: Path, tmp_path: Path) -> None:
        # package_manager.query is NOT a default source.
        # Its output must not poison subsequent http.fetch calls.
        register_tool(_OutputTool("package_manager.query", "see https://pypi.org/project/some-very-long-package-name-here/"))
        register_tool(_OutputTool("http.fetch", "ok"))

        rt = _runtime_with_policy(policy_yaml_path)

        rt.execute_tool("package_manager.query", {"operation": "list"})
        # The same URL appears in the parameter — but the source wasn't tracked
        fetch = rt.execute_tool("http.fetch", {"url": "https://pypi.org/project/some-very-long-package-name-here/"})
        assert fetch.allowed, "non-source capability output must not be tracked as taint"


class TestTrackerDisabled:
    """Passing taint_tracker=None turns the layer off."""

    def test_disabled_tracker_does_not_block(self, policy_yaml_path: Path, tmp_path: Path) -> None:
        attacker_url = "https://api.github.com/repos/owner/secret-very-long-token-here-xyz"
        register_tool(_OutputTool("filesystem.read", f"see {attacker_url}"))
        register_tool(_OutputTool("http.fetch", "fetched"))

        rt = _runtime_with_policy(policy_yaml_path, taint_tracker=None)

        rt.execute_tool("filesystem.read", {"path": "/Security-Constrained-Agent-Runtime/note.txt"})
        fetch = rt.execute_tool("http.fetch", {"url": attacker_url})
        # With the tracker disabled and approval auto-granted, this would have been
        # denied by the taint check if the layer were active. It is now allowed.
        assert fetch.allowed, f"disabled tracker should not block; got: {fetch.explanation}"
        assert "taint" not in fetch.explanation.lower()


class TestCustomTrackerConfig:
    """A caller can supply a custom tracker with different source/sink lists."""

    def test_custom_sink_list(self, policy_yaml_path: Path, tmp_path: Path) -> None:
        # Configure git.commit as a sink and filesystem.read as a source
        custom = TaintTracker(
            source_capabilities=["filesystem.read"],
            sink_capabilities=["git.commit"],
        )

        attacker_url = "https://attacker.example.com/long-suspicious-token-here"
        register_tool(_OutputTool("filesystem.read", attacker_url))
        register_tool(_OutputTool("git.commit", "committed"))

        rt = AgentRuntime(taint_tracker=custom, approval_callback=lambda c, p: True)
        rt.load_policy(policy_yaml_path)
        rt.audit_logger = AuditLogger(log_dir=tmp_path / "audit", agent_id="test", enable_console=False)

        rt.execute_tool("filesystem.read", {"path": "/Security-Constrained-Agent-Runtime/note.txt"})

        # Putting the tainted URL into a commit message should be denied by the custom sink.
        commit = rt.execute_tool("git.commit", {"message": f"Update: {attacker_url}"})
        assert not commit.allowed
        assert "taint" in commit.explanation.lower()

        events = _drain_events(rt.audit_logger)
        taint_events = [e for e in events if e["event_type"] == AuditEventType.TAINT_VIOLATION.value]
        assert len(taint_events) == 1
        assert taint_events[0]["capability"] == "git.commit"
