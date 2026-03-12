"""
Unit tests for src.runtime.capability (plan §4.1).
"""

import pytest

from src.runtime.capability import (
    FILESYSTEM_READ,
    FILESYSTEM_WRITE,
    GIT_COMMIT,
    SHELL_EXECUTE,
    HTTP_FETCH,
    ALL_CAPABILITIES,
    HIGH_RISK_CAPABILITIES,
    resolve_capability,
    is_high_risk,
    is_known_capability,
)


class TestConstants:
    """Tests for capability name constants."""

    def test_filesystem_read_value(self) -> None:
        assert FILESYSTEM_READ == "filesystem.read"

    def test_all_capabilities_contains_expected(self) -> None:
        assert FILESYSTEM_READ in ALL_CAPABILITIES
        assert FILESYSTEM_WRITE in ALL_CAPABILITIES
        assert GIT_COMMIT in ALL_CAPABILITIES
        assert SHELL_EXECUTE in ALL_CAPABILITIES
        assert HTTP_FETCH in ALL_CAPABILITIES

    def test_high_risk_contains_write_shell_http(self) -> None:
        assert FILESYSTEM_WRITE in HIGH_RISK_CAPABILITIES
        assert SHELL_EXECUTE in HIGH_RISK_CAPABILITIES
        assert HTTP_FETCH in HIGH_RISK_CAPABILITIES


class TestResolveCapability:
    """Tests for resolve_capability."""

    def test_returns_canonical_for_alias(self) -> None:
        assert resolve_capability("read_file") == FILESYSTEM_READ
        assert resolve_capability("commit") == GIT_COMMIT
        assert resolve_capability("fetch") == HTTP_FETCH

    def test_returns_self_for_known_capability(self) -> None:
        assert resolve_capability("filesystem.read") == FILESYSTEM_READ
        assert resolve_capability("shell.execute") == SHELL_EXECUTE

    def test_case_insensitive(self) -> None:
        assert resolve_capability("Read_File") == FILESYSTEM_READ
        assert resolve_capability("GIT_COMMIT") == GIT_COMMIT

    def test_unknown_returns_stripped_original(self) -> None:
        assert resolve_capability("unknown.tool") == "unknown.tool"
        assert resolve_capability("  custom.cap  ") == "custom.cap"

    def test_empty_returns_empty(self) -> None:
        assert resolve_capability("") == ""


class TestIsHighRisk:
    """Tests for is_high_risk."""

    def test_shell_execute_high_risk(self) -> None:
        assert is_high_risk("shell.execute") is True
        assert is_high_risk(SHELL_EXECUTE) is True

    def test_filesystem_write_high_risk(self) -> None:
        assert is_high_risk("filesystem.write") is True

    def test_filesystem_read_not_high_risk(self) -> None:
        assert is_high_risk("filesystem.read") is False

    def test_unknown_not_high_risk(self) -> None:
        assert is_high_risk("unknown.cap") is False

    def test_empty_false(self) -> None:
        assert is_high_risk("") is False


class TestIsKnownCapability:
    """Tests for is_known_capability."""

    def test_known_true(self) -> None:
        assert is_known_capability("filesystem.read") is True
        assert is_known_capability("http.fetch") is True

    def test_unknown_false(self) -> None:
        assert is_known_capability("unknown.cap") is False

    def test_empty_false(self) -> None:
        assert is_known_capability("") is False
