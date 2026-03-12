"""
Unit tests for src.policies.defaults (plan §4.1).
"""

import pytest

from src.policies.defaults import get_default_policy, get_development_policy


class TestGetDefaultPolicy:
    """Tests for get_default_policy."""

    def test_returns_dict(self) -> None:
        """Returns a dict."""
        policy = get_default_policy()
        assert isinstance(policy, dict)

    def test_has_version_default_policy_capabilities(self) -> None:
        """Has version, default_policy, capabilities keys."""
        policy = get_default_policy()
        assert "version" in policy
        assert "default_policy" in policy
        assert "capabilities" in policy

    def test_default_policy_is_deny(self) -> None:
        """default_policy is 'deny'."""
        policy = get_default_policy()
        assert policy["default_policy"] == "deny"

    def test_capabilities_empty(self) -> None:
        """Capabilities list is empty (no capabilities allowed)."""
        policy = get_default_policy()
        assert policy["capabilities"] == []


class TestGetDevelopmentPolicy:
    """Tests for get_development_policy."""

    def test_returns_dict(self) -> None:
        """Returns a dict."""
        policy = get_development_policy()
        assert isinstance(policy, dict)

    def test_has_version_default_policy_capabilities(self) -> None:
        """Has version, default_policy, capabilities."""
        policy = get_development_policy()
        assert policy["version"] == "1.0"
        assert policy["default_policy"] == "deny"
        assert isinstance(policy["capabilities"], list)

    def test_includes_expected_capabilities(self) -> None:
        """Includes filesystem.read, filesystem.write, shell.execute (denied), etc."""
        policy = get_development_policy()
        names = [c["name"] for c in policy["capabilities"]]
        assert "filesystem.read" in names
        assert "filesystem.write" in names
        assert "shell.execute" in names
        assert "http.fetch" in names
        assert "package_manager.query" in names

    def test_shell_execute_denied(self) -> None:
        """shell.execute is explicitly allowed: false."""
        policy = get_development_policy()
        for c in policy["capabilities"]:
            if c["name"] == "shell.execute":
                assert c["allowed"] is False
                break
        else:
            pytest.fail("shell.execute not found")

    def test_each_capability_has_name_allowed(self) -> None:
        """Each capability has name and allowed; constraints optional (dict when present)."""
        policy = get_development_policy()
        for cap in policy["capabilities"]:
            assert "name" in cap
            assert "allowed" in cap
            if "constraints" in cap:
                assert isinstance(cap["constraints"], dict)
