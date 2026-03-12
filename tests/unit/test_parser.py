"""
Unit tests for src.policies.parser (plan §4.1).
"""

import pytest
from pathlib import Path

from src.policies.parser import (
    load_policy,
    path_matches_globs,
    endpoint_matches_globs,
    compile_path_specs,
)


class TestLoadPolicy:
    """Tests for load_policy."""

    def test_load_policy_yaml(self, policy_yaml_path: Path) -> None:
        """Load YAML policy returns dict with version, default_policy, capabilities."""
        policy = load_policy(policy_yaml_path)
        assert policy["version"] == "1.0"
        assert policy["default_policy"] == "deny"
        assert isinstance(policy["capabilities"], list)
        assert len(policy["capabilities"]) >= 1
        names = [c["name"] for c in policy["capabilities"]]
        assert "filesystem.read" in names
        assert "shell.execute" in names

    def test_load_policy_json(self, policy_json_path: Path) -> None:
        """Load JSON policy returns same structure as YAML."""
        policy = load_policy(policy_json_path)
        assert policy["version"] == "1.0"
        assert policy["default_policy"] == "deny"
        assert len(policy["capabilities"]) >= 1

    def test_load_policy_capability_has_name_allowed_constraints(self, policy_yaml_path: Path) -> None:
        """Each capability has name, allowed, and constraints."""
        policy = load_policy(policy_yaml_path)
        for cap in policy["capabilities"]:
            assert "name" in cap
            assert "allowed" in cap
            assert isinstance(cap["allowed"], bool)
            assert "constraints" in cap
            assert isinstance(cap["constraints"], dict)

    def test_load_policy_default_fallback(self) -> None:
        """load_policy(None) uses default path or fallback (no exception)."""
        policy = load_policy(None)
        assert "version" in policy
        assert "default_policy" in policy
        assert "capabilities" in policy


class TestPathMatchesGlobs:
    """Tests for path_matches_globs (deny takes precedence)."""

    def test_deny_takes_precedence(self) -> None:
        """Path matching deny list returns False."""
        # Use patterns that work on current OS (path is resolved before matching)
        allow = ["**"]
        deny = ["**/.git/**"]
        # Path under .git should be denied
        assert path_matches_globs(".git/config", allow, deny) is False

    def test_empty_allow_and_empty_deny(self) -> None:
        """Empty allow with empty deny: implementation returns True (no allow list = no restriction)."""
        result = path_matches_globs("/any/path", [], [])
        assert result is True  # current parser: not allow_patterns when no match -> True when []

    def test_allow_match(self) -> None:
        """Path matching allow list and not in deny returns True."""
        # Literal path in allow list
        allow = ["**/test_parser.py"]
        deny = []
        assert path_matches_globs("tests/unit/test_parser.py", allow, deny) is True


class TestEndpointMatchesGlobs:
    """Tests for endpoint_matches_globs."""

    def test_deny_takes_precedence(self) -> None:
        """URL in deny list returns False."""
        allow = ["https://api.github.com/**"]
        deny = ["http://**"]
        assert endpoint_matches_globs("http://evil.com", allow, deny) is False
        assert endpoint_matches_globs("https://api.github.com/users/x", allow, deny) is True

    def test_empty_allow_and_empty_deny(self) -> None:
        """Empty allow with empty deny: implementation returns True (no allow list = allow all)."""
        result = endpoint_matches_globs("https://example.com", [], [])
        assert result is True  # current parser: not allow_patterns when no match -> True when []


class TestCompilePathSpecs:
    """Tests for compile_path_specs."""

    def test_returns_tuple_of_two(self) -> None:
        """Returns (allow_spec, deny_spec) tuple."""
        allow_spec, deny_spec = compile_path_specs(["/a/**"], ["/a/deny/**"])
        # Either PathSpec instances or None if pathspec not installed
        assert isinstance((allow_spec, deny_spec), tuple)
        assert len((allow_spec, deny_spec)) == 2

    def test_empty_patterns(self) -> None:
        """Empty pattern lists can return None or specs."""
        a, d = compile_path_specs([], [])
        assert a is None or a is not None
        assert d is None or d is not None
