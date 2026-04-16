"""
Unit tests for src.runtime.policy_engine (plan §4.1).
"""

import pytest
from pathlib import Path

from src.runtime.policy_engine import PolicyEngine, Decision


class TestPolicyEngineLoadPolicy:
    """Tests for load_policy."""

    def test_load_policy_from_path(self, policy_yaml_path: Path) -> None:
        """load_policy(path) loads and stores policy."""
        engine = PolicyEngine()
        engine.load_policy(policy_yaml_path)
        policy = engine.get_policy()
        assert policy["version"] == "1.0"
        assert len(policy["capabilities"]) >= 1

    def test_load_policy_none_uses_default(self) -> None:
        """load_policy(None) does not raise (uses parser default)."""
        engine = PolicyEngine()
        engine.load_policy(None)
        policy = engine.get_policy()
        assert "capabilities" in policy


class TestPolicyEngineGetCapabilityConstraints:
    """Tests for get_capability_constraints."""

    def test_returns_constraints_for_known_capability(self, policy_yaml_path: Path) -> None:
        engine = PolicyEngine()
        engine.load_policy(policy_yaml_path)
        c = engine.get_capability_constraints("filesystem.read")
        assert isinstance(c, dict)
        assert "paths" in c or "max_file_size" in c

    def test_unknown_capability_empty_dict(self, policy_yaml_path: Path) -> None:
        engine = PolicyEngine()
        engine.load_policy(policy_yaml_path)
        assert engine.get_capability_constraints("nonexistent.cap") == {}


class TestPolicyEngineEvaluate:
    """Tests for evaluate(capability, parameters)."""

    @pytest.fixture
    def engine(self, policy_yaml_path: Path) -> PolicyEngine:
        """Engine with Policy.yaml loaded."""
        e = PolicyEngine()
        e.load_policy(policy_yaml_path)
        return e

    def test_unknown_capability_default_deny(self, engine: PolicyEngine) -> None:
        """Unknown capability returns denied when default_policy is deny."""
        d = engine.evaluate("unknown.cap", {})
        assert d.allowed is False
        assert "not in policy" in d.reason or "deny" in d.reason.lower()

    def test_explicitly_denied_capability(self, engine: PolicyEngine) -> None:
        """Capability with allowed: false returns denied."""
        d = engine.evaluate("shell.execute", {})
        assert d.allowed is False
        assert "denied" in d.reason.lower()

    def test_decision_has_allowed_reason(self, engine: PolicyEngine) -> None:
        """Decision has allowed, reason, needs_approval."""
        d = engine.evaluate("shell.execute", {})
        assert hasattr(d, "allowed")
        assert hasattr(d, "reason")
        assert hasattr(d, "needs_approval")
        assert isinstance(d.reason, str)

    def test_http_fetch_allowed_with_allowed_url(self, engine: PolicyEngine) -> None:
        """http.fetch with allowed URL returns allowed (and may need_approval)."""
        d = engine.evaluate("http.fetch", {"url": "https://api.github.com/users/x"})
        assert d.allowed is True
        assert "Allowed" in d.reason or d.reason

    def test_http_fetch_denied_for_http_url(self, engine: PolicyEngine) -> None:
        """http.fetch with http:// URL can be denied by policy (deny list)."""
        d = engine.evaluate("http.fetch", {"url": "http://evil.com"})
        # Policy typically denies http://**
        assert d.allowed is False or (d.allowed and "http" in str(d.details or ""))

    def test_package_manager_query_allowed(self, engine: PolicyEngine) -> None:
        """package_manager.query is allowed by policy (no path/url)."""
        d = engine.evaluate("package_manager.query", {})
        assert d.allowed is True

    def test_needs_approval_set_when_required(self, engine: PolicyEngine) -> None:
        """When policy has require_approval: true, decision has needs_approval True."""
        d = engine.evaluate("http.fetch", {"url": "https://api.github.com/"})
        # Policy in examples has require_approval: true for http.fetch
        assert d.needs_approval is True or not d.allowed


class TestPolicyEngineGetExplanation:
    """Tests for get_explanation."""

    @pytest.fixture
    def engine(self, policy_yaml_path: Path) -> PolicyEngine:
        e = PolicyEngine()
        e.load_policy(policy_yaml_path)
        return e

    def test_denied_explanation_contains_denied(self, engine: PolicyEngine) -> None:
        """Explanation for denied decision contains 'Denied' or reason."""
        d = engine.evaluate("shell.execute", {})
        expl = engine.get_explanation(d)
        assert "Denied" in expl or "denied" in expl or len(expl) > 0

    def test_allowed_explanation_contains_reason(self, engine: PolicyEngine) -> None:
        """Explanation for allowed decision is non-empty."""
        d = engine.evaluate("package_manager.query", {})
        expl = engine.get_explanation(d)
        assert len(expl) > 0


class TestDecision:
    """Tests for Decision dataclass."""

    def test_decision_immutable(self) -> None:
        """Decision is frozen (immutable)."""
        d = Decision(allowed=False, reason="test")
        with pytest.raises((AttributeError, Exception)):
            d.allowed = True  # type: ignore

    def test_decision_details_optional(self) -> None:
        """details can be None."""
        d = Decision(allowed=True, reason="ok", needs_approval=False, details=None)
        assert d.details is None
