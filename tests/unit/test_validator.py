"""
Unit tests for src.policies.validator (plan §4.1).
"""

import pytest

from src.policies.validator import validate_policy, _validate_policy_schema_static, ToolValidatorV2, ValidationResult


class TestValidatePolicy:
    """Tests for validate_policy (schema validation)."""

    def test_valid_policy_passes(self, minimal_policy: dict) -> None:
        """Valid policy does not raise."""
        validate_policy(minimal_policy)

    def test_valid_full_policy_passes(self, policy_yaml_path) -> None:
        """Loaded YAML policy passes validation."""
        from src.policies.parser import load_policy
        policy = load_policy(policy_yaml_path)
        validate_policy(policy)

    def test_invalid_capability_non_bool_allowed_raises(self) -> None:
        """Policy with non-bool 'allowed' raises ValueError."""
        policy = {
            "version": "1.0",
            "default_policy": "deny",
            "capabilities": [{"name": "x", "allowed": "yes", "constraints": {}}],
        }
        with pytest.raises(ValueError) as exc_info:
            validate_policy(policy)
        assert "allowed" in str(exc_info.value).lower() or "non-bool" in str(exc_info.value).lower()

    def test_invalid_capability_missing_name_raises(self) -> None:
        """Policy with capability missing 'name' raises."""
        policy = {
            "version": "1.0",
            "default_policy": "deny",
            "capabilities": [{"allowed": True, "constraints": {}}],
        }
        with pytest.raises(ValueError):
            validate_policy(policy)

    def test_policy_not_dict_raises(self) -> None:
        """Policy that is not a dict raises."""
        with pytest.raises(ValueError):
            validate_policy([])
        with pytest.raises(ValueError):
            validate_policy("not a dict")

    def test_capabilities_not_list_raises(self) -> None:
        """Policy with capabilities not a list raises."""
        with pytest.raises(ValueError):
            validate_policy({"version": "1.0", "default_policy": "deny", "capabilities": {}})

    def test_max_file_size_can_be_str(self) -> None:
        """max_file_size as string (e.g. '10MB') is valid."""
        policy = {
            "version": "1.0",
            "default_policy": "deny",
            "capabilities": [
                {"name": "filesystem.read", "allowed": True, "constraints": {"max_file_size": "10MB"}},
            ],
        }
        validate_policy(policy)


class TestToolValidatorV2:
    """Tests for ToolValidatorV2 (runtime validation)."""

    def test_denied_capability_returns_not_allowed(self, minimal_policy: dict) -> None:
        """When capability is denied by policy, validate returns not allowed."""
        v = ToolValidatorV2(minimal_policy, base_workspace="/workspace", audit_log=False)
        result = v.validate("shell.execute", {})
        assert isinstance(result, ValidationResult)
        assert result.allowed is False
        assert "denied" in result.message.lower() or "not found" in result.message.lower()

    def test_unknown_capability_returns_not_allowed(self, minimal_policy: dict) -> None:
        """Unknown capability returns not allowed."""
        v = ToolValidatorV2(minimal_policy, base_workspace="/workspace", audit_log=False)
        result = v.validate("unknown.cap", {})
        assert result.allowed is False

    def test_invalid_schema_raises_on_init(self) -> None:
        """ToolValidatorV2 with invalid policy schema raises ValueError."""
        bad = {"capabilities": "not a list"}
        with pytest.raises(ValueError):
            ToolValidatorV2(bad, base_workspace="/workspace", audit_log=False)
