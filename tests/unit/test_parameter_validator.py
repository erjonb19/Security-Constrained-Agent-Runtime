"""Unit tests for src.security.parameter_validator (Phase 2.3)."""

import pytest

from src.security.parameter_validator import ValidationResult, validate


class TestPathTraversal:
    def test_rejects_dotdot_in_path(self) -> None:
        r = validate("filesystem.read", {"path": "../../../etc/passwd"}, {})
        assert r.valid is False
        assert r.constraint_violated == "paths"
        assert any("traversal" in e.lower() or ".." in e for e in r.errors)

    def test_accepts_simple_relative_path(self) -> None:
        r = validate("filesystem.read", {"path": "README.md"}, {})
        assert r.valid is True

    def test_rejects_null_byte(self) -> None:
        r = validate("filesystem.read", {"path": "a\x00b"}, {})
        assert r.valid is False


class TestPackageManagerOperations:
    def test_action_must_be_in_operations(self) -> None:
        r = validate(
            "package_manager.query",
            {"action": "install", "name": "x"},
            {"operations": ["list", "search", "info"]},
        )
        assert r.valid is False
        assert r.constraint_violated == "operations"

    def test_allowed_action(self) -> None:
        r = validate(
            "package_manager.query",
            {"action": "list"},
            {"operations": ["list", "search", "info"]},
        )
        assert r.valid is True


class TestHttpHttps:
    def test_http_url_when_policy_denies_http(self) -> None:
        r = validate(
            "http.fetch",
            {"url": "http://example.com/x"},
            {"endpoints": {"deny": ["http://**"]}},
        )
        assert r.valid is False
        assert r.constraint_violated == "endpoints"

    def test_https_allowed(self) -> None:
        r = validate(
            "http.fetch",
            {"url": "https://api.github.com/v1/x"},
            {"endpoints": {"deny": ["http://**"], "allow": ["https://**"]}},
        )
        assert r.valid is True
