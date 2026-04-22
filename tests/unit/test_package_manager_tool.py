from __future__ import annotations

import pytest

from src.tools.package_manager import PackageManagerQueryTool


def test_package_manager_invalid_action() -> None:
    t = PackageManagerQueryTool()
    r = t.execute({"action": "install", "name": "requests"})
    assert r.success is False


def test_package_manager_list() -> None:
    t = PackageManagerQueryTool()
    r = t.execute({"action": "list"})
    assert r.success is True
    assert isinstance(r.output, dict)
    assert "packages" in r.output


def test_package_manager_info_requires_name() -> None:
    t = PackageManagerQueryTool()
    r = t.execute({"action": "info"})
    assert r.success is False


def test_package_manager_search_requires_name() -> None:
    t = PackageManagerQueryTool()
    r = t.execute({"action": "search"})
    assert r.success is False


def test_package_manager_rejects_unsafe_name() -> None:
    t = PackageManagerQueryTool()
    r = t.execute({"action": "info", "name": "requests; rm -rf /"})
    assert r.success is False

