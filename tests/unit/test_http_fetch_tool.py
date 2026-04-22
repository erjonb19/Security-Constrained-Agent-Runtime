from __future__ import annotations

from typing import Any, Dict

import pytest

from src.tools.http_fetch import HttpFetchTool


class _FakeResponse:
    def __init__(self, status_code: int = 200, headers: Dict[str, str] | None = None, chunks: list[bytes] | None = None):
        self.status_code = status_code
        self.headers = headers or {"content-type": "text/plain"}
        self._chunks = chunks or [b"ok"]

    def iter_content(self, chunk_size: int = 8192):
        for c in self._chunks:
            yield c


def test_http_fetch_requires_url() -> None:
    t = HttpFetchTool()
    r = t.execute({})
    assert r.success is False
    assert "url" in (r.error or "").lower()


def test_http_fetch_invalid_method() -> None:
    t = HttpFetchTool()
    r = t.execute({"url": "https://example.com", "method": "PUT"})
    assert r.success is False


def test_http_fetch_enforces_max_response_size(monkeypatch: pytest.MonkeyPatch) -> None:
    t = HttpFetchTool()

    def fake_request(method: str, url: str, stream: bool, timeout: float):
        return _FakeResponse(status_code=200, chunks=[b"a" * 10, b"b" * 10])

    import src.tools.http_fetch as mod

    monkeypatch.setattr(mod.requests, "request", fake_request)
    r = t.execute({"url": "https://example.com", "method": "GET", "max_response_size": 15})
    assert r.success is False
    assert "max_response_size" in (r.error or "")


def test_http_fetch_success_returns_text(monkeypatch: pytest.MonkeyPatch) -> None:
    t = HttpFetchTool()

    def fake_request(method: str, url: str, stream: bool, timeout: float):
        return _FakeResponse(status_code=200, chunks=[b"hello", b" ", b"world"])

    import src.tools.http_fetch as mod

    monkeypatch.setattr(mod.requests, "request", fake_request)
    r = t.execute({"url": "https://example.com"})
    assert r.success is True
    assert isinstance(r.output, dict)
    assert r.output.get("text") == "hello world"

