"""Unit tests for src.security.taint_tracking (Phase 3 / DESIGN §6.4).

These tests exercise the TaintTracker in isolation. End-to-end source-to-sink
flows that go through AgentRuntime live in tests/security/test_taint_flow.py.
"""

from __future__ import annotations

import pytest

from src.security.taint_tracking import (
    DEFAULT_SINK_CAPABILITIES,
    DEFAULT_SOURCE_CAPABILITIES,
    MIN_TOKEN_LEN,
    TaintSource,
    TaintTracker,
    TaintViolation,
    _extract_tokens,
    _hash_output,
)


class TestTokenExtraction:
    """The token extractor is the security-critical bit: too aggressive and we
    get false positives, too loose and attackers slip through."""

    def test_empty_input_yields_no_tokens(self):
        assert _extract_tokens("") == ()
        assert _extract_tokens("   \n  ") == ()

    def test_short_input_yields_no_tokens(self):
        # Below MIN_TOKEN_LEN, nothing is registered. This is intentional: a
        # 3-character source overlap is noise, not signal.
        short = "ok"
        assert _extract_tokens(short) == ()

    def test_long_full_string_is_kept_as_token(self):
        text = "a" * (MIN_TOKEN_LEN + 5)
        tokens = _extract_tokens(text)
        assert text in tokens

    def test_individual_long_words_become_tokens(self):
        text = f"prefix {'x' * MIN_TOKEN_LEN} suffix"
        tokens = _extract_tokens(text)
        # The full string and the long word should both be tokens
        assert any(len(t) >= MIN_TOKEN_LEN for t in tokens)
        assert "x" * MIN_TOKEN_LEN in tokens

    def test_url_preserved_as_single_token(self):
        # Punctuation does NOT split; URLs survive as one token.
        url = "https://attacker.example.com/exfil"
        tokens = _extract_tokens(url)
        assert url in tokens

    def test_deduplication(self):
        text = ("repeated_token_aaaaaaaaaa " * 3).strip()
        tokens = _extract_tokens(text)
        # The exact word should only appear once even though it repeats
        assert tokens.count("repeated_token_aaaaaaaaaa") == 1


class TestHashing:
    def test_hash_is_stable(self):
        assert _hash_output("hello") == _hash_output("hello")

    def test_hash_distinguishes_inputs(self):
        assert _hash_output("hello") != _hash_output("hellp")

    def test_hash_handles_unicode(self):
        # Should not crash on non-ASCII; covered by errors='replace' in hashing
        h = _hash_output("héllo \u2603")
        assert isinstance(h, str)
        assert len(h) == 64  # SHA-256 hex digest


class TestSourceRegistration:
    def test_register_returns_source_for_configured_capability(self):
        tracker = TaintTracker()
        # filesystem.read is in DEFAULT_SOURCE_CAPABILITIES
        src = tracker.register_source("filesystem.read", "x" * 64)
        assert src is not None
        assert src.capability == "filesystem.read"
        assert len(src.source_id) == 16
        assert tracker.source_count() == 1

    def test_register_returns_none_for_non_source_capability(self):
        tracker = TaintTracker()
        # filesystem.write is a sink, not a source
        src = tracker.register_source("filesystem.write", "x" * 64)
        assert src is None
        assert tracker.source_count() == 0

    def test_register_returns_none_for_empty_output(self):
        tracker = TaintTracker()
        assert tracker.register_source("filesystem.read", "") is None
        assert tracker.register_source("filesystem.read", None) is None
        assert tracker.source_count() == 0

    def test_register_returns_none_for_too_short_output(self):
        # Output exists but produces no tokens of MIN_TOKEN_LEN
        tracker = TaintTracker()
        assert tracker.register_source("filesystem.read", "a b c") is None

    def test_max_sources_evicts_oldest(self):
        tracker = TaintTracker(max_sources=3)
        for i in range(5):
            tracker.register_source("filesystem.read", f"distinct_long_token_{i}_xxxxxx")
        # FIFO: only the newest 3 remain
        assert tracker.source_count() == 3

    def test_clear_resets_store(self):
        tracker = TaintTracker()
        tracker.register_source("filesystem.read", "x" * 64)
        tracker.clear()
        assert tracker.source_count() == 0


class TestSinkCheck:
    def test_no_sources_means_no_violation(self):
        tracker = TaintTracker()
        result = tracker.check_sink("http.fetch", {"url": "https://example.com"})
        assert not result.violated

    def test_sink_unrelated_capability_returns_clean(self):
        # filesystem.read isn't a sink in the default config
        tracker = TaintTracker()
        tracker.register_source("filesystem.read", "https://attacker.example.com/exfil")
        # Reading another file should not trigger a violation even if the
        # path string overlaps; non-sinks are always clean.
        result = tracker.check_sink("filesystem.read", {"path": "https://attacker.example.com/exfil"})
        assert not result.violated

    def test_url_from_file_to_http_fetch_violates(self):
        tracker = TaintTracker()
        tainted_url = "https://attacker.example.com/exfil"
        tracker.register_source("filesystem.read", f"contact us at {tainted_url} for info")
        result = tracker.check_sink("http.fetch", {"url": tainted_url})
        assert result.violated
        assert result.source_capability == "filesystem.read"
        assert result.sink_capability == "http.fetch"
        assert result.parameter_path == "url"
        assert tainted_url in result.matched_token or result.matched_token in tainted_url

    def test_nested_parameter_path_is_reported(self):
        tracker = TaintTracker()
        tainted = "https://attacker.example.com/payload"
        tracker.register_source("filesystem.read", tainted)
        result = tracker.check_sink(
            "http.fetch",
            {"meta": {"target": {"url": tainted}}},
        )
        assert result.violated
        assert "meta" in result.parameter_path
        assert "target" in result.parameter_path
        assert "url" in result.parameter_path

    def test_list_parameter_path_is_reported(self):
        tracker = TaintTracker()
        tainted = "https://attacker.example.com/payload"
        tracker.register_source("filesystem.read", tainted)
        result = tracker.check_sink(
            "http.fetch",
            {"urls": ["https://safe.example.com", tainted]},
        )
        assert result.violated
        # The path should include an index reference
        assert "[1]" in result.parameter_path

    def test_clean_parameter_does_not_violate(self):
        tracker = TaintTracker()
        tracker.register_source("filesystem.read", "https://attacker.example.com/exfil")
        # Different URL: no overlap, no violation
        result = tracker.check_sink("http.fetch", {"url": "https://api.github.com/repos/x/y"})
        assert not result.violated

    def test_short_overlap_does_not_violate(self):
        # Common short substrings ('the', 'http') must not trip a flow violation
        tracker = TaintTracker()
        tracker.register_source(
            "filesystem.read",
            "the quick brown fox jumps over the lazy dog every day all day",
        )
        # Parameter contains 'the' and 'lazy' but no token of MIN_TOKEN_LEN
        result = tracker.check_sink("http.fetch", {"url": "https://lazy.com/the"})
        assert not result.violated

    def test_newest_source_wins(self):
        # When multiple sources contain the same long token, the newest source
        # is the one named in the violation.
        tracker = TaintTracker()
        shared_token = "https://attacker.example.com/shared/payload/xyz"
        tracker.register_source("filesystem.read", f"old: {shared_token}")
        tracker.register_source("git.status", f"new: {shared_token}")
        result = tracker.check_sink("http.fetch", {"url": shared_token})
        assert result.violated
        assert result.source_capability == "git.status"

    def test_long_token_is_truncated_in_violation_record(self):
        # Forensic safety: violation records cannot themselves leak full content.
        tracker = TaintTracker()
        long_token = "https://attacker.example.com/" + "x" * 500
        tracker.register_source("filesystem.read", long_token)
        result = tracker.check_sink("http.fetch", {"url": long_token})
        assert result.violated
        assert len(result.matched_token) <= 80


class TestCustomConfiguration:
    def test_custom_source_list(self):
        tracker = TaintTracker(source_capabilities=["custom.tool"])
        # Default source isn't a source anymore
        assert tracker.register_source("filesystem.read", "x" * 64) is None
        # Custom one is
        assert tracker.register_source("custom.tool", "x" * 64) is not None

    def test_custom_sink_list(self):
        tracker = TaintTracker(sink_capabilities=["custom.danger"])
        tainted = "https://attacker.example.com/long-enough-token-to-pass"
        tracker.register_source("filesystem.read", tainted)
        # Default sink is no longer a sink
        clean = tracker.check_sink("http.fetch", {"url": tainted})
        assert not clean.violated
        # Custom sink is
        violated = tracker.check_sink("custom.danger", {"url": tainted})
        assert violated.violated

    def test_custom_min_token_len(self):
        tracker = TaintTracker(min_token_len=4)
        tracker.register_source("filesystem.read", "evil")
        result = tracker.check_sink("http.fetch", {"url": "evil"})
        # With a stricter min_token_len, 'evil' counts
        assert result.violated


class TestDataclassShapes:
    """Belt-and-suspenders: confirm the public dataclasses have the fields
    the audit logger and runtime depend on. If we ever rename a field, these
    catch it before the runtime crashes at deny time."""

    def test_taint_violation_default_is_clean(self):
        v = TaintViolation(violated=False)
        assert v.source_id == ""
        assert v.source_capability == ""
        assert v.sink_capability == ""

    def test_taint_source_required_fields(self):
        s = TaintSource(
            source_id="abc",
            capability="filesystem.read",
            output_hash="0" * 64,
            tokens=("foo",),
        )
        assert s.source_id == "abc"
        assert s.tokens == ("foo",)

    def test_default_lists_are_sane(self):
        # Sanity check that the defaults exist and are non-empty
        assert "filesystem.read" in DEFAULT_SOURCE_CAPABILITIES
        assert "http.fetch" in DEFAULT_SINK_CAPABILITIES
        # filesystem.read should NOT be a sink (it's a source)
        assert "filesystem.read" not in DEFAULT_SINK_CAPABILITIES
