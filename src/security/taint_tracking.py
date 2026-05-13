"""Taint tracking for agent tool outputs (plan Phase 6 stretch / DESIGN §6.4).

This module implements an MVP information-flow control layer that tracks data
flowing *between* tool calls within a single agent session. It complements the
existing pre-call defenses:

    Layer 1: Policy engine          — capability allowed?
    Layer 2: Approval                — does this need human sign-off?
    Layer 3: Parameter validator    — are parameters structurally safe?
    Layer 4: Injection detector     — do values contain malicious *patterns*?
    Layer 5: **Taint tracker**      — do values originate from an untrusted source?
    Layer 6: Tool implementation

Where the injection detector asks "is this string suspicious?", the taint
tracker asks a different question: "did this string come from a previous tool
output, and is the destination a high-risk sink?". The two layers are
orthogonal: a perfectly innocent-looking URL fetched from a previous file read
will pass the injection detector but trip the taint tracker if the agent then
tries to feed it to ``http.fetch``.

THREAT MODEL
------------
The attacker controls the *content* of some upstream resource the agent reads
(file, web page, prior HTTP response, git output). They cannot directly call
the runtime API, but they can hope the agent will:

  1. Read the malicious content with a low-risk capability (``filesystem.read``,
     ``http.fetch`` with a benign URL).
  2. Take some part of that content and pass it as a parameter to a high-risk
     capability (``filesystem.write``, ``git.commit``, ``git.push``,
     ``http.fetch`` with a new URL, ``shell.execute``).

This is the classical "confused deputy" pattern in the LLM era. The taint
tracker treats the act of moving data from an untrusted source into a
high-risk sink as itself a security event, regardless of whether the data
matches any known attack pattern.

DESIGN
------
* **Granularity**: token-level. Tool outputs are split into substrings of at
  least ``MIN_TOKEN_LEN`` characters, after stripping whitespace. We require
  exact substring containment for a parameter to be considered tainted.
  Shorter overlap is too noisy (random 3-char alignment will fire on
  legitimate workflows).
* **Scope**: process-local, per ``TaintTracker`` instance. The runtime owns
  one tracker per agent session. Cross-session taint persistence is out of
  scope for the MVP and would require a serialized store.
* **Memory bound**: each tracker keeps at most ``MAX_SOURCES`` sources, evicting
  oldest first. This bounds memory under long sessions and prevents an attacker
  from filling the store with adversarial sources.
* **Determinism**: same inputs in same order produce same decisions. The tracker
  does not call the LLM, does not retry, and does not consult external state.
"""

from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import dataclass
from typing import Any, Deque, Iterable, List, Optional, Sequence, Tuple


# Minimum substring length to register as a taint token.
# Below this we get false positives on common short strings ("the", "ok", "/").
MIN_TOKEN_LEN = 16

# Maximum number of source records retained per tracker.
# Older sources are evicted FIFO when the cap is exceeded.
MAX_SOURCES = 256

# Capabilities that, by default, are treated as taint sinks. A flow into one of
# these capabilities from an untrusted source triggers a violation.
# This list is conservative: the runtime can override at construction time.
DEFAULT_SINK_CAPABILITIES = frozenset({
    "filesystem.write",
    "git.commit",
    "git.push",
    "http.fetch",
    "shell.execute",
    "package_manager.query",
})

# Capabilities whose output is considered untrusted (a taint source). These are
# capabilities that read potentially attacker-controlled content.
DEFAULT_SOURCE_CAPABILITIES = frozenset({
    "filesystem.read",
    "http.fetch",
    "git.status",
    "git.log",
    "git.diff",
})


@dataclass(frozen=True)
class TaintSource:
    """Record of a single tainted output."""

    source_id: str           # short hash for correlation in audit events
    capability: str          # which capability produced it
    output_hash: str         # SHA-256 of full output (for forensics)
    tokens: Tuple[str, ...]  # substrings extracted as taint markers


@dataclass(frozen=True)
class TaintViolation:
    """Result of a sink check that found a taint flow."""

    violated: bool
    source_id: str = ""
    source_capability: str = ""
    sink_capability: str = ""
    parameter_path: str = ""
    matched_token: str = ""
    reason: str = ""


def _hash_output(text: str) -> str:
    """SHA-256 of an output string, used as a content-addressable id."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _extract_tokens(text: str, min_len: int = MIN_TOKEN_LEN) -> Tuple[str, ...]:
    """Split a tool output into candidate taint tokens.

    The strategy is conservative: split on whitespace and keep tokens of at
    least ``min_len`` characters. We do NOT split on punctuation, because URLs,
    paths, and command strings contain meaningful punctuation that we want to
    preserve as a single token. We also keep the trimmed full string as a
    coarse-grained token, so that a verbatim copy of the entire output (a
    common LLM behavior) is always caught even if no individual word reaches
    ``min_len``.
    """
    if not isinstance(text, str) or not text.strip():
        return ()

    tokens: List[str] = []
    full = text.strip()
    if len(full) >= min_len:
        tokens.append(full)

    for piece in full.split():
        piece = piece.strip()
        if len(piece) >= min_len:
            tokens.append(piece)

    # De-duplicate while preserving order
    seen: set = set()
    unique: List[str] = []
    for tok in tokens:
        if tok not in seen:
            seen.add(tok)
            unique.append(tok)
    return tuple(unique)


def _walk_strings(value: Any, path: str = "") -> Iterable[Tuple[str, str]]:
    """Yield ``(path, string)`` pairs from a parameter tree.

    Mirrors the recursive walker in ``injection_detector`` so taint checks
    operate over the same parameter surface as injection checks.
    """
    if isinstance(value, str):
        yield path or "<root>", value
    elif isinstance(value, dict):
        for k, v in value.items():
            sub = f"{path}.{k}" if path else str(k)
            yield from _walk_strings(v, sub)
    elif isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            sub = f"{path}[{i}]" if path else f"[{i}]"
            yield from _walk_strings(item, sub)
    # Other types (numbers, bools, None) carry no taint.


class TaintTracker:
    """Per-session taint tracker.

    Lifecycle:
        tracker = TaintTracker()
        # after a source-capability call:
        tracker.register_source(capability, output)
        # before a sink-capability call:
        result = tracker.check_sink(capability, parameters)
        if result.violated: deny + audit
    """

    def __init__(
        self,
        *,
        source_capabilities: Optional[Sequence[str]] = None,
        sink_capabilities: Optional[Sequence[str]] = None,
        min_token_len: int = MIN_TOKEN_LEN,
        max_sources: int = MAX_SOURCES,
    ) -> None:
        self._sources: Deque[TaintSource] = deque(maxlen=max_sources)
        self._source_caps = frozenset(source_capabilities) if source_capabilities is not None else DEFAULT_SOURCE_CAPABILITIES
        self._sink_caps = frozenset(sink_capabilities) if sink_capabilities is not None else DEFAULT_SINK_CAPABILITIES
        self._min_token_len = min_token_len

    # --- Source side -----------------------------------------------------

    def is_source(self, capability: str) -> bool:
        """Whether outputs of ``capability`` should be registered as tainted."""
        return capability in self._source_caps

    def register_source(self, capability: str, output: Any) -> Optional[TaintSource]:
        """Record a tool output as a taint source.

        Returns the ``TaintSource`` that was stored, or ``None`` if the output
        was empty, non-string, or the capability is not configured as a source.
        """
        if not self.is_source(capability):
            return None

        # Coerce common output shapes to a single string for hashing
        text = output if isinstance(output, str) else str(output) if output is not None else ""
        tokens = _extract_tokens(text, self._min_token_len)
        if not tokens:
            return None

        full_hash = _hash_output(text)
        source = TaintSource(
            source_id=full_hash[:16],
            capability=capability,
            output_hash=full_hash,
            tokens=tokens,
        )
        self._sources.append(source)
        return source

    # --- Sink side -------------------------------------------------------

    def is_sink(self, capability: str) -> bool:
        """Whether ``capability`` should be checked against the taint store."""
        return capability in self._sink_caps

    def check_sink(self, capability: str, parameters: Any) -> TaintViolation:
        """Check whether any parameter contains a previously-tainted token.

        Returns a ``TaintViolation`` with ``violated=True`` on the first match.
        Match precedence: more recent sources first (we walk the deque from
        right to left), so the audit trail blames the freshest origin.
        """
        if not self.is_sink(capability):
            return TaintViolation(violated=False)

        # Walk all string parameters once and remember them with their paths,
        # then test each token against each parameter string. This is O(P*T)
        # where P is the number of parameter strings and T the total tokens;
        # both are small in practice.
        params_list = [(path, s) for path, s in _walk_strings(parameters) if isinstance(s, str)]
        if not params_list:
            return TaintViolation(violated=False)

        # Iterate sources newest-first.
        for source in reversed(self._sources):
            for tok in source.tokens:
                # Skip tokens too short to be meaningful (defensive; should already be filtered)
                if len(tok) < self._min_token_len:
                    continue
                for path, param_str in params_list:
                    if tok in param_str:
                        return TaintViolation(
                            violated=True,
                            source_id=source.source_id,
                            source_capability=source.capability,
                            sink_capability=capability,
                            parameter_path=path,
                            matched_token=tok if len(tok) <= 80 else tok[:77] + "...",
                            reason=(
                                f"Parameter at {path!r} contains data from earlier "
                                f"{source.capability} output (source {source.source_id})."
                            ),
                        )
        return TaintViolation(violated=False)

    # --- Inspection ------------------------------------------------------

    def source_count(self) -> int:
        """Number of taint sources currently retained."""
        return len(self._sources)

    def clear(self) -> None:
        """Forget all sources. Used when starting a new agent session."""
        self._sources.clear()
