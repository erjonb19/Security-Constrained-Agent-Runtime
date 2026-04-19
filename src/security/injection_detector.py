"""Prompt/output injection detection for tool parameters (plan Phase 2.2, DESIGN §5.4).

Scans string values in parameter dicts (recursively) for pattern-based indicators of
prompt injection, shell/command injection, and similar attacks.

**Sensitivity** (which pattern groups apply):

- ``low``: Destructive shell-style and pipe-to-shell patterns only.
- ``medium`` (default): ``low`` plus common prompt-injection and instruction-override phrases.
- ``high``: ``medium`` plus additional command/script markers (stricter; more false positives).

**Capability tiers** (without policy YAML changes):

- **Relaxed** (e.g. ``filesystem.read``, read-only HTTP): same as above but prompt-phrase
  patterns are limited to ``medium``/``high`` sensitivity only (at ``low`` sensitivity,
  relaxed capabilities still run destructive patterns only).
- **Strict** (e.g. ``filesystem.write``, ``git``, ``shell.*``): full pattern set for the
  chosen sensitivity.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterator, Optional, Sequence, Tuple

# Max recursion depth for nested dict/list parameters
_MAX_DEPTH = 24
# Skip scanning strings longer than this (DoS safety)
_MAX_STRING_LEN = 512_000


@dataclass(frozen=True)
class InjectionScanResult:
    """Outcome of scanning tool parameters for injection patterns."""

    clean: bool
    reason: str = ""
    injection_type: str = ""
    pattern_matched: str = ""
    parameter_path: Optional[str] = None


@dataclass(frozen=True)
class _PatternRule:
    """Single rule: compiled regex, category for audit logs, human label."""

    regex: re.Pattern[str]
    injection_type: str
    label: str


def _compile_rules(
    sensitivity: str,
    *,
    relaxed_capability: bool,
) -> Tuple[_PatternRule, ...]:
    """Build pattern rules for sensitivity and strict vs relaxed capability."""
    s = sensitivity.lower()
    if s not in ("low", "medium", "high"):
        s = "medium"

    destructive: list[_PatternRule] = [
        _PatternRule(
            re.compile(r"rm\s+-\s*rf\b", re.IGNORECASE | re.MULTILINE),
            "command",
            "rm_-rf",
        ),
        _PatternRule(
            re.compile(r"curl\s+[^\n]*\|\s*(?:sh|bash)\b", re.IGNORECASE),
            "command",
            "curl_pipe_sh",
        ),
        _PatternRule(
            re.compile(r"wget\s+[^\n]*\|\s*(?:sh|bash)\b", re.IGNORECASE),
            "command",
            "wget_pipe_sh",
        ),
        _PatternRule(
            re.compile(r";\s*rm\s+", re.IGNORECASE),
            "command",
            "semicolon_rm",
        ),
        _PatternRule(
            re.compile(r"`rm\s+", re.IGNORECASE),
            "command",
            "backtick_rm",
        ),
    ]

    prompt_medium: list[_PatternRule] = [
        _PatternRule(
            re.compile(
                r"ignore\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|rules?|directions?)",
                re.IGNORECASE,
            ),
            "prompt",
            "ignore_previous_instructions",
        ),
        _PatternRule(
            re.compile(
                r"disregard\s+(?:the\s+)?(?:above|prior|previous)",
                re.IGNORECASE,
            ),
            "prompt",
            "disregard_above",
        ),
        _PatternRule(
            re.compile(r"\bjailbreak\b", re.IGNORECASE),
            "prompt",
            "jailbreak",
        ),
        _PatternRule(
            re.compile(r"system\s*:\s*you\s+are\s+now", re.IGNORECASE),
            "prompt",
            "system_role_override",
        ),
    ]

    extra_high: list[_PatternRule] = [
        _PatternRule(
            re.compile(r"\b(?:/bin/(?:ba)?sh|cmd\.exe|powershell(?:\.exe)?)\b", re.IGNORECASE),
            "command",
            "shell_binary",
        ),
        _PatternRule(
            re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE),
            "command",
            "eval_exec_paren",
        ),
        _PatternRule(
            re.compile(r"<\s*script[\s>]", re.IGNORECASE),
            "command",
            "script_tag",
        ),
    ]

    rules: list[_PatternRule] = list(destructive)

    include_prompt = s in ("medium", "high")
    if relaxed_capability and s == "low":
        include_prompt = False
    if include_prompt:
        rules.extend(prompt_medium)

    if s == "high":
        rules.extend(extra_high)

    return tuple(rules)


def _capability_relaxed(capability: str) -> bool:
    """Use a slightly lighter prompt-pattern set for read-oriented capabilities."""
    c = capability.lower()
    if c.startswith("filesystem.read"):
        return True
    if c == "http.fetch":
        return True
    if c.startswith("package_manager.") and "query" in c:
        return True
    return False


class InjectionDetector:
    """
    Pattern-based injection detection on tool parameters.

    Args:
        sensitivity: ``low`` | ``medium`` | ``high`` (see module docstring).
    """

    def __init__(self, sensitivity: str = "medium") -> None:
        self.sensitivity = sensitivity.lower() if sensitivity else "medium"
        if self.sensitivity not in ("low", "medium", "high"):
            self.sensitivity = "medium"

    def _rules_for(self, capability: str) -> Sequence[_PatternRule]:
        relaxed = _capability_relaxed(capability)
        return _compile_rules(self.sensitivity, relaxed_capability=relaxed)

    def scan(self, capability: str, parameters: dict[str, Any]) -> InjectionScanResult:
        """
        Scan all string values in ``parameters`` for injection patterns.

        Returns :class:`InjectionScanResult` with ``clean=True`` if no match.
        """
        rules = self._rules_for(capability)
        for path, text in _iter_string_values(parameters, depth=0, prefix=""):
            if len(text) > _MAX_STRING_LEN:
                continue
            for rule in rules:
                m = rule.regex.search(text)
                if m:
                    matched = m.group(0)
                    if len(matched) > 200:
                        matched = matched[:200] + "..."
                    return InjectionScanResult(
                        clean=False,
                        reason=f"Injection pattern detected ({rule.label})",
                        injection_type=rule.injection_type,
                        pattern_matched=matched,
                        parameter_path=path or "<root>",
                    )
        return InjectionScanResult(clean=True)


def _iter_string_values(
    obj: Any,
    depth: int,
    prefix: str,
) -> Iterator[Tuple[str, str]]:
    """Yield (json-path-like string, value) for each string in nested dict/list."""
    if depth > _MAX_DEPTH:
        return
    if isinstance(obj, str):
        yield (prefix, obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            key = str(k)
            p = f"{prefix}.{key}" if prefix else key
            yield from _iter_string_values(v, depth + 1, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            p = f"{prefix}[{i}]" if prefix else f"[{i}]"
            yield from _iter_string_values(v, depth + 1, p)
