"""Parameter validation (design §3.3, §4.1).

validate(capability, parameters, constraints) -> ValidationResult

Checks performed (in order):
1. Type validation  – required params are present and the right type.
2. Path traversal   – any path param must not escape via `..` sequences.
3. Path normalization – resolved path is coerced in place.
4. Enum validation  – if constraints list allowed values, param must be one.
5. Range / length   – min/max for numbers; min_length/max_length for strings.
6. Shell-flag / dangerous-pattern filtering – blocks rm -rf, --exec, etc.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Result object
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    """Outcome of parameter validation."""

    valid: bool
    errors: List[str] = field(default_factory=list)
    constraint_violated: Optional[str] = None

    def __bool__(self) -> bool:
        return self.valid


# ---------------------------------------------------------------------------
# Dangerous shell patterns (defence-in-depth on top of injection detector)
# ---------------------------------------------------------------------------

_DANGEROUS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("rm_-rf",         re.compile(r"rm\s+-[rf]{1,2}\s*[/~]", re.IGNORECASE)),
    ("shell_exec",     re.compile(r"--exec\b|--command\b|-e\s", re.IGNORECASE)),
    ("shell_subst",    re.compile(r"\$\(|`")),
    ("path_traversal", re.compile(r"\.\.[/\\]")),
    ("null_byte",      re.compile(r"\x00")),
    ("pipe_chain",     re.compile(r"\|\s*\w")),
    ("redirect",       re.compile(r">\s*[/~\w]")),
]

# Capabilities where shell-pattern filtering applies
_SHELL_LIKE_CAPABILITIES = {"git", "git.commit", "git.push", "shell.execute"}

# Parameter names that carry file-system paths
_PATH_PARAMS = {"path", "repo_path", "file", "src", "dst", "destination", "source"}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate(
    capability: str,
    parameters: Dict[str, Any],
    constraints: Optional[Dict[str, Any]] = None,
) -> ValidationResult:
    """Validate *parameters* for *capability* against *constraints*.

    Args:
        capability:  Resolved capability name (e.g. ``"git"``, ``"filesystem.read"``).
        parameters:  Raw parameter dict from the tool call.
        constraints: Constraint block from the policy capability entry (may be None).

    Returns:
        :class:`ValidationResult` – ``valid=True`` when all checks pass.
    """
    constraints = constraints or {}
    errors: list[str] = []
    constraint_violated: Optional[str] = None

    # 1. Type validation
    type_errors, type_constraint = _check_types(parameters, constraints)
    if type_errors:
        errors.extend(type_errors)
        constraint_violated = constraint_violated or type_constraint

    # 2 & 3. Path traversal + normalization
    path_errors, path_constraint = _check_paths(parameters)
    if path_errors:
        errors.extend(path_errors)
        constraint_violated = constraint_violated or path_constraint

    # 4. Enum validation
    enum_errors, enum_constraint = _check_enums(parameters, constraints)
    if enum_errors:
        errors.extend(enum_errors)
        constraint_violated = constraint_violated or enum_constraint

    # 5. Range / length checks
    range_errors, range_constraint = _check_ranges(parameters, constraints)
    if range_errors:
        errors.extend(range_errors)
        constraint_violated = constraint_violated or range_constraint

    # 6. Shell-flag / dangerous-pattern filtering
    if capability in _SHELL_LIKE_CAPABILITIES:
        shell_errors, shell_constraint = _check_shell_patterns(parameters)
        if shell_errors:
            errors.extend(shell_errors)
            constraint_violated = constraint_violated or shell_constraint

    return ValidationResult(
        valid=len(errors) == 0,
        errors=errors,
        constraint_violated=constraint_violated,
    )


# ---------------------------------------------------------------------------
# Internal checkers
# ---------------------------------------------------------------------------

def _check_types(
    parameters: Dict[str, Any],
    constraints: Dict[str, Any],
) -> tuple[list[str], Optional[str]]:
    errors: list[str] = []
    param_specs: Dict[str, Any] = constraints.get("parameters", {})

    for param_name, spec in param_specs.items():
        if not isinstance(spec, dict):
            continue
        expected_type = spec.get("type")
        required = spec.get("required", False)

        if param_name not in parameters:
            if required:
                errors.append(f"Missing required parameter: '{param_name}'.")
            continue

        value = parameters[param_name]
        if expected_type and not _matches_type(value, expected_type):
            errors.append(
                f"Parameter '{param_name}' must be of type {expected_type!r}, "
                f"got {type(value).__name__!r}."
            )

    if errors:
        return errors, "type_validation"
    return [], None


def _matches_type(value: Any, expected: str) -> bool:
    type_map: dict[str, Any] = {
        "string":  str,
        "str":     str,
        "number":  (int, float),
        "int":     int,
        "integer": int,
        "float":   float,
        "boolean": bool,
        "bool":    bool,
        "object":  dict,
        "dict":    dict,
        "array":   list,
        "list":    list,
    }
    expected_type = type_map.get(expected.lower())
    if expected_type is None:
        return True
    # bool is a subclass of int in Python — guard against false positives
    if expected_type is int and isinstance(value, bool):
        return False
    return isinstance(value, expected_type)


def _check_paths(
    parameters: Dict[str, Any],
) -> tuple[list[str], Optional[str]]:
    errors: list[str] = []

    for key in _PATH_PARAMS:
        if key not in parameters:
            continue
        value = parameters[key]
        if not isinstance(value, str):
            continue

        if "\x00" in value:
            errors.append(f"Parameter '{key}' contains a null byte.")
            continue

        if re.search(r"\.\.[/\\]", value) or value.endswith(".."):
            errors.append(
                f"Parameter '{key}' contains a path-traversal sequence: {value!r}."
            )
            continue

        # Normalize in place so downstream tools see the resolved path
        try:
            parameters[key] = str(Path(value).resolve())
        except Exception:
            pass

    if errors:
        return errors, "path_traversal"
    return [], None


def _check_enums(
    parameters: Dict[str, Any],
    constraints: Dict[str, Any],
) -> tuple[list[str], Optional[str]]:
    errors: list[str] = []

    # Top-level list constraints: e.g. operations: ["list", "search", "info"]
    for key, allowed_values in constraints.items():
        if not isinstance(allowed_values, list) or key not in parameters:
            continue
        value = parameters[key]
        values_to_check = value if isinstance(value, list) else [value]
        for v in values_to_check:
            if v not in allowed_values:
                errors.append(
                    f"Parameter '{key}' value {v!r} is not in the allowed set: {allowed_values}."
                )

    # Nested param_specs with 'enum'
    for param_name, spec in constraints.get("parameters", {}).items():
        if not isinstance(spec, dict):
            continue
        enum_vals = spec.get("enum")
        if not enum_vals or param_name not in parameters:
            continue
        value = parameters[param_name]
        values_to_check = value if isinstance(value, list) else [value]
        for v in values_to_check:
            if v not in enum_vals:
                errors.append(
                    f"Parameter '{param_name}' value {v!r} not in allowed enum: {enum_vals}."
                )

    if errors:
        return errors, "enum_validation"
    return [], None


def _check_ranges(
    parameters: Dict[str, Any],
    constraints: Dict[str, Any],
) -> tuple[list[str], Optional[str]]:
    errors: list[str] = []

    for param_name, spec in constraints.get("parameters", {}).items():
        if not isinstance(spec, dict) or param_name not in parameters:
            continue
        value = parameters[param_name]

        if isinstance(value, (int, float)) and not isinstance(value, bool):
            mn, mx = spec.get("min"), spec.get("max")
            if mn is not None and value < mn:
                errors.append(f"Parameter '{param_name}' value {value} is below minimum {mn}.")
            if mx is not None and value > mx:
                errors.append(f"Parameter '{param_name}' value {value} exceeds maximum {mx}.")

        if isinstance(value, str):
            mn_len, mx_len = spec.get("min_length"), spec.get("max_length")
            if mn_len is not None and len(value) < mn_len:
                errors.append(
                    f"Parameter '{param_name}' length {len(value)} is below minimum {mn_len}."
                )
            if mx_len is not None and len(value) > mx_len:
                errors.append(
                    f"Parameter '{param_name}' length {len(value)} exceeds maximum {mx_len}."
                )

    if errors:
        return errors, "range_validation"
    return [], None


def _check_shell_patterns(
    parameters: Dict[str, Any],
) -> tuple[list[str], Optional[str]]:
    errors: list[str] = []

    for key, value in parameters.items():
        if not isinstance(value, str):
            continue
        for pattern_name, pattern in _DANGEROUS_PATTERNS:
            if pattern.search(value):
                errors.append(
                    f"Parameter '{key}' contains a dangerous pattern ({pattern_name})."
                )
                break

    if errors:
        return errors, "dangerous_pattern"
    return [], None
