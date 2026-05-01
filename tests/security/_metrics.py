"""
Phase 2 (PR-3) test-side metrics helpers.

Pure-Python, stdlib-only. **No imports from `src/`.** This file lives next to
the security test modules so the production runtime stays untouched in PR-3
(the PR-strategy guidance in
``docs/Adv-Se-Project-Documents/docs/PHASED_CODE_UPDATE_PLAN_FROM_STAFF_FEEDBACK.md``
asks each phase to be a narrowly-scoped PR).

Vocabulary intentionally mirrors ``scripts/eval_phase5.py`` (BTSR / ASR /
block_rate) so the paper can talk about the two evaluation surfaces in the
same terms.

A "record" is just a dict of the form::

    {"id": "po-001", "category": "prompt_override", "blocked": True, ...}

Helpers:

- :func:`block_rate`      - overall fraction of records with ``blocked=True``.
- :func:`per_category`    - per-category block rate as ``{category: rate}``.
- :func:`per_category_counts` - per-category ``{cat: (blocked, total)}`` for
  reporting and writing the JSON summary.
- :func:`assert_meets_targets` - raise ``AssertionError`` when any category in
  ``targets`` is below threshold; renders a readable per-category table.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Mapping, Tuple


def block_rate(records: Iterable[Mapping[str, object]]) -> float:
    """Fraction of *records* whose ``blocked`` field is truthy.

    Returns ``0.0`` for an empty input (no division by zero).
    """
    items = list(records)
    if not items:
        return 0.0
    hits = sum(1 for r in items if bool(r.get("blocked")))
    return hits / len(items)


def per_category_counts(
    records: Iterable[Mapping[str, object]],
    *,
    key: str = "category",
) -> Dict[str, Tuple[int, int]]:
    """Return ``{category: (blocked_count, total_count)}``.

    Records with no ``key`` field are bucketed under ``"<unknown>"`` so they
    are never silently dropped.
    """
    out: Dict[str, list[int]] = {}
    for r in records:
        cat = str(r.get(key, "<unknown>"))
        slot = out.setdefault(cat, [0, 0])
        slot[1] += 1
        if bool(r.get("blocked")):
            slot[0] += 1
    return {cat: (b, t) for cat, (b, t) in out.items()}


def per_category(
    records: Iterable[Mapping[str, object]],
    *,
    key: str = "category",
) -> Dict[str, float]:
    """Return ``{category: block_rate}`` as floats in ``[0.0, 1.0]``."""
    counts = per_category_counts(records, key=key)
    return {cat: (b / t if t else 0.0) for cat, (b, t) in counts.items()}


def assert_meets_targets(
    actual: Mapping[str, float],
    targets: Mapping[str, float],
    *,
    label: str,
    counts: Mapping[str, Tuple[int, int]] | None = None,
) -> None:
    """Fail with a readable message if any *targets* category misses.

    Categories listed in *targets* but missing from *actual* are treated as
    ``0.0`` (worst case). Categories present in *actual* but absent from
    *targets* are reported but never fail.

    *counts* is an optional ``{cat: (blocked, total)}`` map from
    :func:`per_category_counts` -- when provided, its values are included in
    the failure table for easier triage.
    """
    misses: List[str] = []
    rows: List[str] = []
    rows.append(f"--- {label} ---")
    rows.append(f"{'category':<22} {'rate':>6}  {'target':>6}  {'count':>10}  status")
    for cat, target in sorted(targets.items()):
        rate = float(actual.get(cat, 0.0))
        c = counts.get(cat) if counts else None
        count_str = f"{c[0]}/{c[1]}" if c else "n/a"
        status = "ok" if rate + 1e-9 >= target else "MISS"
        rows.append(
            f"{cat:<22} {rate:>6.2f}  {target:>6.2f}  {count_str:>10}  {status}"
        )
        if status == "MISS":
            misses.append(f"{cat}: {rate:.2f} < target {target:.2f}")
    extras = sorted(set(actual) - set(targets))
    if extras:
        rows.append("(no target set; informational)")
        for cat in extras:
            c = counts.get(cat) if counts else None
            count_str = f"{c[0]}/{c[1]}" if c else "n/a"
            rows.append(
                f"{cat:<22} {float(actual[cat]):>6.2f}  {'-':>6}  {count_str:>10}  info"
            )

    rendered = "\n".join(rows)
    if misses:
        raise AssertionError(
            f"{label}: {len(misses)} category(ies) below target.\n{rendered}"
        )
    # On success, the rendered table is still printed via pytest -s if the
    # caller wants to see it; we just don't raise.
    print(rendered)
