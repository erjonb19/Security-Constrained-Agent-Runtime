"""Tests for groundedness.py -- the anti-hallucination gate.

WHY THIS FILE EXISTS
The README makes a specific promise: "verifies every claim in a generated brief
traces back to a real returned row, so the agent cannot state a number it did not
retrieve." That promise had NO pytest coverage. The only exercise of the module
was demo_groundedness_wiring.py, a narrative script that prints its findings and
is not collected by pytest -- so nothing would have caught a regression here.

The case that matters most is `test_shifted_value_is_ungrounded`: a number that
is plausible, correctly shaped, and in the right column, but that no query
returned. That is exactly what a hallucination looks like, and it is the reason
the module exists.
"""

import pytest

from groundedness import (Claim, GroundednessResult, QueryLedger, check_claims)


COLUMNS = ["region", "year", "ed_per_1k", "pmpm"]
ROWS = [
    {"region": "Bronx", "year": 2023, "ed_per_1k": 689.1, "pmpm": 412.10},
    {"region": "Manhattan", "year": 2023, "ed_per_1k": 540.6, "pmpm": 380.22},
    {"region": "Queens", "year": 2023, "ed_per_1k": 612.3, "pmpm": 401.77},
]


@pytest.fixture
def ledger():
    led = QueryLedger()
    led.record(COLUMNS, ROWS)
    return led


# --------------------------------------------------------------------------
# QueryLedger
# --------------------------------------------------------------------------
class TestQueryLedger:
    def test_record_returns_increasing_ids_starting_at_one(self):
        led = QueryLedger()
        assert led.record(COLUMNS, ROWS) == 1
        assert led.record(COLUMNS, ROWS) == 2

    def test_get_returns_recorded_columns_and_rows(self, ledger):
        q = ledger.get(1)
        assert q["columns"] == COLUMNS
        assert q["rows"] == ROWS

    def test_get_unknown_id_returns_none(self, ledger):
        assert ledger.get(999) is None

    def test_ledger_snapshots_the_row_list_it_was_given(self):
        """The ledger is the evidence record, so appending to the caller's list
        afterwards must not add rows to it. Note this is a SHALLOW copy: the row
        dicts themselves are shared, so mutating a dict in place would still be
        visible. Callers hand over freshly built rows, so that is not a live
        concern -- but it is the actual guarantee, so this is what is asserted."""
        led = QueryLedger()
        rows = [dict(ROWS[0])]
        led.record(COLUMNS, rows)
        rows.append({"region": "Injected", "ed_per_1k": 1.0})
        assert len(led.get(1)["rows"]) == 1

    def test_all_queries_returns_a_copy(self, ledger):
        snapshot = ledger.all_queries()
        snapshot.clear()
        assert ledger.get(1) is not None


# --------------------------------------------------------------------------
# Claim parsing
# --------------------------------------------------------------------------
class TestClaim:
    def test_from_dict_parses_all_fields(self):
        c = Claim.from_dict({"value": "689.1", "metric": "ed_per_1k",
                             "dims": {"region": "Bronx"}, "source_query_id": 1,
                             "label": "Bronx ED rate"})
        assert c.value == 689.1 and isinstance(c.value, float)
        assert c.metric == "ed_per_1k"
        assert c.dims == {"region": "Bronx"}
        assert c.source_query_id == 1
        assert c.label == "Bronx ED rate"

    def test_from_dict_defaults_optional_fields(self):
        c = Claim.from_dict({"value": 1, "metric": "pmpm"})
        assert c.dims == {} and c.source_query_id is None and c.label == ""


# --------------------------------------------------------------------------
# check_claims -- the gate itself
# --------------------------------------------------------------------------
class TestCheckClaims:
    def test_exact_claim_is_grounded(self, ledger):
        r = check_claims([Claim(689.1, "ed_per_1k", {"region": "Bronx"})], ledger)
        assert r.ok is True
        assert r.ungrounded == []
        assert r.findings[0].matched_query_id == 1

    def test_shifted_value_is_ungrounded(self, ledger):
        """THE case this module exists for: right column, right region, plausible
        magnitude -- but no row returned it."""
        r = check_claims([Claim(694.1, "ed_per_1k", {"region": "Bronx"})], ledger)
        assert r.ok is False
        assert len(r.ungrounded) == 1
        assert "possible hallucination" in r.ungrounded[0].reason

    def test_right_number_but_wrong_region_is_ungrounded(self, ledger):
        """Bronx's real number attributed to Manhattan. The value exists in the
        data; the claim still misstates it."""
        r = check_claims([Claim(689.1, "ed_per_1k", {"region": "Manhattan"})], ledger)
        assert r.ok is False

    def test_rounding_in_the_brief_is_tolerated(self, ledger):
        """A brief that says 689.1 for a stored 689.13 is honest prose, not a
        fabrication, so the check allows a small tolerance."""
        led = QueryLedger()
        led.record(COLUMNS, [{"region": "Bronx", "ed_per_1k": 689.13}])
        assert check_claims([Claim(689.1, "ed_per_1k", {"region": "Bronx"})], led).ok

    def test_unknown_metric_column_is_ungrounded(self, ledger):
        r = check_claims([Claim(689.1, "not_a_column", {"region": "Bronx"})], ledger)
        assert r.ok is False

    def test_dimension_absent_from_row_is_ungrounded(self, ledger):
        r = check_claims([Claim(689.1, "ed_per_1k", {"borough": "Bronx"})], ledger)
        assert r.ok is False

    def test_non_numeric_cell_cannot_support_a_numeric_claim(self):
        led = QueryLedger()
        led.record(["region", "ed_per_1k"], [{"region": "Bronx", "ed_per_1k": "N/A"}])
        assert check_claims([Claim(0.0, "ed_per_1k", {"region": "Bronx"})], led).ok is False

    def test_dimension_match_is_case_and_whitespace_insensitive(self, ledger):
        r = check_claims([Claim(689.1, "ed_per_1k", {"region": "  bronx "})], ledger)
        assert r.ok is True

    def test_missing_source_query_id_is_reported_specifically(self, ledger):
        """A claim citing evidence that does not exist must not fall back to
        searching every other query -- the citation itself is the defect."""
        r = check_claims([Claim(689.1, "ed_per_1k", {"region": "Bronx"},
                                source_query_id=42)], ledger)
        assert r.ok is False
        assert "not found in ledger" in r.findings[0].reason

    def test_claim_without_source_id_searches_every_query(self):
        led = QueryLedger()
        led.record(COLUMNS, [{"region": "Bronx", "ed_per_1k": 1.0}])
        second = led.record(COLUMNS, ROWS)
        r = check_claims([Claim(540.6, "ed_per_1k", {"region": "Manhattan"})], led)
        assert r.ok is True
        assert r.findings[0].matched_query_id == second

    def test_one_bad_claim_fails_the_whole_brief(self, ledger):
        """A brief is committed or not as a unit; a single unsupported figure
        must sink it even when everything else checks out."""
        r = check_claims([
            Claim(689.1, "ed_per_1k", {"region": "Bronx"}),
            Claim(540.6, "ed_per_1k", {"region": "Manhattan"}),
            Claim(999.9, "ed_per_1k", {"region": "Queens"}),
        ], ledger)
        assert r.ok is False
        assert len(r.findings) == 3
        assert len(r.ungrounded) == 1

    def test_empty_claim_list_is_vacuously_ok(self, ledger):
        r = check_claims([], ledger)
        assert isinstance(r, GroundednessResult)
        assert r.ok is True and r.findings == []

    def test_empty_ledger_grounds_nothing(self):
        r = check_claims([Claim(1.0, "ed_per_1k")], QueryLedger())
        assert r.ok is False
