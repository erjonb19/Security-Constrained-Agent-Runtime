"""End-to-end: the hospital build vs. a measure CMS suppressed.

Builds from tiny synthetic CSVs shaped like the real CMS files. Pins three cases:

  1. Every HWR row "Not Available" + footnote 4  -> build SHIPS, HWR empty.
  2. Every HWR row "Not Available", NO footnote  -> build ABORTS (could be a
     broken file; nothing proves the gap is deliberate).
  3. HWR measure missing from the file entirely  -> build ABORTS (that is what a
     CMS rename looks like -- the case the gate was built for).

And the real Oct 2026 shape, where CMS footnoted most rows 4 but some 5 (no
results this period) or 19 (not in the program):

  4. Mostly 4, some 5 / 19 / "4, 19"             -> build SHIPS, HWR a WARN.
  5. Same mix, one blank footnote                -> build ABORTS.
  6. Same mix, one footnote 29                   -> build ABORTS.
  7. Mostly 5 / 19, only a few 4s                -> build ABORTS.
"""

import csv
import os
import sys

import duckdb
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import build_hospital_gold as b

HWR = "Hybrid Hospital-Wide All-Cause Readmission Measure (HWR)"
FAC = [("330001", "NY"), ("330002", "NY"), ("310001", "NJ")]
FAC10 = [(f"3300{i:02d}", "NY") for i in range(1, 6)] + \
        [(f"3100{i:02d}", "NJ") for i in range(1, 6)]

# The Oct 2026 shape on 10 hospitals: 7 of 10 carry footnote 4.
OCT_MIX = ["4", "4", "4", "4", "4", "4", "4, 19", "5", "19", "19"]


def _write(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def _make_data(d, hwr_mode, fac=FAC):
    """hwr_mode is a named mode, or a list of HWR footnotes (one per hospital,
    every row 'Not Available')."""
    _write(d / "hospital_general.csv",
           ["Facility ID", "Facility Name", "City/Town", "State", "ZIP Code",
            "Hospital overall rating"],
           [(f, f"H{f}", "X", s, "10001", "3") for f, s in fac])
    _write(d / "mspb.csv", ["Facility ID", "Score"], [(f, "0.98") for f, _ in fac])

    hdr = ["Facility ID", "State", "Measure Name", "Score", "Footnote"]
    unplanned = []
    for i, (f, s) in enumerate(fac):
        for name in b.UNPLANNED_MEASURES:
            if name == HWR:
                if isinstance(hwr_mode, list):
                    unplanned.append((f, s, name, "Not Available", hwr_mode[i]))
                elif hwr_mode == "suppressed":
                    unplanned.append((f, s, name, "Not Available", "4"))
                elif hwr_mode == "empty_no_footnote":
                    unplanned.append((f, s, name, "Not Available", ""))
                # "missing": no row at all
            else:
                unplanned.append((f, s, name, "15.2", ""))
    _write(d / "unplanned_visits.csv", hdr, unplanned)

    timely = []
    for f, s in fac:
        for name in b.TIMELY_MEASURES:
            timely.append((f, s, name, "120", ""))
        timely.append((f, s, b.ED_VOLUME_MEASURE, "high", ""))
    _write(d / "timely_effective_care.csv", hdr, timely)


@pytest.fixture
def build(tmp_path, monkeypatch):
    def run(hwr_mode, fac=FAC):
        data = tmp_path / "data"
        data.mkdir(exist_ok=True)
        _make_data(data, hwr_mode, fac)
        monkeypatch.setattr(b, "DATA", str(data).replace("\\", "/"))
        monkeypatch.setattr(b, "OUT_DIR", str(tmp_path / "medallion"))
        monkeypatch.setattr(b, "GOLD_DB", str(tmp_path / "medallion" / "g.duckdb"))
        b.main(vintage="2026-10-01")
        return str(tmp_path / "medallion" / "g.duckdb")
    return run


def test_cms_suppressed_measure_ships_with_a_warning(build, capsys):
    db = build("suppressed")
    con = duckdb.connect(db, read_only=True)
    n, hwr, hf = con.execute(
        "SELECT count(*), count(readmit_hwr), count(readmit_hf) "
        "FROM gold_hospital_profile").fetchone()
    assert (n, hwr, hf) == (3, 0, 3), "everything else refreshed; HWR shipped empty"
    out = capsys.readouterr().out
    assert "CMS-suppressed this release" in out and "readmit_hwr" in out


def test_empty_measure_without_footnote_still_aborts(build):
    with pytest.raises(SystemExit, match="Build ABORTED"):
        build("empty_no_footnote")


def test_missing_measure_still_aborts(build):
    with pytest.raises(SystemExit, match="Build ABORTED"):
        build("missing")


def test_october_footnote_mix_ships_with_a_warning(build, capsys):
    db = build(OCT_MIX, FAC10)
    con = duckdb.connect(db, read_only=True)
    n, hwr, hf = con.execute(
        "SELECT count(*), count(readmit_hwr), count(readmit_hf) "
        "FROM gold_hospital_profile").fetchone()
    assert (n, hwr, hf) == (10, 0, 10), "everything else refreshed; HWR shipped empty"
    out = capsys.readouterr().out
    assert "[WARN ] column_has_data(readmit_hwr)" in out
    assert "CMS-suppressed this release" in out and "readmit_hwr" in out


def test_october_mix_with_a_blank_footnote_aborts(build):
    mix = ["", *OCT_MIX[1:]]
    with pytest.raises(SystemExit, match="Build ABORTED"):
        build(mix, FAC10)


def test_october_mix_with_an_unknown_footnote_aborts(build):
    mix = ["29", *OCT_MIX[1:]]
    with pytest.raises(SystemExit, match="Build ABORTED"):
        build(mix, FAC10)


def test_mostly_5_and_19_with_few_4s_aborts(build):
    mix = ["4", "4", "5", "5", "5", "5", "19", "19", "19", "19"]
    with pytest.raises(SystemExit, match="Build ABORTED"):
        build(mix, FAC10)
