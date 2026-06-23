"""
test_cms_sources.py
===================
Manually tests every CMS Provider Data Catalog source on our shortlist. For each
dataset identifier it resolves the live CSV via CMS's own metastore index,
downloads the header and a few rows, and reports PASS/FAIL with the columns.

Run from the repo root with venv311 active:
    python test_cms_sources.py

No third-party deps; uses only the standard library.
"""

from __future__ import annotations

import csv
import io
import json
import urllib.request

METASTORE = "https://data.cms.gov/provider-data/api/1/metastore/schemas/dataset/items"

# identifier -> friendly name (the twelve we shortlisted)
TARGETS = {
    "xubh-q36u": "Hospital General Information",
    "632h-zaca": "Unplanned Hospital Visits - Hospital",
    "yv7e-xc69": "Timely and Effective Care - Hospital",
    "ynj2-r877": "Complications and Deaths - Hospital",
    "77hc-ibv8": "Healthcare Associated Infections - Hospital",
    "dgck-syfz": "Patient Survey (HCAHPS) - Hospital",
    "rrqw-56er": "Medicare Spending Per Beneficiary - Hospital",
    "9n3s-kdb3": "Hospital Readmissions Reduction Program",
    "q9vs-r7wp": "Inpatient Psychiatric Facility Quality - Facility",
    "6jpm-sxkc": "Home Health Care Agencies",
    "252m-zfp9": "Hospice - Provider Data",
    "23ew-n7w9": "Dialysis Facility - Listing by Facility",
}


def load_catalog() -> dict:
    """Return {identifier: downloadURL} for every CSV distribution in the catalog."""
    req = urllib.request.Request(METASTORE, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        items = json.load(r)
    out = {}
    for it in items:
        ident = it.get("identifier")
        for dist in it.get("distribution", []):
            url = dist.get("downloadURL")
            if ident and url and url.lower().endswith(".csv"):
                out[ident] = url
                break
    return out


def peek_csv(url: str, n_rows: int = 3):
    """Download just enough of the CSV to read the header and a few rows."""
    req = urllib.request.Request(url, headers={"Accept": "text/csv"})
    with urllib.request.urlopen(req, timeout=120) as r:
        # read ~64KB, enough for header + sample without pulling the whole file
        chunk = r.read(65536).decode("utf-8", errors="replace")
    reader = csv.reader(io.StringIO(chunk))
    rows = []
    for i, row in enumerate(reader):
        rows.append(row)
        if i >= n_rows:
            break
    header = rows[0] if rows else []
    sample = rows[1:n_rows + 1] if len(rows) > 1 else []
    return header, sample


def main():
    print("resolving CMS Provider Data Catalog index...")
    catalog = load_catalog()
    print(f"catalog has {len(catalog)} CSV datasets\n")

    ok, missing, errored = 0, 0, 0
    for ident, name in TARGETS.items():
        url = catalog.get(ident)
        if not url:
            print(f"[MISSING] {ident}  {name}  (not found in catalog)")
            missing += 1
            continue
        try:
            header, sample = peek_csv(url)
            ok += 1
            print(f"[PASS]    {ident}  {name}")
            print(f"            cols: {len(header)} | {', '.join(header[:6])}{' ...' if len(header) > 6 else ''}")
            if sample:
                print(f"            e.g.: {sample[0][:3]}")
        except Exception as e:
            errored += 1
            print(f"[ERROR]   {ident}  {name}  -> {e}")

    print(f"\nsummary: {ok} pass, {missing} missing, {errored} error, of {len(TARGETS)} tested")


if __name__ == "__main__":
    main()
