"""
fetch_cms.py  (two-catalog)
===========================
Pulls a CMS dataset to data\\<name>.csv, auto-detecting which catalog it is:

  * Main catalog (long UUID, e.g. 6219697b-8f6c-4164-bed4-cd9317c58ebc)
        -> data-api/v1/dataset/<uuid>/data, paged JSON
  * Provider Data Catalog (short id, e.g. xubh-q36u)
        -> resolved via the catalog metastore to a direct CSV download

Usage:
    python fetch_cms.py <id> [output_name]

Examples:
    python fetch_cms.py 6219697b-8f6c-4164-bed4-cd9317c58ebc gv          # main catalog
    python fetch_cms.py xubh-q36u hospital_general                       # provider-data
    python fetch_cms.py                                                  # defaults to GV

Output:
    data\\<output_name>.csv   (defaults to the id if no name given)
"""

from __future__ import annotations

import csv
import json
import os
import re
import sys
import urllib.request

DATA_DIR = "data"
GV_DEFAULT = "6219697b-8f6c-4164-bed4-cd9317c58ebc"

MAIN_API = "https://data.cms.gov/data-api/v1/dataset/{uuid}/data"
PROVIDER_METASTORE = "https://data.cms.gov/provider-data/api/1/metastore/schemas/dataset/items"

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
PAGE_SIZE = 5000


def _out_path(name: str) -> str:
    os.makedirs(DATA_DIR, exist_ok=True)
    return os.path.join(DATA_DIR, f"{name}.csv")


def fetch_main_catalog(uuid: str, out: str) -> None:
    """Page the JSON data-api and write one CSV."""
    base = MAIN_API.format(uuid=uuid)
    offset, total, writer, f = 0, 0, None, None
    try:
        while True:
            url = f"{base}?size={PAGE_SIZE}&offset={offset}"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=180) as resp:
                batch = json.load(resp)
            if not batch:
                break
            if writer is None:
                f = open(out, "w", newline="", encoding="utf-8")
                writer = csv.DictWriter(f, fieldnames=list(batch[0].keys()), extrasaction="ignore")
                writer.writeheader()
            for row in batch:
                writer.writerow(row)
            total += len(batch)
            print(f"  fetched {total} rows...")
            offset += PAGE_SIZE
            if len(batch) < PAGE_SIZE:
                break
    finally:
        if f is not None:
            f.close()
    print(f"done (main catalog): {total} rows -> {out}")


def _resolve_provider_csv(identifier: str) -> str:
    """Look up the live CSV download URL for a Provider Data Catalog id."""
    req = urllib.request.Request(PROVIDER_METASTORE, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        items = json.load(r)
    for it in items:
        if it.get("identifier") == identifier:
            for dist in it.get("distribution", []):
                url = dist.get("downloadURL")
                if url and url.lower().endswith(".csv"):
                    return url
    raise SystemExit(f"identifier {identifier!r} not found as a CSV in the Provider Data Catalog")


def fetch_provider_catalog(identifier: str, out: str) -> None:
    """Resolve and stream the provider-data CSV straight to disk."""
    url = _resolve_provider_csv(identifier)
    req = urllib.request.Request(url, headers={"Accept": "text/csv"})
    n = 0
    with urllib.request.urlopen(req, timeout=300) as resp, open(out, "wb") as f:
        while True:
            chunk = resp.read(1 << 16)
            if not chunk:
                break
            f.write(chunk)
            n += len(chunk)
    # quick row count
    with open(out, "r", encoding="utf-8", errors="replace") as f:
        rows = sum(1 for _ in f) - 1
    print(f"done (provider data): ~{rows} rows, {n/1e6:.1f} MB -> {out}")


def main() -> None:
    args = sys.argv[1:]
    ident = args[0] if args else GV_DEFAULT
    name = args[1] if len(args) > 1 else ident
    out = _out_path(name)

    if UUID_RE.match(ident):
        print(f"main catalog (UUID): {ident}")
        fetch_main_catalog(ident, out)
    else:
        print(f"provider data catalog (id): {ident}")
        fetch_provider_catalog(ident, out)


if __name__ == "__main__":
    main()
