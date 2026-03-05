#!/usr/bin/env python3
"""Build local CVE intelligence catalog from NVD/KEV/EPSS sources."""

from __future__ import annotations

import argparse
import csv
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.request import urlopen

from common import write_json


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def fetch_json(url: str) -> dict[str, Any]:
    with urlopen(url, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8", errors="ignore"))


def parse_nvd(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    items = payload.get("vulnerabilities", [])
    for item in items:
        cve = item.get("cve", {})
        cve_id = str(cve.get("id", "")).strip()
        if not cve_id:
            continue
        metrics = cve.get("metrics", {})
        cvss = 0.0
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            rows = metrics.get(key, [])
            if rows and isinstance(rows, list):
                val = rows[0].get("cvssData", {}).get("baseScore")
                if isinstance(val, (int, float)):
                    cvss = float(val)
                    break
        cpes: list[str] = []
        for conf in cve.get("configurations", []) or []:
            for node in conf.get("nodes", []) or []:
                for m in node.get("cpeMatch", []) or []:
                    crit = str(m.get("criteria", "")).strip()
                    if crit:
                        cpes.append(crit)
        cwes: list[str] = []
        for weakness in cve.get("weaknesses", []) or []:
            for desc in weakness.get("description", []) or []:
                w = str(desc.get("value", "")).strip()
                if w.startswith("CWE-"):
                    cwes.append(w)
        desc = ""
        for d in cve.get("descriptions", []) or []:
            if d.get("lang") == "en":
                desc = str(d.get("value", ""))
                break
        out[cve_id] = {
            "cve": cve_id,
            "cvss": cvss,
            "epss": 0.0,
            "kev": False,
            "cwe": sorted(list(set(cwes))),
            "cpes": sorted(list(set(cpes)))[:40],
            "vendor": "",
            "product": "",
            "versions": [],
            "description": desc[:2000],
        }
    return out


def parse_kev(payload: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    rows = payload.get("vulnerabilities", []) or payload.get("known_exploited_vulnerabilities", [])
    for row in rows or []:
        cve = str(row.get("cveID", "") or row.get("cve", "")).strip().upper()
        if cve.startswith("CVE-"):
            out.add(cve)
    return out


def parse_epss(path: Path) -> dict[str, float]:
    out: dict[str, float] = {}
    if not path.exists():
        return out
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve = str(row.get("cve", "")).strip().upper()
            if not cve.startswith("CVE-"):
                continue
            try:
                out[cve] = float(row.get("epss", "0") or 0.0)
            except Exception:
                continue
    return out


def enrich_vendor_product(cpe: str) -> tuple[str, str]:
    # cpe:2.3:a:vendor:product:version:...
    parts = cpe.split(":")
    if len(parts) < 6:
        return "", ""
    return parts[3], parts[4]


def main() -> None:
    parser = argparse.ArgumentParser(description="Build CVE intelligence catalog")
    parser.add_argument("--nvd-json", default="")
    parser.add_argument("--kev-json", default="")
    parser.add_argument("--epss-csv", default="")
    parser.add_argument("--fetch", action="store_true", help="download default feeds when file args are not provided")
    parser.add_argument("--nvd-url", default="https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000")
    parser.add_argument("--kev-url", default="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    parser.add_argument("--out", default="data/processed/cve_catalog.json")
    args = parser.parse_args()

    if args.nvd_json:
        nvd_doc = read_json(Path(args.nvd_json))
    elif args.fetch:
        nvd_doc = fetch_json(args.nvd_url)
    else:
        nvd_doc = {"vulnerabilities": []}

    if args.kev_json:
        kev_doc = read_json(Path(args.kev_json))
    elif args.fetch:
        kev_doc = fetch_json(args.kev_url)
    else:
        kev_doc = {"vulnerabilities": []}

    epss = parse_epss(Path(args.epss_csv)) if args.epss_csv else {}
    catalog = parse_nvd(nvd_doc)
    kev_set = parse_kev(kev_doc)
    for cve_id, item in catalog.items():
        item["kev"] = cve_id in kev_set
        item["epss"] = float(epss.get(cve_id, 0.0))
        for cpe in item.get("cpes", []):
            vendor, product = enrich_vendor_product(cpe)
            if vendor and not item["vendor"]:
                item["vendor"] = vendor
            if product and not item["product"]:
                item["product"] = product
        keywords = {item.get("vendor", ""), item.get("product", "")}
        item["keywords"] = sorted([x for x in keywords if x])

    rows = sorted(catalog.values(), key=lambda x: (1 if x.get("kev", False) else 0, x.get("epss", 0.0), x.get("cvss", 0.0)), reverse=True)
    write_json(
        Path(args.out),
        {
            "generated_records": len(rows),
            "generated_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "cves": rows,
        },
    )
    print(f"[cve-feed] out={args.out}")
    print(f"[cve-feed] records={len(rows)}")


if __name__ == "__main__":
    main()
