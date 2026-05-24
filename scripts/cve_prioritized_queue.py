#!/usr/bin/env python3
"""Prioritize CVE relevance findings for manual validation and reporting."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from common import read_json, write_json


def score(row: dict[str, Any]) -> float:
    meta = row.get("metadata", {}) or {}
    risk = float(row.get("risk_score", 0.0) or 0.0)
    matcher = float(meta.get("matcher_score", 0.0) or 0.0)
    epss = float(meta.get("epss", 0.0) or 0.0)
    kev_bonus = 20.0 if bool(meta.get("kev", False)) else 0.0
    return round(min(100.0, risk * 0.55 + matcher * 0.30 + epss * 100.0 * 0.15 + kev_bonus), 2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build top-N CVE validation queue")
    parser.add_argument("--findings", default="data/reports/engine/findings.json")
    parser.add_argument("--out", default="data/reports/engine/cve_priority_queue.json")
    parser.add_argument("--top-n", type=int, default=25)
    args = parser.parse_args()

    rows = read_json(Path(args.findings))
    if isinstance(rows, dict):
        rows = rows.get("findings", [])
    selected: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("category", "")) != "cve_relevance":
            continue
        selected.append(
            {
                "plugin": row.get("plugin"),
                "target": row.get("target"),
                "title": row.get("title"),
                "severity": row.get("severity"),
                "risk_score": row.get("risk_score", 0),
                "score": score(row),
                "cve": (row.get("metadata", {}) or {}).get("cve"),
                "cvss": (row.get("metadata", {}) or {}).get("cvss"),
                "epss": (row.get("metadata", {}) or {}).get("epss"),
                "kev": (row.get("metadata", {}) or {}).get("kev"),
            }
        )
    selected.sort(key=lambda x: float(x.get("score", 0.0)), reverse=True)
    write_json(Path(args.out), {"top_n": args.top_n, "queue": selected[: args.top_n]})
    print(f"[cve-queue] out={args.out}")
    print(f"[cve-queue] selected={len(selected[: args.top_n])}")


if __name__ == "__main__":
    main()
