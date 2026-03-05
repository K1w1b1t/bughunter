#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Build adaptive score weights from triage/payout history")
    parser.add_argument("--submissions", default="data/findings/submissions.jsonl")
    parser.add_argument("--findings", default="data/reports/engine/findings.json")
    parser.add_argument("--out", default="data/processed/feedback_weights.json")
    args = parser.parse_args()

    submissions = read_jsonl(Path(args.submissions))
    findings_doc = json.loads(Path(args.findings).read_text(encoding="utf-8")) if Path(args.findings).exists() else {"findings": []}
    findings = findings_doc.get("findings", [])

    # category payout/acceptance based adjustments
    cat_stats: dict[str, dict[str, float]] = defaultdict(lambda: {"count": 0.0, "accepted": 0.0, "payout": 0.0})
    asset_stats: dict[str, dict[str, float]] = defaultdict(lambda: {"count": 0.0, "accepted": 0.0, "payout": 0.0})
    for s in submissions:
        c = str(s.get("bug_class", "unknown"))
        cat_stats[c]["count"] += 1
        cat_stats[c]["payout"] += float(s.get("payout_usd", 0))
        if s.get("result") == "accepted":
            cat_stats[c]["accepted"] += 1
        a = str(s.get("asset", ""))
        if a:
            asset_stats[a]["count"] += 1
            asset_stats[a]["payout"] += float(s.get("payout_usd", 0))
            if s.get("result") == "accepted":
                asset_stats[a]["accepted"] += 1

    category_adjustments: dict[str, float] = {}
    for c, st in cat_stats.items():
        count = max(1.0, st["count"])
        acc = st["accepted"] / count
        avg_pay = st["payout"] / count
        adj = (acc * 12.0) + min(12.0, avg_pay / 150.0) - 4.0
        category_adjustments[c] = round(adj, 2)

    plugin_stats: dict[str, dict[str, float]] = defaultdict(lambda: {"count": 0.0, "high": 0.0})
    for f in findings:
        p = str(f.get("plugin", "unknown"))
        plugin_stats[p]["count"] += 1
        if float(f.get("risk_score", 0)) >= 70:
            plugin_stats[p]["high"] += 1

    plugin_adjustments: dict[str, float] = {}
    for p, st in plugin_stats.items():
        rate = st["high"] / max(1.0, st["count"])
        plugin_adjustments[p] = round((rate - 0.5) * 10.0, 2)

    asset_adjustments: dict[str, float] = {}
    for a, st in asset_stats.items():
        count = max(1.0, st["count"])
        acc = st["accepted"] / count
        avg_pay = st["payout"] / count
        asset_adjustments[a] = round((acc * 10.0) + min(10.0, avg_pay / 200.0) - 3.0, 2)

    payload = {
        "category_adjustments": category_adjustments,
        "plugin_adjustments": plugin_adjustments,
        "asset_adjustments": asset_adjustments,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"[feedback-loop] out={args.out}")


if __name__ == "__main__":
    main()
