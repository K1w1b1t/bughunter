#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml


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
    parser = argparse.ArgumentParser(description="Calibrate program profiles from real submissions")
    parser.add_argument("--profiles", default="config/program_profiles.yaml")
    parser.add_argument("--submissions", default="data/findings/submissions.jsonl")
    parser.add_argument("--out", default="config/program_profiles.calibrated.yaml")
    args = parser.parse_args()

    prof_path = Path(args.profiles)
    cfg = yaml.safe_load(prof_path.read_text(encoding="utf-8")) or {}
    submissions = read_jsonl(Path(args.submissions))

    by_program: dict[str, dict[str, float]] = defaultdict(lambda: {"count": 0.0, "accepted": 0.0, "payout": 0.0, "dup": 0.0})
    for s in submissions:
        p = str(s.get("program", "unknown"))
        by_program[p]["count"] += 1
        by_program[p]["payout"] += float(s.get("payout_usd", 0))
        if s.get("result") == "accepted":
            by_program[p]["accepted"] += 1
        if s.get("result") == "duplicate":
            by_program[p]["dup"] += 1

    for p in cfg.get("program_profiles", []):
        name = p.get("name", "")
        st = by_program.get(name)
        if not st:
            continue
        count = max(1.0, st["count"])
        hist = p.setdefault("historical_performance", {})
        hist["acceptance_rate"] = round(st["accepted"] / count, 4)
        hist["duplicate_rate"] = round(st["dup"] / count, 4)
        hist["avg_payout_usd"] = round(st["payout"] / count, 2)

        bias = p.setdefault("scoring_bias", {})
        # adaptive tuning: increase acceptance weight when accepted rate is high
        acc = hist["acceptance_rate"]
        bias["acceptance_weight"] = round(min(0.4, max(0.15, 0.2 + acc * 0.2)), 2)
        # increase payout weight as avg payout grows
        payout = hist["avg_payout_usd"]
        bias["payout_weight"] = round(min(0.4, max(0.15, 0.2 + min(1.0, payout / 2000) * 0.2)), 2)

    Path(args.out).write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    print(f"[calibrate] out={args.out}")


if __name__ == "__main__":
    main()

