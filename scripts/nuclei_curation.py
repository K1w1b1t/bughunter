#!/usr/bin/env python3
"""Curate nuclei templates into high-signal and noise sets using performance history."""

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

import yaml

from common import read_jsonl, write_json


def main() -> None:
    parser = argparse.ArgumentParser(description="Nuclei template curation")
    parser.add_argument("--signals", default="data/findings/nuclei_signals.jsonl")
    parser.add_argument("--curation", default="config/nuclei-curation.yaml")
    parser.add_argument("--out", default="data/reports/nuclei_curation.json")
    args = parser.parse_args()

    signals = read_jsonl(Path(args.signals))
    cfg = yaml.safe_load(Path(args.curation).read_text(encoding="utf-8")) or {}
    min_acceptance = float(cfg.get("min_acceptance_rate", 0.25))
    min_payout = float(cfg.get("min_payout_usd", 150))
    high_tags = set(cfg.get("high_signal_tags", []))
    noise_tags = set(cfg.get("noise_tags", []))

    stats: dict[str, dict[str, float]] = defaultdict(lambda: {"hits": 0, "accepted": 0, "payout": 0.0})
    tag_map: dict[str, set[str]] = defaultdict(set)

    for s in signals:
        tid = str(s.get("template_id", "")).strip()
        if not tid:
            continue
        stats[tid]["hits"] += 1
        if s.get("accepted"):
            stats[tid]["accepted"] += 1
        stats[tid]["payout"] += float(s.get("payout_usd", 0))
        tags = s.get("tags", [])
        if isinstance(tags, list):
            for t in tags:
                tag_map[tid].add(str(t))

    high_signal: list[dict[str, float | str]] = []
    noise: list[dict[str, float | str]] = []
    neutral: list[dict[str, float | str]] = []

    for tid, st in stats.items():
        hits = max(1.0, st["hits"])
        acceptance_rate = st["accepted"] / hits
        avg_payout = st["payout"] / hits
        tags = tag_map.get(tid, set())
        rec = {
            "template_id": tid,
            "acceptance_rate": round(acceptance_rate, 4),
            "avg_payout": round(avg_payout, 2),
            "hits": int(st["hits"]),
        }

        if (acceptance_rate >= min_acceptance and avg_payout >= min_payout) or (tags & high_tags):
            high_signal.append(rec)
        elif tags & noise_tags:
            noise.append(rec)
        else:
            neutral.append(rec)

    payload = {"high_signal": high_signal, "neutral": neutral, "noise": noise}
    write_json(Path(args.out), payload)
    print("[nuclei-curation] out=" + args.out)
    print(f"[nuclei-curation] high={len(high_signal)} neutral={len(neutral)} noise={len(noise)}")


if __name__ == "__main__":
    main()
