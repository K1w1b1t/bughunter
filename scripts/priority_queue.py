#!/usr/bin/env python3
"""Build daily top-N hunt queue using risk, novelty and program performance profile."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml

from common import read_json, read_jsonl, write_json


def load_profiles(path: Path) -> dict[str, Any]:
    cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out: dict[str, Any] = {}
    for p in cfg.get("program_profiles", []):
        out[p.get("name", "")] = p
    return out


def novelty_lookup(delta: dict[str, Any]) -> set[str]:
    d = delta.get("delta", {})
    novelty_assets: set[str] = set()
    for s in d.get("new_subdomains", []):
        novelty_assets.add(s)
    for e in d.get("new_endpoints", []):
        try:
            host = e.split("/")[2]
            novelty_assets.add(host)
        except Exception:
            pass
    return novelty_assets


def score_item(item: dict[str, Any], profile: dict[str, Any], novelty_assets: set[str]) -> float:
    rf = item.get("risk_factors", {})
    technical = float(rf.get("technical_severity", 0))
    criticality = float(rf.get("asset_criticality", 0))
    acceptance = float(rf.get("acceptance_likelihood", 0))

    profile_perf = profile.get("historical_performance", {})
    payout = float(profile_perf.get("avg_payout_usd", 0))
    payout_norm = min(100.0, payout / 20.0)
    novelty = 100.0 if str(item.get("asset", "")) in novelty_assets else 0.0

    weights = profile.get("scoring_bias", {})
    novelty_w = float(weights.get("novelty_weight", 0.30))
    payout_w = float(weights.get("payout_weight", 0.30))
    acceptance_w = float(weights.get("acceptance_weight", 0.25))
    criticality_w = float(weights.get("criticality_weight", 0.15))

    return round(
        novelty * novelty_w + payout_norm * payout_w + acceptance * acceptance_w + max(technical, criticality) * criticality_w,
        2,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Daily priority queue generator")
    parser.add_argument("--findings", default="data/findings/triaged_findings.jsonl")
    parser.add_argument("--profiles", default="config/program_profiles.yaml")
    parser.add_argument("--delta", default="data/reports/delta_recon.json")
    parser.add_argument("--out", default="data/reports/daily_priority_queue.json")
    parser.add_argument("--top-n", type=int, default=20)
    args = parser.parse_args()

    findings = read_jsonl(Path(args.findings))
    profiles = load_profiles(Path(args.profiles))
    delta = read_json(Path(args.delta)) if Path(args.delta).exists() else {"delta": {}}
    novelty_assets = novelty_lookup(delta)

    ranked: list[dict[str, Any]] = []
    for f in findings:
        program = str(f.get("program", ""))
        profile = profiles.get(program, {})
        score = score_item(f, profile, novelty_assets)
        ranked.append(
            {
                "id": f.get("id"),
                "program": program,
                "asset": f.get("asset"),
                "title": f.get("title"),
                "score": score,
                "surface": f.get("surface"),
            }
        )
    ranked.sort(key=lambda x: float(x["score"]), reverse=True)
    payload = {"top_n": args.top_n, "queue": ranked[: args.top_n]}
    write_json(Path(args.out), payload)
    print("[priority-queue] out=" + args.out)
    print("[priority-queue] selected=" + str(len(payload["queue"])))


if __name__ == "__main__":
    main()
