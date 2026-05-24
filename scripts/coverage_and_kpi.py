#!/usr/bin/env python3
"""Generate coverage, gaps backlog, risk ranking, and weekly KPI report."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from common import read_jsonl, write_json


def parse_week(value: str) -> str:
    datetime.strptime(value, "%Y-%m-%d")
    return value


def calc_risk_score(finding: dict[str, Any], matrix: dict[str, Any]) -> float:
    w = matrix["risk_model"]["score_weights"]
    rf = finding.get("risk_factors", {})
    return round(
        float(rf.get("technical_severity", 0)) * float(w["technical_severity"]) +
        float(rf.get("exploitability", 0)) * float(w["exploitability"]) +
        float(rf.get("asset_criticality", 0)) * float(w["asset_criticality"]) +
        float(rf.get("acceptance_likelihood", 0)) * float(w["acceptance_likelihood"]),
        2
    )


def build_program_coverage(findings: list[dict[str, Any]], matrix: dict[str, Any]) -> dict[str, Any]:
    required_surfaces = set(matrix["baseline"]["required_surfaces"])
    controls = matrix.get("test_controls", [])

    expected_owasp: set[str] = set()
    expected_mitre: set[str] = set()
    for c in controls:
        o = c.get("owasp", {})
        expected_owasp.update(o.get("wstg", []))
        expected_owasp.update(o.get("asvs", []))
        expected_owasp.update(o.get("api_top_10", []))
        expected_mitre.update(c.get("mitre_attack", []))

    by_program: dict[str, Any] = defaultdict(lambda: {
        "surfaces": set(),
        "owasp_refs": set(),
        "mitre_techniques": set(),
        "findings": 0
    })

    for f in findings:
        p = f.get("program", "unknown")
        by_program[p]["findings"] += 1
        if f.get("surface"):
            by_program[p]["surfaces"].add(f["surface"])
        tax = f.get("taxonomy", {})
        by_program[p]["owasp_refs"].update(tax.get("owasp_refs", []))
        m = tax.get("mitre_attack", {})
        by_program[p]["mitre_techniques"].update(m.get("techniques", []))

    report: dict[str, Any] = {}
    for p, obj in by_program.items():
        missing_surfaces = sorted(required_surfaces - obj["surfaces"])
        missing_owasp = sorted(expected_owasp - obj["owasp_refs"])
        missing_mitre = sorted(expected_mitre - obj["mitre_techniques"])
        report[p] = {
            "findings": obj["findings"],
            "coverage": {
                "surfaces_covered": sorted(obj["surfaces"]),
                "owasp_covered": sorted(obj["owasp_refs"]),
                "mitre_covered": sorted(obj["mitre_techniques"])
            },
            "gaps": {
                "missing_surfaces": missing_surfaces,
                "missing_owasp_refs": missing_owasp,
                "missing_mitre_techniques": missing_mitre
            }
        }
    return report


def build_gap_backlog(program_coverage: dict[str, Any], out_path: Path) -> None:
    backlog: list[dict[str, Any]] = []
    for program, info in program_coverage.items():
        for s in info["gaps"]["missing_surfaces"]:
            backlog.append({
                "program": program,
                "type": "surface-gap",
                "item": s,
                "priority": "high",
                "action": f"Run focused assessment workflow for {s} surface"
            })
        for o in info["gaps"]["missing_owasp_refs"]:
            backlog.append({
                "program": program,
                "type": "owasp-gap",
                "item": o,
                "priority": "medium",
                "action": f"Add test case mapped to {o}"
            })
        for m in info["gaps"]["missing_mitre_techniques"]:
            backlog.append({
                "program": program,
                "type": "mitre-gap",
                "item": m,
                "priority": "medium",
                "action": f"Add detection/testing hypothesis for {m}"
            })
    write_json(out_path, {"generated_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"), "backlog": backlog})


def weekly_kpis(submissions: list[dict[str, Any]], week_start: str) -> dict[str, Any]:
    start = datetime.strptime(week_start, "%Y-%m-%d")
    in_week: list[dict[str, Any]] = []
    for s in submissions:
        submitted = s.get("submitted_utc", "")
        if not submitted:
            continue
        dt = datetime.fromisoformat(submitted.replace("Z", "+00:00")).replace(tzinfo=None)
        if (dt - start).days < 0 or (dt - start).days >= 7:
            continue
        in_week.append(s)

    total = len(in_week)
    accepted = sum(1 for x in in_week if x.get("result") == "accepted")
    duplicates = sum(1 for x in in_week if x.get("result") == "duplicate")
    payout = sum(float(x.get("payout_usd", 0)) for x in in_week)
    hours = sum(float(x.get("hours_spent", 0)) for x in in_week)

    avg_hours_to_submit = 0.0
    deltas: list[float] = []
    for x in in_week:
        first_seen = x.get("first_seen_utc")
        submitted = x.get("submitted_utc")
        if first_seen and submitted:
            t1 = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
            t2 = datetime.fromisoformat(submitted.replace("Z", "+00:00"))
            deltas.append((t2 - t1).total_seconds() / 3600)
    if deltas:
        avg_hours_to_submit = round(sum(deltas) / len(deltas), 2)

    by_program: dict[str, dict[str, float]] = defaultdict(lambda: {"payout": 0.0, "hours": 0.0, "count": 0.0})
    acceptance_by_class: Counter[str] = Counter()
    total_by_class: Counter[str] = Counter()
    duplicate_by_surface: Counter[str] = Counter()
    total_by_surface: Counter[str] = Counter()

    for s in in_week:
        p = str(s.get("program", "unknown"))
        by_program[p]["payout"] += float(s.get("payout_usd", 0))
        by_program[p]["hours"] += float(s.get("hours_spent", 0))
        by_program[p]["count"] += 1

        bug_class = str(s.get("bug_class", "unknown"))
        total_by_class[bug_class] += 1
        if s.get("result") == "accepted":
            acceptance_by_class[bug_class] += 1

        surface = str(s.get("surface", "unknown"))
        total_by_surface[surface] += 1
        if s.get("result") == "duplicate":
            duplicate_by_surface[surface] += 1

    payout_per_hour_by_program = {
        k: round(v["payout"] / v["hours"], 2) if v["hours"] else 0.0 for k, v in by_program.items()
    }
    acceptance_rate_by_class = {
        k: round((acceptance_by_class[k] / total_by_class[k]) * 100, 2) for k in total_by_class
    }
    duplicate_rate_by_surface = {
        k: round((duplicate_by_surface[k] / total_by_surface[k]) * 100, 2) for k in total_by_surface
    }

    return {
        "week_start": week_start,
        "total_submissions": total,
        "acceptance_rate": round((accepted / total) * 100, 2) if total else 0.0,
        "duplicate_rate": round((duplicates / total) * 100, 2) if total else 0.0,
        "avg_time_to_submission_hours": avg_hours_to_submit,
        "payout_per_hour_usd": round(payout / hours, 2) if hours else 0.0,
        "total_payout_usd": round(payout, 2),
        "total_hours": round(hours, 2),
        "payout_per_hour_by_program": payout_per_hour_by_program,
        "acceptance_rate_by_bug_class": acceptance_rate_by_class,
        "duplicate_rate_by_surface": duplicate_rate_by_surface,
    }


def top_priority_queue(findings: list[dict[str, Any]], matrix: dict[str, Any], top_n: int) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    for f in findings:
        score = calc_risk_score(f, matrix)
        enriched.append({
            "id": f.get("id"),
            "program": f.get("program"),
            "asset": f.get("asset"),
            "title": f.get("title"),
            "score": score
        })
    enriched.sort(key=lambda x: x["score"], reverse=True)
    return enriched[:top_n]


def main() -> None:
    parser = argparse.ArgumentParser(description="Coverage, gaps and KPI reporter")
    parser.add_argument("--findings", default="data/findings/triaged_findings.jsonl")
    parser.add_argument("--submissions", default="data/findings/submissions.jsonl")
    parser.add_argument("--matrix", default="config/control-matrix.yaml")
    parser.add_argument("--week-start", required=True, type=parse_week)
    parser.add_argument("--out-report", default="data/reports/coverage_report.json")
    parser.add_argument("--out-backlog", default="data/findings/backlog_gaps.json")
    parser.add_argument("--out-kpi", default="data/reports/weekly_kpis.json")
    parser.add_argument("--out-priority", default="data/reports/top_priority_queue.json")
    parser.add_argument("--top-n", type=int, default=15)
    args = parser.parse_args()

    findings = read_jsonl(Path(args.findings))
    submissions = read_jsonl(Path(args.submissions))
    matrix = yaml.safe_load(Path(args.matrix).read_text(encoding="utf-8")) or {}

    coverage = build_program_coverage(findings, matrix)
    write_json(
        Path(args.out_report),
        {
            "generated_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "program_coverage": coverage,
        },
    )
    build_gap_backlog(coverage, Path(args.out_backlog))

    kpi = weekly_kpis(submissions, args.week_start)
    write_json(Path(args.out_kpi), kpi)

    top_queue = top_priority_queue(findings, matrix, args.top_n)
    write_json(
        Path(args.out_priority),
        {
            "generated_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "top_priority_findings": top_queue,
        },
    )

    print("[coverage-kpi] coverage_report=" + args.out_report)
    print("[coverage-kpi] backlog_gaps=" + args.out_backlog)
    print("[coverage-kpi] weekly_kpi=" + args.out_kpi)
    print("[coverage-kpi] priority_queue=" + args.out_priority)


if __name__ == "__main__":
    main()
