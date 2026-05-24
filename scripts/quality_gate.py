#!/usr/bin/env python3
"""Pre-submission quality gate for professional bug bounty findings."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import re
from pathlib import Path
from typing import Any

import yaml

from common import finding_signature, read_json, read_jsonl


def load_program_scope(config_path: Path, program_name: str) -> tuple[list[str], list[str]]:
    cfg = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    includes: list[str] = []
    excludes: list[str] = []
    for p in cfg.get("programs", []):
        if p.get("name") != program_name:
            continue
        includes.extend(p.get("in_scope", []))
        excludes.extend(p.get("out_of_scope", []))
    return includes, excludes


def host_in_scope(asset: str, include: list[str], exclude: list[str]) -> bool:
    a = asset.strip().lower()
    if not a or not include:
        return False
    included = any(fnmatch.fnmatch(a, pat.lower()) for pat in include)
    excluded = any(fnmatch.fnmatch(a, pat.lower()) for pat in exclude)
    return included and not excluded


def check_required_paths(finding: dict[str, Any], root: Path) -> list[str]:
    issues: list[str] = []
    ev = finding.get("evidence", {})
    req = root / ev.get("request_file", "")
    resp = root / ev.get("response_file", "")
    if not req.exists():
        issues.append(f"evidence.request_file missing: {req}")
    if not resp.exists():
        issues.append(f"evidence.response_file missing: {resp}")
    return issues


def compute_evidence_sha256(request_path: Path, response_path: Path) -> str:
    h = hashlib.sha256()
    h.update(request_path.read_bytes())
    h.update(b"\n---\n")
    h.update(response_path.read_bytes())
    return h.hexdigest()


def score_risk(finding: dict[str, Any], matrix_cfg: dict[str, Any]) -> float:
    weights = matrix_cfg["risk_model"]["score_weights"]
    rf = finding.get("risk_factors", {})
    score = (
        float(rf.get("technical_severity", 0)) * float(weights["technical_severity"]) +
        float(rf.get("exploitability", 0)) * float(weights["exploitability"]) +
        float(rf.get("asset_criticality", 0)) * float(weights["asset_criticality"]) +
        float(rf.get("acceptance_likelihood", 0)) * float(weights["acceptance_likelihood"])
    )
    return round(score, 2)


def risk_priority(score: float, matrix_cfg: dict[str, Any]) -> str:
    for band in matrix_cfg["risk_model"]["priority_bands"]:
        if score >= float(band["min_score"]):
            return str(band["name"])
    return "P4"


def check_schema_level(finding: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    required = [
        "id", "title", "program", "asset", "surface", "taxonomy",
        "reproduction", "business_impact", "evidence", "risk_factors", "timeline"
    ]
    for key in required:
        if key not in finding:
            issues.append(f"missing required field: {key}")
    tax = finding.get("taxonomy", {})
    if not tax.get("cwe"):
        issues.append("taxonomy.cwe is required")
    cvss = tax.get("cvss", {})
    if cvss.get("base_score") is None:
        issues.append("taxonomy.cvss.base_score is required")
    mitre = tax.get("mitre_attack", {})
    if mitre.get("applicable") and not mitre.get("techniques"):
        issues.append("taxonomy.mitre_attack.techniques required when applicable=true")
    return issues


def duplicate_likelihood(finding: dict[str, Any], known: list[dict[str, Any]]) -> bool:
    sig = finding_signature(finding)
    for item in known:
        if item.get("signature") == sig:
            return True
        if finding_signature(item) == sig:
            return True
    return False


def token_set(value: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", value.lower()) if t}


def semantic_duplicate_likelihood(finding: dict[str, Any], known: list[dict[str, Any]]) -> bool:
    title_tokens = token_set(str(finding.get("title", "")))
    endpoint_tokens = token_set(str(finding.get("endpoint", "")))
    union_a = title_tokens | endpoint_tokens
    if not union_a:
        return False

    for item in known:
        if item.get("program") != finding.get("program"):
            continue
        if item.get("asset") != finding.get("asset"):
            continue
        union_b = token_set(str(item.get("title", ""))) | token_set(str(item.get("endpoint", "")))
        if not union_b:
            continue
        sim = len(union_a & union_b) / max(1, len(union_a | union_b))
        if sim >= 0.75:
            return True
    return False


def advanced_duplicate_likelihood(finding: dict[str, Any], known: list[dict[str, Any]]) -> bool:
    bug_class = str(finding.get("bug_class", finding.get("category", ""))).lower()
    endpoint = str(finding.get("endpoint", "")).lower()
    title = str(finding.get("title", "")).lower()
    evidence = finding.get("evidence", {})
    ev_keys = set(evidence.keys()) if isinstance(evidence, dict) else set()

    for item in known:
        if str(item.get("program", "")).lower() != str(finding.get("program", "")).lower():
            continue
        if str(item.get("asset", "")).lower() != str(finding.get("asset", "")).lower():
            continue
        i_bug = str(item.get("bug_class", item.get("category", ""))).lower()
        if i_bug and bug_class and i_bug != bug_class:
            continue
        i_endpoint = str(item.get("endpoint", "")).lower()
        i_title = str(item.get("title", "")).lower()
        i_ev = item.get("evidence", {})
        i_ev_keys = set(i_ev.keys()) if isinstance(i_ev, dict) else set()

        title_sim = len(token_set(title) & token_set(i_title)) / max(1, len(token_set(title) | token_set(i_title)))
        ep_sim = 1.0 if endpoint and endpoint == i_endpoint else 0.0
        ev_sim = len(ev_keys & i_ev_keys) / max(1, len(ev_keys | i_ev_keys)) if (ev_keys or i_ev_keys) else 0.0
        score = (title_sim * 0.5) + (ep_sim * 0.35) + (ev_sim * 0.15)
        if score >= 0.75:
            return True
    return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Run quality gate before submission")
    parser.add_argument("--finding", required=True, help="Path to finding JSON")
    parser.add_argument("--programs", default="config/programs.yaml")
    parser.add_argument("--matrix", default="config/control-matrix.yaml")
    parser.add_argument("--known", default="data/findings/triaged_findings.jsonl")
    parser.add_argument("--workspace-root", default=".")
    args = parser.parse_args()

    workspace = Path(args.workspace_root).resolve()
    finding_path = Path(args.finding)
    programs_path = Path(args.programs)
    matrix_path = Path(args.matrix)
    known_path = Path(args.known)

    finding = read_json(finding_path)
    known = read_jsonl(known_path)
    matrix_cfg = yaml.safe_load(matrix_path.read_text(encoding="utf-8")) or {}

    checklist: dict[str, bool] = {
        "in_scope_confirmed": False,
        "repro_100_percent": False,
        "evidence_complete": False,
        "evidence_hash_valid": False,
        "business_impact_proven": False,
        "anti_false_positive_passed": False,
        "duplicate_unlikely": False
    }
    issues: list[str] = []

    issues.extend(check_schema_level(finding))

    include, exclude = load_program_scope(programs_path, finding.get("program", ""))
    checklist["in_scope_confirmed"] = host_in_scope(finding.get("asset", ""), include, exclude)
    if not checklist["in_scope_confirmed"]:
        issues.append("asset is not in allowed scope for the selected program")

    repro = finding.get("reproduction", {})
    checklist["repro_100_percent"] = bool(repro.get("verified")) and float(repro.get("success_rate", 0)) >= 1.0
    if not checklist["repro_100_percent"]:
        issues.append("reproduction must be verified with success_rate=1.0")

    ev = finding.get("evidence", {})
    checklist["evidence_complete"] = all(
        bool(ev.get(x)) for x in ["request_file", "response_file", "timestamp_utc", "sha256", "tool_versions"]
    )
    issues.extend(check_required_paths(finding, workspace))
    if not checklist["evidence_complete"]:
        issues.append("evidence fields are incomplete")
    else:
        req = workspace / ev["request_file"]
        resp = workspace / ev["response_file"]
        if req.exists() and resp.exists():
            actual_hash = compute_evidence_sha256(req, resp)
            checklist["evidence_hash_valid"] = actual_hash.lower() == str(ev.get("sha256", "")).lower()
            if not checklist["evidence_hash_valid"]:
                issues.append("evidence sha256 mismatch with request/response artifacts")

    bi = finding.get("business_impact", {})
    proof_artifacts = bi.get("proof_artifacts", [])
    if not isinstance(proof_artifacts, list):
        proof_artifacts = []
    checklist["business_impact_proven"] = (
        bool(bi.get("validated"))
        and len(str(bi.get("statement", "")).strip()) >= 15
        and len(proof_artifacts) >= 1
    )
    if not checklist["business_impact_proven"]:
        issues.append("business impact must include validated statement and proof_artifacts")

    validation = finding.get("validation", {})
    checklist["anti_false_positive_passed"] = bool(validation.get("control_check_passed")) and bool(
        validation.get("negative_test_passed")
    )
    if not checklist["anti_false_positive_passed"]:
        issues.append("anti-false-positive checks failed or missing")

    checklist["duplicate_unlikely"] = not (
        duplicate_likelihood(finding, known)
        or semantic_duplicate_likelihood(finding, known)
        or advanced_duplicate_likelihood(finding, known)
    )
    if not checklist["duplicate_unlikely"]:
        issues.append("probable duplicate (exact or semantic)")

    score = score_risk(finding, matrix_cfg)
    priority = risk_priority(score, matrix_cfg)
    all_pass = all(checklist.values()) and not issues

    print("[quality-gate] result=" + ("PASS" if all_pass else "FAIL"))
    print("[quality-gate] checklist=" + str(checklist))
    print(f"[quality-gate] risk_score={score} priority={priority}")
    if issues:
        print("[quality-gate] issues:")
        for issue in issues:
            print(f"- {issue}")

    raise SystemExit(0 if all_pass else 2)


if __name__ == "__main__":
    main()
