#!/usr/bin/env python3
"""Generate markdown report from finding JSON and template placeholders."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


REQUIRED_KEYS = ["title", "summary", "program", "asset"]


def build_context(finding: dict) -> dict[str, str]:
    tax = finding.get("taxonomy", {})
    cvss = tax.get("cvss", {})
    mitre = tax.get("mitre_attack", {})
    repro = finding.get("reproduction", {})
    impact = finding.get("business_impact", {})
    evidence = finding.get("evidence", {})

    context = {
        "id": str(finding.get("id", "<missing:id>")),
        "title": str(finding.get("title", "<missing:title>")),
        "summary": str(finding.get("summary", "<missing:summary>")),
        "program": str(finding.get("program", "<missing:program>")),
        "asset": str(finding.get("asset", "<missing:asset>")),
        "surface": str(finding.get("surface", "<missing:surface>")),
        "status": str(finding.get("status", "<missing:status>")),
        "endpoint": str(finding.get("endpoint", "")),
        "parameter": str(finding.get("parameter", "")),
        "cwe": ", ".join(tax.get("cwe", [])) or "<missing:cwe>",
        "owasp_refs": ", ".join(tax.get("owasp_refs", [])) or "<missing:owasp_refs>",
        "cvss_vector": str(cvss.get("vector", "<missing:cvss_vector>")),
        "cvss_score": str(cvss.get("base_score", "<missing:cvss_score>")),
        "cvss_severity": str(cvss.get("severity", "<missing:cvss_severity>")),
        "mitre_applicable": str(mitre.get("applicable", "<missing:mitre_applicable>")),
        "mitre_techniques": ", ".join(mitre.get("techniques", [])) or "n/a",
        "mitre_notes": str(mitre.get("notes", "")),
        "steps": str(repro.get("steps", "<missing:steps>")),
        "repro_verified": str(repro.get("verified", "<missing:repro_verified>")),
        "repro_success_rate": str(repro.get("success_rate", "<missing:repro_success_rate>")),
        "impact": str(impact.get("statement", "<missing:impact>")),
        "impact_validated": str(impact.get("validated", "<missing:impact_validated>")),
        "evidence_request": str(evidence.get("request_file", "<missing:evidence.request_file>")),
        "evidence_response": str(evidence.get("response_file", "<missing:evidence.response_file>")),
        "evidence_timestamp": str(evidence.get("timestamp_utc", "<missing:evidence.timestamp_utc>")),
        "evidence_sha256": str(evidence.get("sha256", "<missing:evidence.sha256>")),
        "tool_versions": ", ".join([f"{k}:{v}" for k, v in evidence.get("tool_versions", {}).items()]) or "<missing:tool_versions>",
        "remediation": str(finding.get("remediation", "<missing:remediation>"))
    }
    return context


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate bug bounty report draft")
    parser.add_argument("--template", required=True)
    parser.add_argument("--finding", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    template = Path(args.template).read_text(encoding="utf-8")
    finding = json.loads(Path(args.finding).read_text(encoding="utf-8"))

    for key in REQUIRED_KEYS:
        finding.setdefault(key, f"<missing:{key}>")

    report = template.format(**build_context(finding))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8")

    print(f"[report] generated={out}")


if __name__ == "__main__":
    main()
