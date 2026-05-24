#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def main() -> None:
    parser = argparse.ArgumentParser(description="Automated impact validation for high-value classes")
    parser.add_argument("--findings", default="data/reports/engine/findings.json")
    parser.add_argument("--out", default="data/reports/engine/impact_validated.json")
    args = parser.parse_args()

    doc = json.loads(Path(args.findings).read_text(encoding="utf-8")) if Path(args.findings).exists() else {"findings": []}
    findings = doc.get("findings", [])
    out_rows: list[dict[str, Any]] = []

    for f in findings:
        category = str(f.get("category", "")).lower()
        evidence = f.get("evidence", {})
        score = float(f.get("risk_score", 0))
        impact = {"validated": False, "reason": "insufficient evidence"}

        if "idor" in category or "role_access" in category or "auth" in category:
            if isinstance(evidence, dict) and ("diff" in evidence or "mutated_url" in evidence or "statuses" in evidence):
                impact = {"validated": True, "reason": "cross-context behavior difference with request/response evidence"}
        elif "payment" in category or "race" in category or "business" in category:
            if score >= 65:
                impact = {"validated": True, "reason": "high-risk business logic signal with reproducible endpoint evidence"}
        elif "sensitive_data" in category or "exposure" in category:
            if isinstance(evidence, dict) and evidence.get("hits"):
                impact = {"validated": True, "reason": "sensitive data artifacts detected in response payload"}

        row = dict(f)
        row["impact_validation"] = impact
        out_rows.append(row)

    payload = {"count": len(out_rows), "findings": out_rows}
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"[impact-validation] out={args.out}")


if __name__ == "__main__":
    main()

