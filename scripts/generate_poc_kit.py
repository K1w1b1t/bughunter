#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


TARGET_CLASSES = {"idor_candidate", "auth_vs_unauth_behavior_change", "auth_token_control_weakness", "role_access_anomaly"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate PoC kit and submit-ready markdown")
    parser.add_argument("--findings", default="data/reports/engine/impact_validated.json")
    parser.add_argument("--out-dir", default="data/reports/engine/poc_kits")
    parser.add_argument("--top-n", type=int, default=10)
    args = parser.parse_args()

    doc = json.loads(Path(args.findings).read_text(encoding="utf-8")) if Path(args.findings).exists() else {"findings": []}
    findings = doc.get("findings", [])
    selected = []
    for f in findings:
        cat = str(f.get("category", "")).lower()
        iv = f.get("impact_validation", {})
        if cat in TARGET_CLASSES and iv.get("validated"):
            selected.append(f)
    selected = selected[: args.top_n]

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = []
    for i, f in enumerate(selected, start=1):
        fid = f"POC-{i:04d}"
        ev = f.get("evidence", {})
        request_file = ev.get("request_file", "")
        response_file = ev.get("response_file", "")
        impact = f.get("impact_validation", {}).get("reason", "")
        md = (
            f"# {f.get('title','Untitled')}\n\n"
            f"## Target\n{f.get('target','')}\n\n"
            f"## Category\n{f.get('category','')}\n\n"
            f"## Impact Summary\n{impact}\n\n"
            f"## Evidence\n- Request: `{request_file}`\n- Response: `{response_file}`\n\n"
            "## Reproduction (Auto Draft)\n"
            "1. Use the provided request artifact.\n"
            "2. Replay with alternate context/ID/token based on evidence.\n"
            "3. Confirm unauthorized or behavior-changing response.\n"
        )
        (out_dir / f"{fid}.md").write_text(md, encoding="utf-8")
        summary.append({"id": fid, "title": f.get("title"), "target": f.get("target"), "file": str(out_dir / f"{fid}.md")})

    (out_dir / "index.json").write_text(json.dumps({"count": len(summary), "kits": summary}, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"[poc-kit] generated={len(summary)} out={out_dir}")


if __name__ == "__main__":
    main()

