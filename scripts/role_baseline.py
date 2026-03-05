#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def main() -> None:
    parser = argparse.ArgumentParser(description="Maintain baseline per session/role from findings evidence")
    parser.add_argument("--findings", default="data/reports/engine/findings.json")
    parser.add_argument("--baseline", default="data/reports/engine/role_baseline.json")
    parser.add_argument("--out-diff", default="data/reports/engine/role_baseline_diff.json")
    args = parser.parse_args()

    doc = json.loads(Path(args.findings).read_text(encoding="utf-8")) if Path(args.findings).exists() else {"findings": []}
    rows = doc.get("findings", [])
    base_path = Path(args.baseline)
    baseline = json.loads(base_path.read_text(encoding="utf-8")) if base_path.exists() else {"entries": {}}
    entries = baseline.get("entries", {})
    diffs: list[dict[str, Any]] = []

    for r in rows:
        ev = r.get("evidence", {})
        if not isinstance(ev, dict):
            continue
        session = str(ev.get("session", ""))
        target = str(r.get("target", ""))
        category = str(r.get("category", ""))
        if not session:
            continue
        key = f"{target}|{session}|{category}"
        current = {
            "risk_score": r.get("risk_score", 0),
            "title": r.get("title", ""),
            "diff": ev.get("diff", {}),
        }
        prev = entries.get(key)
        if prev and prev != current:
            diffs.append({"key": key, "old": prev, "new": current})
        entries[key] = current

    baseline["entries"] = entries
    base_path.parent.mkdir(parents=True, exist_ok=True)
    base_path.write_text(json.dumps(baseline, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    out = {"diffs": diffs, "count": len(diffs)}
    Path(args.out_diff).write_text(json.dumps(out, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"[role-baseline] diffs={len(diffs)} out={args.out_diff}")


if __name__ == "__main__":
    main()

