#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def main() -> None:
    parser = argparse.ArgumentParser(description="Delta-first prioritization queue")
    parser.add_argument("--findings", default="data/reports/engine/findings.json")
    parser.add_argument("--baseline-diff", default="data/reports/engine/baseline_diff.json")
    parser.add_argument("--out", default="data/reports/engine/delta_first_queue.json")
    parser.add_argument("--top-n", type=int, default=30)
    args = parser.parse_args()

    findings_doc = json.loads(Path(args.findings).read_text(encoding="utf-8")) if Path(args.findings).exists() else {"findings": []}
    rows = findings_doc.get("findings", [])
    diff_doc = json.loads(Path(args.baseline_diff).read_text(encoding="utf-8")) if Path(args.baseline_diff).exists() else {"diffs": []}
    diffs = {d.get("key", ""): d for d in diff_doc.get("diffs", [])}

    scored: list[dict[str, Any]] = []
    for r in rows:
        key = f"{r.get('plugin')}|{r.get('target')}|{r.get('title')}"
        s = float(r.get("risk_score", 0))
        d = diffs.get(key)
        if d:
            if d.get("type") == "new":
                s += 20
            elif d.get("type") == "changed":
                s += 15
        cat = str(r.get("category", "")).lower()
        if "auth" in cat or "idor" in cat:
            s += 10
        scored.append({"key": key, "target": r.get("target"), "title": r.get("title"), "score": round(min(100, s), 2), "category": r.get("category")})

    scored.sort(key=lambda x: x["score"], reverse=True)
    out = {"top_n": args.top_n, "queue": scored[: args.top_n]}
    p = Path(args.out)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(out, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"[delta-first] out={args.out} selected={len(out['queue'])}")


if __name__ == "__main__":
    main()

