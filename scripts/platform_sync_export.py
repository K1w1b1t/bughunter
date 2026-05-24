#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract platform sync details from engine findings")
    parser.add_argument("--findings", default="data/reports/engine/findings.json")
    parser.add_argument("--out", default="data/reports/engine/platform_sync.json")
    args = parser.parse_args()

    doc = json.loads(Path(args.findings).read_text(encoding="utf-8")) if Path(args.findings).exists() else {"findings": []}
    findings = doc.get("findings", [])
    sync_items: list[dict[str, Any]] = []
    for f in findings:
        if str(f.get("plugin")) == "platform_sync":
            sync_items.append(f)
    payload = {"count": len(sync_items), "items": sync_items}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(f"[platform-sync-export] out={args.out}")


if __name__ == "__main__":
    main()

