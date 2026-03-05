from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task


def _load(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    rows = doc.get("findings", []) if isinstance(doc, dict) else doc
    return [x for x in rows if isinstance(x, dict)]


def payloads_for_type(param_type: str) -> list[str]:
    t = param_type.lower()
    if t in {"numeric_id", "identifier", "object_reference"}:
        return ["0", "1", "2", "999999", "-1"]
    if t == "token":
        return ["token", "token.", "token-truncated", "Bearer token"]
    if t in {"search", "filter", "string"}:
        return ["test", "test%20value", "a+b", "%27test%27", "%22test%22"]
    if t == "email":
        return ["user@example.com", "user+alt@example.com"]
    if t == "boolean":
        return ["true", "false", "1", "0"]
    if t == "pagination":
        return ["1", "10", "100", "1000"]
    if t == "file_reference":
        return ["report.pdf", "avatar.png", "document.txt"]
    return ["test"]


class PluginImpl(Plugin):
    name = "smart_payload_engine"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        source = Path(cfg.get("parameter_source", "data/reports/engine/findings.json"))
        rows = [r for r in _load(source) if str(r.get("target", "")) == task.target and str(r.get("category", "")) == "parameter_intelligence"]
        if not rows:
            return []

        generated: list[dict[str, object]] = []
        for row in rows:
            ev = row.get("evidence", {}) if isinstance(row.get("evidence"), dict) else {}
            pmap = ev.get("parameter_map_sample", [])
            if not isinstance(pmap, list):
                continue
            for item in pmap[:300]:
                if not isinstance(item, dict):
                    continue
                p = str(item.get("parameter", ""))
                t = str(item.get("type", "string"))
                ep = str(item.get("endpoint", ""))
                generated.append({"endpoint": ep, "parameter": p, "type": t, "payloads": payloads_for_type(t)})

        if not generated:
            return []
        out = Path(cfg.get("out_file", "data/processed/smart_payloads.json"))
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({"target": task.target, "count": len(generated), "payloads": generated}, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="smart_payload_generation",
                severity="info",
                title=f"Smart payload engine generated payload sets for {len(generated)} parameter contexts",
                evidence={"payload_file": str(out), "payload_sample": generated[:80]},
                metadata={"novelty": 66, "confidence": 80, "impact": 42, "discovery_source": "smart_payload_engine"},
            )
        ]
