from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hunterops.async_io import read_json, write_json
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task


async def _load(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        doc = await read_json(path)
    except Exception:
        return []
    rows = doc.get("findings", []) if isinstance(doc, dict) else doc
    return [x for x in rows if isinstance(x, dict)]


class PluginImpl(Plugin):
    name = "evidence_collector"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        source = Path(cfg.get("findings_source", "data/reports/engine/findings.json"))
        out_dir = Path(cfg.get("out_dir", "data/evidence/engine_collected"))
        out_dir.mkdir(parents=True, exist_ok=True)
        rows = [r for r in await _load(source) if str(r.get("target", "")) == task.target]
        if not rows:
            return []

        bundles: list[dict[str, Any]] = []
        for i, r in enumerate(rows[:200], start=1):
            ev = r.get("evidence", {}) if isinstance(r.get("evidence"), dict) else {}
            rec = {
                "finding_title": r.get("title", ""),
                "plugin": r.get("plugin", ""),
                "target": task.target,
                "request": ev.get("request", {}),
                "response_metadata": ev.get("response", {}),
                "headers": ev.get("headers", {}),
                "timestamp": ev.get("timestamp") or datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "discovery_source": ev.get("discovery_source", (r.get("metadata", {}) or {}).get("discovery_source", r.get("plugin", ""))),
                "anomaly_indicators": ev.get("diff") or ev.get("response_diff") or {},
            }
            raw = json.dumps(rec, ensure_ascii=True, sort_keys=True)
            rec["evidence_id"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            bundles.append(rec)
            await write_json(out_dir / f"evidence_{i:03d}.json", rec)

        index = out_dir / "index.json"
        await write_json(index, {"target": task.target, "count": len(bundles), "evidence": bundles})
        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="evidence_collection",
                severity="info",
                title=f"Evidence collector stored {len(bundles)} structured evidence bundles",
                evidence={"index": str(index), "evidence_sample": bundles[:30]},
                metadata={"novelty": 60, "confidence": 90, "impact": 48, "discovery_source": "evidence_collector"},
            )
        ]
