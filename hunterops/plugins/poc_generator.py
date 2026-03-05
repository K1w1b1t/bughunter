from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task


def _load_previous_findings(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if isinstance(doc, dict):
        rows = doc.get("findings", [])
    else:
        rows = doc
    return [x for x in rows if isinstance(x, dict)]


class PluginImpl(Plugin):
    name = "poc_generator"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        source = Path(cfg.get("findings_source", "data/reports/engine/findings.json"))
        out_dir = Path(cfg.get("out_dir", "data/reports/engine/poc_auto"))
        out_dir.mkdir(parents=True, exist_ok=True)
        rows = _load_previous_findings(source)
        if not rows:
            return []

        interesting = []
        for r in rows:
            if str(r.get("target", "")) != task.target:
                continue
            cat = str(r.get("category", "")).lower()
            if any(k in cat for k in ("idor", "auth", "response_anomaly", "sensitive", "cors", "debug")):
                interesting.append(r)
        interesting = interesting[:25]
        if not interesting:
            return []

        generated: list[dict[str, str]] = []
        for i, r in enumerate(interesting, start=1):
            title = str(r.get("title", "Finding")).strip() or "Finding"
            ev = r.get("evidence", {}) if isinstance(r.get("evidence"), dict) else {}
            req1 = ev.get("base_url") or ev.get("url") or ev.get("modified_url") or ""
            req2 = ev.get("variant_url") or ev.get("mutated_url") or ""
            poc = {
                "title": title,
                "category": str(r.get("category", "")),
                "target": task.target,
                "request_sequence": [x for x in [req1, req2] if x],
                "observed_behavior": str(ev.get("diff", ""))[:500],
                "confidence": str((r.get("metadata", {}) or {}).get("confidence", "")),
            }
            p = out_dir / f"poc_{i:03d}.json"
            p.write_text(json.dumps(poc, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
            generated.append({"title": title, "path": str(p)})

        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="poc_generation",
                severity="info",
                title=f"Auto PoC generator created {len(generated)} reproducible artifacts",
                evidence={"generated_pocs": generated[:50], "out_dir": str(out_dir)},
                metadata={"novelty": 64, "confidence": 82, "impact": 50, "discovery_source": "poc_generator"},
            )
        ]
