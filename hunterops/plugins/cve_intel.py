from __future__ import annotations

from pathlib import Path
from typing import Any

from hunterops.async_io import read_json
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task


async def load_catalog(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        payload = await read_json(path)
    except Exception:
        return []
    if isinstance(payload, dict):
        rows = payload.get("cves", [])
    else:
        rows = payload
    if not isinstance(rows, list):
        return []
    return [x for x in rows if isinstance(x, dict)]


class PluginImpl(Plugin):
    name = "cve_intel"

    async def run(self, task: Task, context: dict[str, Any]) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        catalog = await load_catalog(Path(cfg.get("catalog_file", "data/processed/cve_catalog.json")))
        if not catalog:
            return []

        top = sorted(
            catalog,
            key=lambda c: (
                1 if c.get("kev", False) else 0,
                float(c.get("epss", 0.0) or 0.0),
                float(c.get("cvss", 0.0) or 0.0),
            ),
            reverse=True,
        )[:10]
        summary = [
            {
                "cve": str(item.get("cve", "")),
                "cvss": item.get("cvss"),
                "epss": item.get("epss"),
                "kev": bool(item.get("kev", False)),
            }
            for item in top
            if item.get("cve")
        ]
        if not summary:
            return []

        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="cve_intelligence",
                severity="info",
                title=f"CVE intelligence loaded ({len(catalog)} records)",
                evidence={"top_candidates": summary},
                metadata={"novelty": 35, "confidence": 70, "impact": 25},
            )
        ]
