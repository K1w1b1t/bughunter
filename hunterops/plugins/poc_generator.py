from __future__ import annotations

from pathlib import Path
from typing import Any

from hunterops.async_io import read_json, write_json
from hunterops.findings import calculate_impact
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task


async def _load_previous_findings(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        doc = await read_json(path)
    except Exception:
        return []
    if isinstance(doc, dict):
        rows = doc.get("findings", [])
    else:
        rows = doc
    return [x for x in rows if isinstance(x, dict)]


def _business_impact_text(impact_score: float) -> str:
    score = float(impact_score)
    if score >= 90.0:
        return (
            "Potential financial loss per transaction: High. "
            "A successful exploit could allow unauthorized transfers, balance manipulation, or free-order completion."
        )
    if score >= 70.0:
        return (
            "Potential financial loss per transaction: Medium-High. "
            "Attackers may tamper with transactional values or access protected resources across accounts."
        )
    if score >= 50.0:
        return (
            "Potential financial loss per transaction: Medium. "
            "The issue can degrade business controls and may expose sensitive object-level data."
        )
    return (
        "Potential financial loss per transaction: Low. "
        "Operational and trust impact is plausible and should be validated with additional probes."
    )


class PluginImpl(Plugin):
    name = "poc_generator"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        source = Path(cfg.get("findings_source", "data/reports/engine/findings.json"))
        out_dir = Path(cfg.get("out_dir", "data/reports/engine/poc_auto"))
        out_dir.mkdir(parents=True, exist_ok=True)
        rows = await _load_previous_findings(source)
        if not rows:
            return []

        interesting = []
        for r in rows:
            if str(r.get("target", "")) != task.target:
                continue
            cat = str(r.get("category", "")).lower()
            if any(
                k in cat
                for k in (
                    "idor",
                    "auth",
                    "response_anomaly",
                    "sensitive",
                    "cors",
                    "debug",
                    "financial",
                    "coupon",
                    "currency",
                    "state_machine",
                    "race_condition",
                )
            ):
                interesting.append(r)
        interesting = interesting[:25]
        if not interesting:
            return []

        generated: list[dict[str, str]] = []
        for i, r in enumerate(interesting, start=1):
            title = str(r.get("title", "Finding")).strip() or "Finding"
            category = str(r.get("category", ""))
            ev = r.get("evidence", {}) if isinstance(r.get("evidence"), dict) else {}
            metadata = r.get("metadata", {}) if isinstance(r.get("metadata"), dict) else {}
            req1 = ev.get("base_url") or ev.get("url") or ev.get("modified_url") or ""
            req2 = ev.get("variant_url") or ev.get("mutated_url") or ""
            impact_profile = calculate_impact(
                Finding(
                    plugin=str(r.get("plugin", self.name)),
                    target=task.target,
                    category=category,
                    severity=str(r.get("severity", "medium")),
                    title=title,
                    evidence=ev,
                    metadata=metadata,
                )
            )
            impact_score = float(impact_profile.get("impact_score", 50.0) or 50.0)
            business_impact = _business_impact_text(impact_score)
            poc = {
                "title": title,
                "category": category,
                "target": task.target,
                "request_sequence": [x for x in [req1, req2] if x],
                "observed_behavior": str(ev.get("diff", ""))[:500],
                "confidence": str(metadata.get("confidence", "")),
                "impact_score": impact_score,
                "adjusted_severity": str(impact_profile.get("adjusted_severity", "medium")),
                "business_impact": business_impact,
                "business_impact_section": f"## Business Impact\n{business_impact}",
            }
            p = out_dir / f"poc_{i:03d}.json"
            await write_json(p, poc)
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
