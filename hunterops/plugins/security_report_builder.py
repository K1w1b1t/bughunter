from __future__ import annotations

import html
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

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


def _sev(score: float) -> str:
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 45:
        return "Medium"
    return "Low"


class PluginImpl(Plugin):
    name = "security_report_builder"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        source = Path(cfg.get("findings_source", "data/reports/engine/findings.json"))
        out_dir = Path(cfg.get("out_dir", "data/reports/engine/security_reports"))
        out_dir.mkdir(parents=True, exist_ok=True)
        rows = [r for r in _load(source) if str(r.get("target", "")) == task.target]
        if not rows:
            return []

        items: list[dict[str, Any]] = []
        for r in rows[:120]:
            ev = r.get("evidence", {}) if isinstance(r.get("evidence"), dict) else {}
            meta = r.get("metadata", {}) if isinstance(r.get("metadata"), dict) else {}
            endpoint = str(ev.get("base_url") or ev.get("url") or ev.get("modified_url") or ev.get("variant_url") or "")
            score = float(r.get("risk_score", 0) or 0)
            items.append(
                {
                    "title": str(r.get("title", "")),
                    "severity_estimation": _sev(score),
                    "description": f"Potential issue detected by {r.get('plugin', '')} during safe automated analysis.",
                    "endpoint": endpoint,
                    "category": str(r.get("category", "")),
                    "reproduction_steps": [x for x in [ev.get("base_url"), ev.get("variant_url"), ev.get("modified_url")] if x],
                    "evidence": {"request": ev.get("request", {}), "response": ev.get("response", {}), "diff": ev.get("diff") or ev.get("response_diff") or {}},
                    "impact_explanation": f"Signal confidence {meta.get('confidence', 0)} with risk score {score}.",
                    "remediation_suggestion": "Review authorization checks, input validation, and endpoint access controls for this route.",
                    "discovery_source": meta.get("discovery_source", ev.get("discovery_source", r.get("plugin", ""))),
                    "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                }
            )

        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        json_path = out_dir / f"security_report_{task.target.replace('.', '_')}_{ts}.json"
        md_path = out_dir / f"security_report_{task.target.replace('.', '_')}_{ts}.md"
        html_path = out_dir / f"security_report_{task.target.replace('.', '_')}_{ts}.html"

        json_path.write_text(json.dumps({"target": task.target, "count": len(items), "items": items}, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        md_lines = [f"# Security Report - {task.target}", "", f"Generated: {datetime.now(UTC).isoformat().replace('+00:00', 'Z')}", ""]
        for it in items:
            md_lines.extend(
                [
                    f"## {it['title']}",
                    f"- Severity: {it['severity_estimation']}",
                    f"- Endpoint: {it['endpoint']}",
                    f"- Discovery source: {it['discovery_source']}",
                    f"- Reproduction: {', '.join(it['reproduction_steps'])}",
                    f"- Impact: {it['impact_explanation']}",
                    "",
                ]
            )
        md_path.write_text("\n".join(md_lines), encoding="utf-8")

        rows_html = []
        for it in items:
            rows_html.append(
                "<tr>"
                f"<td>{html.escape(it['title'])}</td>"
                f"<td>{html.escape(it['severity_estimation'])}</td>"
                f"<td>{html.escape(it['endpoint'])}</td>"
                f"<td>{html.escape(it['discovery_source'])}</td>"
                "</tr>"
            )
        html_doc = (
            "<!doctype html><html><head><meta charset='utf-8'><title>Security Report</title>"
            "<style>body{font-family:Arial;padding:20px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px}</style>"
            "</head><body>"
            f"<h1>Security Report - {html.escape(task.target)}</h1>"
            f"<p>Total entries: {len(items)}</p>"
            "<table><thead><tr><th>Title</th><th>Severity</th><th>Endpoint</th><th>Discovery Source</th></tr></thead>"
            f"<tbody>{''.join(rows_html)}</tbody></table></body></html>"
        )
        html_path.write_text(html_doc, encoding="utf-8")

        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="security_report_generation",
                severity="info",
                title=f"Security report package generated ({len(items)} items)",
                evidence={"json_report": str(json_path), "markdown_report": str(md_path), "html_report": str(html_path)},
                metadata={"novelty": 62, "confidence": 92, "impact": 50, "discovery_source": "security_report_builder"},
            )
        ]
