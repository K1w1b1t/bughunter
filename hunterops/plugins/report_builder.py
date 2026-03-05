from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task


def load_rows(path: Path) -> list[dict[str, Any]]:
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


def classify_endpoint(path: str) -> str:
    p = (path or "").lower()
    if any(x in p for x in ("/admin", "/management")):
        return "admin"
    if any(x in p for x in ("/auth", "/login", "/session", "/oauth")):
        return "auth"
    if any(x in p for x in ("/payment", "/wallet", "/invoice", "/checkout", "/coupon")):
        return "payment"
    if "/api/" in p or p.startswith("/api"):
        return "api"
    return "general"


def classify_parameter(name: str) -> str:
    n = (name or "").lower()
    if any(x in n for x in ("id", "uid", "user_id", "account_id", "order_id", "invoice_id", "profile_id")):
        return "numeric_id"
    if "email" in n:
        return "email"
    if any(x in n for x in ("token", "jwt", "auth", "session", "key", "secret")):
        return "token"
    if any(x in n for x in ("is_", "enabled", "active", "flag")):
        return "boolean"
    return "string"


class PluginImpl(Plugin):
    name = "report_builder"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        source = Path(cfg.get("findings_source", "data/reports/engine/findings.json"))
        out_dir = Path(cfg.get("out_dir", "data/reports/engine/bug_reports"))
        out_dir.mkdir(parents=True, exist_ok=True)
        rows = [r for r in load_rows(source) if str(r.get("target", "")) == task.target]
        if not rows:
            return []

        high_signal = [
            r
            for r in rows
            if float(r.get("risk_score", 0) or 0) >= float(cfg.get("min_risk", 55))
            or str(r.get("severity", "")).lower() in {"high", "critical"}
        ][:40]
        if not high_signal:
            return []

        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        report_json = out_dir / f"report_{task.target.replace('.', '_')}_{ts}.json"
        report_md = out_dir / f"report_{task.target.replace('.', '_')}_{ts}.md"

        payload = []
        lines = [f"# HunterOps Bug Bounty Draft - {task.target}", "", f"Generated: {datetime.now(UTC).isoformat().replace('+00:00', 'Z')}", ""]
        for r in high_signal:
            ev = r.get("evidence", {}) if isinstance(r.get("evidence"), dict) else {}
            meta = r.get("metadata", {}) if isinstance(r.get("metadata"), dict) else {}
            endpoint = str(ev.get("base_url") or ev.get("url") or ev.get("modified_url") or "")
            endpoint_path = urlparse(endpoint).path if endpoint else ""
            param_name = str(ev.get("tested_parameter") or ev.get("parameter") or "")
            anomaly_indicators = []
            diff = ev.get("diff") or ev.get("response_diff") or ev.get("base_vs_variant_diff")
            if isinstance(diff, dict):
                if diff.get("status_changed"):
                    anomaly_indicators.append("status_changed")
                if float(diff.get("len_ratio_pct", 0) or 0) > 20:
                    anomaly_indicators.append("size_shift")
                if int(diff.get("structural_delta", 0) or 0) > 0:
                    anomaly_indicators.append("structure_changed")
            md_item = {
                "title": r.get("title"),
                "description": f"Potential security issue detected by plugin {r.get('plugin')}.",
                "affected_endpoint": endpoint,
                "endpoint_classification": classify_endpoint(endpoint_path),
                "parameter": param_name,
                "parameter_classification": classify_parameter(param_name),
                "response_anomaly_indicators": anomaly_indicators,
                "steps_to_reproduce": [x for x in [ev.get("base_url"), ev.get("variant_url"), ev.get("modified_url")] if x],
                "example_request": ev.get("request_file") or "",
                "example_response": ev.get("response_file") or "",
                "impact": f"Risk score {r.get('risk_score', 0)} with category {r.get('category', '')}.",
                "confidence": meta.get("confidence", 0),
                "severity": r.get("severity", "info"),
                "discovery_source": meta.get("discovery_source", ev.get("discovery_source", r.get("plugin", ""))),
                "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            }
            payload.append(md_item)
            lines.extend(
                [
                    f"## {md_item['title']}",
                    f"- Severity: {md_item['severity']}",
                    f"- Confidence: {md_item['confidence']}",
                    f"- Affected endpoint: {md_item['affected_endpoint']}",
                    f"- Endpoint classification: {md_item['endpoint_classification']}",
                    f"- Parameter: {md_item['parameter']}",
                    f"- Parameter classification: {md_item['parameter_classification']}",
                    f"- Response anomaly indicators: {', '.join(md_item['response_anomaly_indicators'])}",
                    f"- Discovery source: {md_item['discovery_source']}",
                    f"- Impact: {md_item['impact']}",
                    f"- Steps: {', '.join(md_item['steps_to_reproduce'])}",
                    "",
                ]
            )

        report_json.write_text(json.dumps({"target": task.target, "count": len(payload), "items": payload}, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        report_md.write_text("\n".join(lines), encoding="utf-8")

        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="report_generation",
                severity="info",
                title=f"Bug bounty report drafts generated ({len(payload)} entries)",
                evidence={"json_report": str(report_json), "markdown_report": str(report_md)},
                metadata={"novelty": 58, "confidence": 90, "impact": 46, "discovery_source": "report_builder"},
            )
        ]
