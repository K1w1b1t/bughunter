from __future__ import annotations

from pathlib import Path
from typing import Any

from hunterops.async_io import read_json
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task


async def _load_findings(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        doc = await read_json(path)
    except Exception:
        return []
    rows = doc.get("findings", []) if isinstance(doc, dict) else doc
    return [x for x in rows if isinstance(x, dict)]


class PluginImpl(Plugin):
    name = "attack_graph_builder"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        source = Path(cfg.get("findings_source", "data/reports/engine/findings.json"))
        rows = [r for r in await _load_findings(source) if str(r.get("target", "")) == task.target]
        if not rows:
            return []

        endpoints: set[str] = set()
        params: set[str] = set()
        nodes: list[dict[str, str]] = []
        edges: list[dict[str, str]] = []
        auth_contexts = {"anonymous"}
        objects = {"user", "account", "order", "invoice", "profile"}

        for r in rows:
            ev = r.get("evidence", {}) if isinstance(r.get("evidence"), dict) else {}
            meta = r.get("metadata", {}) if isinstance(r.get("metadata"), dict) else {}
            for key in ("base_url", "url", "modified_url", "variant_url"):
                u = ev.get(key)
                if isinstance(u, str) and u:
                    p = __import__("urllib.parse").parse.urlparse(u).path or "/"
                    endpoints.add(p)
            tp = ev.get("tested_parameter") or ev.get("parameter")
            if isinstance(tp, str) and tp:
                params.add(tp)
            src = str(meta.get("discovery_source", ""))
            if "auth" in src:
                auth_contexts.add("authenticated")

        for ep in sorted(endpoints):
            nodes.append({"id": f"endpoint:{ep}", "type": "endpoint"})
        for p in sorted(params):
            nodes.append({"id": f"param:{p}", "type": "parameter"})
        for a in sorted(auth_contexts):
            nodes.append({"id": f"auth:{a}", "type": "auth_context"})
        for o in sorted(objects):
            nodes.append({"id": f"obj:{o}", "type": "object"})

        for ep in sorted(endpoints):
            for p in sorted(params):
                if p.lower() in ep.lower() or p.lower() in {"id", "user_id", "account_id", "order_id", "invoice_id", "profile_id"}:
                    edges.append({"from": f"endpoint:{ep}", "to": f"param:{p}", "relation": "parameter_flow"})
            if any(x in ep.lower() for x in ("admin", "internal")):
                edges.append({"from": f"auth:authenticated", "to": f"endpoint:{ep}", "relation": "authentication_dependency"})
            for o in objects:
                if o in ep.lower():
                    edges.append({"from": f"endpoint:{ep}", "to": f"obj:{o}", "relation": "object_access"})

        potential_attack_paths = []
        if any("param:id" == n["id"] for n in nodes) or any(x in params for x in ("id", "user_id", "account_id", "order_id", "invoice_id", "profile_id")):
            potential_attack_paths.append("idor_path")
        if any("admin" in ep.lower() for ep in endpoints):
            potential_attack_paths.append("privilege_escalation_path")
        if any("profile" in ep.lower() or "account" in ep.lower() for ep in endpoints):
            potential_attack_paths.append("data_exposure_path")

        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="attack_graph",
                severity="info",
                title=f"Attack graph built with {len(nodes)} nodes and {len(edges)} edges",
                evidence={"nodes": nodes[:400], "edges": edges[:800], "potential_attack_paths": sorted(set(potential_attack_paths))},
                metadata={"novelty": 70, "confidence": 74, "impact": 50, "discovery_source": "attack_graph_builder"},
            )
        ]
