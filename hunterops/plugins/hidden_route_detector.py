from __future__ import annotations

import re
from datetime import UTC, datetime
from urllib.parse import urljoin, urlparse

from hunterops.http_client import request_http_async
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task

PATH_RE = re.compile(r"""['"](/(?:api|v1|v2|internal|admin|debug|test|config|private)[^'"]*)['"]""", re.IGNORECASE)


def _pathlike(items: list[object]) -> set[str]:
    out: set[str] = set()
    for x in items:
        if isinstance(x, str) and x.startswith("/"):
            out.add(x)
    return out


class PluginImpl(Plugin):
    name = "hidden_route_detector"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        timeout = int(context["runtime"]["timeout_seconds"])
        base = f"https://{task.target}"
        seeds = set(cfg.get("route_seeds", ["/api/", "/api/v1/", "/internal/", "/admin/", "/debug/", "/config/"]))

        # sources: js hints + schema documents + redirect locations
        source_urls = cfg.get("source_paths", ["/", "/swagger.json", "/openapi.json", "/api-docs", "/main.js", "/app.js"])
        req_resp: list[dict[str, object]] = []
        for p in source_urls:
            u = p if p.startswith("http") else f"{base}{p}"
            r = await request_http_async("GET", u, headers={}, timeout=timeout)
            req_resp.append(
                {
                    "request": {"method": "GET", "url": u, "headers": {}},
                    "response": {"status": r.get("status", 0), "length": r.get("length", 0)},
                    "headers": r.get("headers", {}),
                    "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                    "discovery_source": "hidden_route_detector",
                }
            )
            txt = str(r.get("text", ""))
            for h in PATH_RE.findall(txt):
                seeds.add(h)
            loc = str((r.get("headers") or {}).get("Location", ""))
            if loc:
                lu = loc if loc.startswith("http") else urljoin(base + "/", loc)
                if urlparse(lu).netloc in {"", task.target}:
                    seeds.add(urlparse(lu).path or "/")

        # previous response references from payload
        payload_eps = _pathlike(list((task.payload.get("known_endpoints", []) if isinstance(task.payload, dict) else [])))
        seeds |= payload_eps

        hits: list[dict[str, object]] = []
        for p in sorted(seeds)[:250]:
            u = p if p.startswith("http") else f"{base}{p}"
            r = await request_http_async("GET", u, headers={}, timeout=timeout)
            status = int(r.get("status", 0))
            if status not in {0, 404}:
                hits.append({"endpoint": urlparse(u).path or "/", "status": status, "length": int(r.get("length", 0)), "url": u})

        if not hits:
            return []
        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="hidden_route_discovery",
                severity="medium",
                title=f"Hidden route detector validated {len(hits)} candidate routes",
                evidence={"request_response_sample": req_resp[:20], "validated_routes": hits[:120]},
                metadata={
                    "novelty": 81,
                    "confidence": 72,
                    "impact": 58,
                    "discovery_source": "api/js/redirect",
                    "endpoints": [h["endpoint"] for h in hits],
                },
            )
        ]
