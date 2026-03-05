from __future__ import annotations

import re

from hunterops.http_client import request_http
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task


API_PATH_RE = re.compile(r"/api/[A-Za-z0-9_\-/{}]+")


class PluginImpl(Plugin):
    name = "undocumented_api"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        timeout = context["runtime"]["timeout_seconds"]
        sources = [
            "/swagger.json",
            "/openapi.json",
            "/graphql",
            "/api-docs",
            "/docs/openapi.json",
            "/static/app.js",
            "/main.js",
        ]
        found: set[str] = set()
        evidence = []
        for p in sources:
            url = f"https://{task.target}{p}"
            r = request_http("GET", url, timeout=timeout)
            if r["status"] in {200, 201} and r["length"] > 0:
                paths = API_PATH_RE.findall(r["text"])
                for x in paths:
                    found.add(x)
                evidence.append({"url": url, "status": r["status"], "matches": len(paths)})

        if not found:
            return []
        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="undocumented_api_discovery",
                severity="medium",
                title=f"Discovered undocumented/internal API routes ({len(found)})",
                evidence={"sources": evidence, "routes_sample": sorted(found)[:50]},
                metadata={"novelty": 82, "confidence": 72, "impact": 65},
            )
        ]

