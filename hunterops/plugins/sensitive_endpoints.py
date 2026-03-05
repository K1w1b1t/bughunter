from __future__ import annotations

from hunterops.http_client import request_http
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task


SENSITIVE_PATHS = [
    "/admin",
    "/internal",
    "/export",
    "/backup",
    "/debug",
    "/config",
    "/api/private",
]


class PluginImpl(Plugin):
    name = "sensitive_endpoints"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        timeout = context["runtime"]["timeout_seconds"]
        findings: list[Finding] = []
        hits = []
        for p in SENSITIVE_PATHS:
            url = f"https://{task.target}{p}"
            r = request_http("GET", url, headers={}, timeout=timeout)
            if r["status"] not in {0, 404}:
                hits.append({"url": url, "status": r["status"], "length": r["length"]})
        if hits:
            findings.append(
                Finding(
                    plugin=self.name,
                    target=task.target,
                    category="sensitive_endpoint_exposure",
                    severity="medium",
                    title=f"Sensitive endpoints responded on target ({len(hits)})",
                    evidence={"hits": hits},
                    metadata={"novelty": 70, "confidence": 68, "impact": 60},
                )
            )
        return findings

