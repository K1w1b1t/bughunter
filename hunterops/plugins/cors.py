from __future__ import annotations

from typing import Any

from hunterops.plugin_base import Plugin
from hunterops.tool_runner import run_command
from hunterops.types import Finding, Task


class PluginImpl(Plugin):
    name = "cors"

    async def run(self, task: Task, context: dict[str, Any]) -> list[Finding]:
        timeout = context["runtime"]["timeout_seconds"]
        stealth = context["runtime"]["stealth_mode"]
        proxies = context["runtime"]["proxies"]

        cmd = (
            f"curl -s -I -H \"Origin: https://evil.example\" https://{task.target}"
        )
        result = await run_command(cmd, timeout=timeout, stealth_mode=stealth, proxies=proxies)
        headers = result["stdout"].lower()
        findings: list[Finding] = []
        if "access-control-allow-origin: *" in headers or "access-control-allow-credentials: true" in headers:
            findings.append(
                Finding(
                    plugin=self.name,
                    target=task.target,
                    category="cors_misconfiguration",
                    severity="medium",
                    title="Potentially permissive CORS policy detected",
                    evidence={"headers": result["stdout"][:1000]},
                    metadata={"novelty": 65, "confidence": 70, "impact": 50},
                )
            )
        return findings

