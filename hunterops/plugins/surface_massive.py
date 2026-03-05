from __future__ import annotations

from hunterops.plugin_base import Plugin
from hunterops.tool_runner import run_command
from hunterops.types import Finding, Task


class PluginImpl(Plugin):
    name = "surface_massive"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get("surface_massive", {})
        timeout = context["runtime"]["timeout_seconds"]
        stealth = context["runtime"]["stealth_mode"]
        proxies = context["runtime"]["proxies"]
        findings: list[Finding] = []

        for cmd_tpl in cfg.get("commands", []):
            cmd = cmd_tpl.format(target=task.target)
            r = await run_command(cmd, timeout=timeout, stealth_mode=stealth, proxies=proxies)
            lines = [x.strip() for x in r["stdout"].splitlines() if x.strip()]
            if lines:
                findings.append(
                    Finding(
                        plugin=self.name,
                        target=task.target,
                        category="surface_discovery",
                        severity="info",
                        title=f"{cmd.split()[0]} discovered surface artifacts",
                        evidence={"command": cmd, "sample": lines[:30]},
                        metadata={"novelty": 70, "confidence": 70, "impact": 25},
                    )
                )
        return findings

