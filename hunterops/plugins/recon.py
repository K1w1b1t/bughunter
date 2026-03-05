from __future__ import annotations

from typing import Any

from hunterops.plugin_base import Plugin
from hunterops.tool_runner import run_command
from hunterops.types import Finding, Task


class PluginImpl(Plugin):
    name = "recon"

    async def run(self, task: Task, context: dict[str, Any]) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get("recon", {})
        timeout = context["runtime"]["timeout_seconds"]
        stealth = context["runtime"]["stealth_mode"]
        proxies = context["runtime"]["proxies"]

        findings: list[Finding] = []
        for cmd_tpl in cfg.get("commands", []):
            cmd = cmd_tpl.format(target=task.target)
            result = await run_command(cmd, timeout=timeout, stealth_mode=stealth, proxies=proxies)
            lines = [x.strip() for x in result["stdout"].splitlines() if x.strip()]
            if not lines:
                continue
            findings.append(
                Finding(
                    plugin=self.name,
                    target=task.target,
                    category="attack_surface",
                    severity="info",
                    title=f"Recon discovered {len(lines)} artifacts via {cmd.split()[0]}",
                    evidence={"sample": lines[:20], "command": cmd, "rc": result["rc"]},
                    metadata={"novelty": 60, "confidence": 70, "impact": 30},
                )
            )
        return findings

