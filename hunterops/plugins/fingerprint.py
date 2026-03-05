from __future__ import annotations

from typing import Any

from hunterops.plugin_base import Plugin
from hunterops.tool_runner import run_command
from hunterops.types import Finding, Task


class PluginImpl(Plugin):
    name = "fingerprint"

    async def run(self, task: Task, context: dict[str, Any]) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get("fingerprint", {})
        timeout = context["runtime"]["timeout_seconds"]
        stealth = context["runtime"]["stealth_mode"]
        proxies = context["runtime"]["proxies"]
        findings: list[Finding] = []

        for cmd_tpl in cfg.get("commands", []):
            cmd = cmd_tpl.format(target=task.target)
            result = await run_command(cmd, timeout=timeout, stealth_mode=stealth, proxies=proxies)
            lines = [x.strip() for x in result["stdout"].splitlines() if x.strip()]
            if lines:
                findings.append(
                    Finding(
                        plugin=self.name,
                        target=task.target,
                        category="fingerprint",
                        severity="info",
                        title="Application stack fingerprint collected",
                        evidence={"sample": lines[:15], "command": cmd},
                        metadata={"novelty": 40, "confidence": 75, "impact": 20},
                    )
                )
        return findings

