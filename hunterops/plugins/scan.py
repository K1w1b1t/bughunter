from __future__ import annotations

from typing import Any

from hunterops.intelligence import detect_sensitive
from hunterops.plugin_base import Plugin
from hunterops.tool_runner import run_command
from hunterops.types import Finding, Task


class PluginImpl(Plugin):
    name = "scan"

    async def run(self, task: Task, context: dict[str, Any]) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get("scan", {})
        timeout = context["runtime"]["timeout_seconds"]
        stealth = context["runtime"]["stealth_mode"]
        proxies = context["runtime"]["proxies"]
        findings: list[Finding] = []

        for cmd_tpl in cfg.get("commands", []):
            cmd = cmd_tpl.format(target=task.target)
            result = await run_command(cmd, timeout=timeout, stealth_mode=stealth, proxies=proxies)
            lines = [x.strip() for x in result["stdout"].splitlines() if x.strip()]
            if lines:
                sev = "high" if any("[critical]" in x.lower() for x in lines) else "medium"
                findings.append(
                    Finding(
                        plugin=self.name,
                        target=task.target,
                        category="vulnerability_signal",
                        severity=sev,
                        title=f"Scanner output has {len(lines)} potential issues",
                        evidence={"sample": lines[:30], "command": cmd},
                        metadata={"novelty": 55, "confidence": 60, "impact": 60},
                    )
                )

            hits = detect_sensitive(result["stdout"] + "\n" + result["stderr"])
            if hits:
                findings.append(
                    Finding(
                        plugin=self.name,
                        target=task.target,
                        category="sensitive_pattern",
                        severity="high",
                        title=f"Sensitive patterns detected ({len(hits)})",
                        evidence={"hits": hits[:20], "command": cmd},
                        metadata={"novelty": 80, "confidence": 78, "impact": 85},
                    )
                )
        return findings

