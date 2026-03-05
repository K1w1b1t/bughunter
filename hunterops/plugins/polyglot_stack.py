from __future__ import annotations

import json

from hunterops.plugin_base import Plugin
from hunterops.tool_runner import run_command
from hunterops.types import Finding, Task


class PluginImpl(Plugin):
    name = "polyglot_stack"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get("polyglot_stack", {})
        timeout = context["runtime"]["timeout_seconds"]
        stealth = context["runtime"]["stealth_mode"]
        proxies = context["runtime"]["proxies"]
        findings: list[Finding] = []

        for cmd_tpl in cfg.get("commands", []):
            cmd = cmd_tpl.format(target=task.target)
            result = await run_command(cmd, timeout=timeout, stealth_mode=stealth, proxies=proxies)
            if result["rc"] != 0:
                continue
            lines = [x.strip() for x in result["stdout"].splitlines() if x.strip()]
            if not lines:
                continue

            parsed_rows = []
            for line in lines[:50]:
                try:
                    parsed_rows.append(json.loads(line))
                except Exception:
                    # accept non-json only if line has meaningful token separators
                    if ":" in line or "=" in line or "{" in line:
                        parsed_rows.append({"raw": line})

            if not parsed_rows:
                continue

            findings.append(
                Finding(
                    plugin=self.name,
                    target=task.target,
                    category="polyglot_signal",
                    severity="info",
                    title=f"Polyglot module output from `{cmd.split()[0]}`",
                    evidence={"command": cmd, "rc": result["rc"], "rows": parsed_rows[:30]},
                    metadata={"novelty": 60, "confidence": 65, "impact": 35},
                )
            )
        return findings
