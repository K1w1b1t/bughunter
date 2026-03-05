from __future__ import annotations

from typing import Any

from hunterops.plugin_base import Plugin
from hunterops.tool_runner import run_command
from hunterops.types import Finding, Task


class PluginImpl(Plugin):
    name = "fuzz"

    async def run(self, task: Task, context: dict[str, Any]) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get("fuzz", {})
        timeout = context["runtime"]["timeout_seconds"]
        stealth = context["runtime"]["stealth_mode"]
        proxies = context["runtime"]["proxies"]
        pack = task.payload.get("program_pack", {}) if isinstance(task.payload, dict) else {}
        wordlist = pack.get("wordlist") or context["runtime"]["wordlists"].get("default", "wordlists/common.txt")

        findings: list[Finding] = []
        for cmd_tpl in cfg.get("commands", []):
            cmd = cmd_tpl.format(target=task.target, wordlist=wordlist)
            result = await run_command(cmd, timeout=timeout, stealth_mode=stealth, proxies=proxies)
            suspicious = []
            for line in result["stdout"].splitlines():
                if any(code in line for code in (" 200 ", " 201 ", " 204 ", " 401 ", " 403 ")):
                    suspicious.append(line.strip())
            if suspicious:
                findings.append(
                    Finding(
                        plugin=self.name,
                        target=task.target,
                        category="content_discovery",
                        severity="medium",
                        title=f"Fuzzing found {len(suspicious)} candidate paths",
                        evidence={"sample": suspicious[:25], "command": cmd},
                        metadata={"novelty": 75, "confidence": 65, "impact": 45},
                    )
                )
        return findings
