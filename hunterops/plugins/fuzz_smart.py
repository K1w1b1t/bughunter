from __future__ import annotations

import json

from hunterops.plugin_base import Plugin
from hunterops.tool_runner import run_command
from hunterops.types import Finding, Task


class PluginImpl(Plugin):
    name = "fuzz_smart"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get("fuzz_smart", {})
        timeout = context["runtime"]["timeout_seconds"]
        stealth = context["runtime"]["stealth_mode"]
        proxies = context["runtime"]["proxies"]
        pack = task.payload.get("program_pack", {}) if isinstance(task.payload, dict) else {}
        wordlist = pack.get("wordlist") or context["runtime"]["wordlists"].get("default", "wordlists/common.txt")

        findings: list[Finding] = []
        candidates: list[dict] = []
        for cmd_tpl in cfg.get("commands", []):
            cmd = cmd_tpl.format(target=task.target, wordlist=wordlist)
            r = await run_command(cmd, timeout=timeout, stealth_mode=stealth, proxies=proxies)
            stdout = r["stdout"].strip()
            if not stdout:
                continue
            # primary: ffuf JSON object with "results"
            try:
                obj = json.loads(stdout)
                if isinstance(obj, dict) and isinstance(obj.get("results"), list):
                    for item in obj.get("results", []):
                        if isinstance(item, dict):
                            candidates.append(item)
                    continue
            except Exception:
                pass

            # fallback: JSONL
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if isinstance(obj, dict):
                    candidates.append(obj)

        if not candidates:
            return findings

        baseline_size = min((int(c.get("length", 0)) for c in candidates if c.get("length") is not None), default=0)
        smart_hits = []
        for c in candidates:
            size = int(c.get("length", 0))
            status = int(c.get("status", 0))
            words = int(c.get("words", 0))
            lines = int(c.get("lines", 0))
            # intelligent filters: size delta + structural delta + meaningful status
            size_delta = abs(size - baseline_size)
            if status in {200, 201, 202, 401, 403} and (size_delta > 80 or words > 20 or lines > 10):
                smart_hits.append(c)

        if smart_hits:
            findings.append(
                Finding(
                    plugin=self.name,
                    target=task.target,
                    category="fuzzing_smart_filter",
                    severity="medium",
                    title=f"Smart fuzz filter retained {len(smart_hits)} behavioral outliers",
                    evidence={"sample": smart_hits[:25]},
                    metadata={"novelty": 85, "confidence": 70, "impact": 50},
                )
            )
        return findings
