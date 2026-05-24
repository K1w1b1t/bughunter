from __future__ import annotations

import re

from hunterops.plugin_base import Plugin
from hunterops.tool_runner import run_command
from hunterops.types import Finding, Task


class PluginImpl(Plugin):
    name = "crawler_intel"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get("crawler_intel", {})
        timeout = context["runtime"]["timeout_seconds"]
        stealth = context["runtime"]["stealth_mode"]
        proxies = context["runtime"]["proxies"]

        all_urls: set[str] = set()
        js_files: set[str] = set()
        params: set[str] = set()
        findings: list[Finding] = []

        for cmd_tpl in cfg.get("commands", []):
            cmd = cmd_tpl.format(target=task.target)
            r = await run_command(cmd, timeout=timeout, stealth_mode=stealth, proxies=proxies)
            for line in r["stdout"].splitlines():
                s = line.strip()
                if s.startswith("http://") or s.startswith("https://"):
                    all_urls.add(s)
                    if ".js" in s.lower():
                        js_files.add(s)
                    for p in re.findall(r"[?&]([a-zA-Z0-9_]+)=", s):
                        params.add(p)

        if all_urls:
            findings.append(
                Finding(
                    plugin=self.name,
                    target=task.target,
                    category="intelligent_crawling",
                    severity="medium",
                    title=f"Crawler collected {len(all_urls)} URLs, {len(js_files)} JS files",
                    evidence={
                        "urls_sample": sorted(all_urls)[:30],
                        "js_sample": sorted(js_files)[:20],
                        "dynamic_params": sorted(params)[:40],
                    },
                    metadata={"novelty": 80, "confidence": 75, "impact": 40},
                )
            )
        return findings

