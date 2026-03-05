from __future__ import annotations

import asyncio

from hunterops.http_client import request_http
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task


class PluginImpl(Plugin):
    name = "race_basic"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get("race_basic", {})
        timeout = context["runtime"]["timeout_seconds"]
        paths = cfg.get("paths", ["/api/coupon/apply", "/api/wallet/redeem", "/api/plan/upgrade"])

        findings: list[Finding] = []
        for p in paths:
            url = f"https://{task.target}{p}"

            async def call_once() -> dict:
                return await asyncio.to_thread(request_http, "POST", url, {}, {"probe": "race"}, timeout)

            results = await asyncio.gather(*[call_once() for _ in range(6)], return_exceptions=True)
            statuses = [r.get("status", 0) for r in results if isinstance(r, dict)]
            succ = sum(1 for s in statuses if s in {200, 201, 202})
            if succ >= 2 and len(set(statuses)) > 1:
                findings.append(
                    Finding(
                        plugin=self.name,
                        target=task.target,
                        category="race_condition_signal",
                        severity="high",
                        title=f"Potential race condition behavior on {p}",
                        evidence={"url": url, "statuses": statuses},
                        metadata={"novelty": 87, "confidence": 60, "impact": 80},
                    )
                )
        return findings

