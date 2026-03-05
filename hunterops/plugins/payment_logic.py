from __future__ import annotations

from hunterops.http_client import request_http
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task


PAYMENT_KEYS = ["price", "discount", "coupon", "wallet", "balance", "credit", "plan", "checkout"]


class PluginImpl(Plugin):
    name = "payment_logic"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        timeout = context["runtime"]["timeout_seconds"]
        findings: list[Finding] = []
        paths = [f"/api/{k}" for k in PAYMENT_KEYS]
        hits = []
        for p in paths:
            url = f"https://{task.target}{p}"
            r = request_http("GET", url, timeout=timeout)
            if r["status"] in {200, 201, 401, 403}:
                hits.append({"url": url, "status": r["status"], "len": r["length"]})
        if hits:
            findings.append(
                Finding(
                    plugin=self.name,
                    target=task.target,
                    category="payment_logic_surface",
                    severity="medium",
                    title=f"Payment-related endpoints discovered ({len(hits)})",
                    evidence={"hits": hits},
                    metadata={"novelty": 78, "confidence": 73, "impact": 70},
                )
            )
        return findings

