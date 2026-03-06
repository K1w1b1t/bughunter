from __future__ import annotations

import asyncio
from urllib.parse import urlencode

from hunterops.http_client import request_http_async
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task


class PluginImpl(Plugin):
    name = "deep_endpoint"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get("deep_endpoint", {})
        timeout = context["runtime"]["timeout_seconds"]
        candidates = cfg.get("paths", ["/api/profile", "/api/orders", "/api/invoices"])
        findings: list[Finding] = []

        for p in candidates:
            base_url = f"https://{task.target}{p}"
            variants = [
                ("GET", base_url, None),
                ("POST", base_url, {"debug": "1"}),
                ("PUT", base_url, {"debug": "1"}),
                ("GET", f"{base_url}?{urlencode({'include':'all','expand':'true'})}", None),
                ("GET", f"{base_url}?{urlencode({'admin':'1','internal':'1'})}", None),
            ]
            calls = [
                request_http_async(method, url, body=body, timeout=timeout)
                for method, url, body in variants
            ]
            raw_responses = await asyncio.gather(*calls, return_exceptions=False)
            responses = []
            for idx, (method, url, _body) in enumerate(variants):
                r = raw_responses[idx]
                responses.append({"method": method, "url": url, "status": r["status"], "length": r["length"]})

            status_set = {x["status"] for x in responses}
            lengths = {x["length"] for x in responses}
            if len(status_set) > 1 or len(lengths) > 2:
                findings.append(
                    Finding(
                        plugin=self.name,
                        target=task.target,
                        category="deep_endpoint_variation",
                        severity="medium",
                        title=f"Endpoint shows behavior variance under method/param changes: {p}",
                        evidence={"responses": responses},
                        metadata={"novelty": 76, "confidence": 68, "impact": 58},
                    )
                )
        return findings
