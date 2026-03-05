from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from hunterops.http_client import json_keys, request_http_async
from hunterops.intelligence import http_diff_score
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task


def toggle_variant(url: str) -> str:
    p = urlparse(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    q.append(("view", "summary"))
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(q), p.fragment))


class PluginImpl(Plugin):
    name = "response_diff_engine"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        timeout = int(context["runtime"]["timeout_seconds"])
        base = f"https://{task.target}"
        paths = cfg.get("paths", ["/api/me", "/api/profile", "/api/orders?id=1", "/search?q=test"])

        findings: list[Finding] = []
        for p in paths:
            url = p if p.startswith("http") else f"{base}{p}"
            alt = toggle_variant(url)
            r1 = await request_http_async("GET", url, headers={}, timeout=timeout)
            r2 = await request_http_async("GET", alt, headers={}, timeout=timeout)
            d = http_diff_score(
                {"status": r1.get("status", 0), "length": r1.get("length", 0), "json_keys": json_keys(str(r1.get("text", "")))},
                {"status": r2.get("status", 0), "length": r2.get("length", 0), "json_keys": json_keys(str(r2.get("text", "")))},
            )
            if d["anomaly_score"] >= 40:
                findings.append(
                    Finding(
                        plugin=self.name,
                        target=task.target,
                        category="response_anomaly",
                        severity="medium",
                        title="Response diff anomaly detected between baseline and variant",
                        evidence={"base_url": url, "variant_url": alt, "diff": d},
                        metadata={"novelty": 74, "confidence": 70, "impact": 58, "discovery_source": "response_diff_engine"},
                    )
                )
        return findings
