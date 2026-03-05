from __future__ import annotations

import re

from hunterops.http_client import request_http
from hunterops.intelligence import detect_sensitive
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task


EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
CPF_RE = re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")
INTERNAL_URL_RE = re.compile(r"https?://(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)[^\s\"']+")


class PluginImpl(Plugin):
    name = "sensitive_data"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get("sensitive_data", {})
        timeout = context["runtime"]["timeout_seconds"]
        urls = cfg.get("paths", ["/api/me", "/api/profile", "/api/users"])
        findings: list[Finding] = []
        hits = []
        for p in urls:
            url = f"https://{task.target}{p}"
            r = request_http("GET", url, timeout=timeout)
            if r["status"] == 0:
                continue
            text = r["text"]
            local_hits = {
                "url": url,
                "status": r["status"],
                "emails": EMAIL_RE.findall(text)[:10],
                "cpf": CPF_RE.findall(text)[:10],
                "internal_urls": INTERNAL_URL_RE.findall(text)[:10],
                "tokens": detect_sensitive(text)[:10],
            }
            if local_hits["emails"] or local_hits["cpf"] or local_hits["internal_urls"] or local_hits["tokens"]:
                hits.append(local_hits)
        if hits:
            findings.append(
                Finding(
                    plugin=self.name,
                    target=task.target,
                    category="sensitive_data_exposure",
                    severity="high",
                    title=f"Sensitive patterns found in HTTP responses ({len(hits)} endpoints)",
                    evidence={"hits": hits},
                    metadata={"novelty": 85, "confidence": 80, "impact": 88},
                )
            )
        return findings

