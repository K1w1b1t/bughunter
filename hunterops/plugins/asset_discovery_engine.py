from __future__ import annotations

import asyncio
import socket
from urllib.parse import urlparse

from hunterops.http_client import request_http_async
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task


async def resolve_host(host: str) -> str:
    try:
        return await asyncio.to_thread(socket.gethostbyname, host)
    except Exception:
        return ""


class PluginImpl(Plugin):
    name = "asset_discovery_engine"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        timeout = int(context["runtime"]["timeout_seconds"])
        prefixes = cfg.get("subdomain_prefixes", ["www", "api", "app", "admin", "staging", "dev"])
        scope_suffixes = cfg.get("allowed_scope_suffixes", [task.target])

        subdomains = {task.target}
        for p in prefixes:
            if isinstance(p, str) and p.strip():
                subdomains.add(f"{p.strip()}.{task.target}")

        scoped = set()
        for s in subdomains:
            if any(s == suf or s.endswith("." + suf) for suf in scope_suffixes):
                scoped.add(s)

        live_hosts: list[str] = []
        detected_services: list[dict[str, object]] = []
        technologies: list[dict[str, str]] = []
        for host in sorted(scoped)[:100]:
            ip = await resolve_host(host)
            if not ip:
                continue
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}/"
                r = await request_http_async("GET", url, headers={}, timeout=timeout)
                status = int(r.get("status", 0))
                if status == 0:
                    continue
                live_hosts.append(host)
                hdr = r.get("headers", {}) or {}
                service = {
                    "host": host,
                    "url": url,
                    "ip": ip,
                    "status": status,
                    "content_type": str(hdr.get("Content-Type", "")),
                }
                detected_services.append(service)
                tech = []
                if hdr.get("Server"):
                    tech.append(str(hdr.get("Server")))
                if hdr.get("X-Powered-By"):
                    tech.append(str(hdr.get("X-Powered-By")))
                if tech:
                    technologies.append({"host": host, "tech": " | ".join(tech)})
                break

        if not detected_services:
            return []
        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="asset_discovery",
                severity="info",
                title=f"Asset discovery mapped {len(set(live_hosts))} live hosts",
                evidence={
                    "subdomains": sorted(scoped),
                    "live_hosts": sorted(set(live_hosts)),
                    "detected_services": detected_services[:120],
                    "technologies": technologies[:120],
                },
                metadata={
                    "novelty": 76,
                    "confidence": 82,
                    "impact": 40,
                    "discovery_source": "asset_discovery_engine",
                    "assets": [{"host": urlparse(x["url"]).hostname or "", "type": "web"} for x in detected_services[:200]],
                },
            )
        ]
