from __future__ import annotations

import re
from urllib.parse import urlparse

from hunterops.http_client import request_http_async
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task

SCRIPT_RE = re.compile(r"""<script[^>]+src=['"]([^'"]+)['"]""", re.IGNORECASE)
PATH_RE = re.compile(r"""['"](/(?:api|v1|v2|internal|admin|debug|test|config)[^'"]*)['"]""", re.IGNORECASE)


class PluginImpl(Plugin):
    name = "hidden_route_discovery"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        timeout = int(context["runtime"]["timeout_seconds"])
        base = f"https://{task.target}"
        seeds = cfg.get(
            "route_seeds",
            ["/api/", "/api/v1/", "/v1/", "/internal/", "/admin/", "/debug/", "/test/", "/config/"],
        )
        candidates: set[str] = {x for x in seeds if isinstance(x, str)}

        home = await request_http_async("GET", f"{base}/", headers={}, timeout=timeout)
        html = str(home.get("text", ""))
        for path in PATH_RE.findall(html):
            candidates.add(path)
        scripts = SCRIPT_RE.findall(html)
        for src in scripts[:20]:
            s_url = src if src.startswith("http") else f"{base}{src if src.startswith('/') else '/' + src}"
            if urlparse(s_url).netloc not in {"", task.target}:
                continue
            js = await request_http_async("GET", s_url, headers={}, timeout=timeout)
            for path in PATH_RE.findall(str(js.get("text", ""))):
                candidates.add(path)

        hits: list[dict[str, object]] = []
        for c in sorted(candidates)[:200]:
            url = c if c.startswith("http") else f"{base}{c}"
            r = await request_http_async("GET", url, headers={}, timeout=timeout)
            status = int(r.get("status", 0))
            if status not in {0, 404}:
                hits.append({"endpoint": c, "url": url, "status": status, "length": int(r.get("length", 0))})

        if not hits:
            return []
        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="hidden_route_discovery",
                severity="medium",
                title=f"Potential hidden routes responding ({len(hits)})",
                evidence={"hits": hits[:120]},
                metadata={
                    "novelty": 79,
                    "confidence": 70,
                    "impact": 58,
                    "endpoints": [h["endpoint"] for h in hits],
                },
            )
        ]
