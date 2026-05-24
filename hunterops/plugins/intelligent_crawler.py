from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse

from hunterops.http_client import request_http_async
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task

SCRIPT_RE = re.compile(r"""<script[^>]+src=['"]([^'"]+)['"]""", re.IGNORECASE)
JS_ROUTE_RE = re.compile(r"""['"](/(?:api|v1|v2|admin|internal|graphql|auth)[^'"]*)['"]""", re.IGNORECASE)
FETCH_RE = re.compile(r"""fetch\(\s*['"]([^'"]+)['"]""")
AXIOS_RE = re.compile(r"""axios\.(?:get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]""", re.IGNORECASE)


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: set[str] = set()
        self.scripts: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        amap = {k.lower(): (v or "") for k, v in attrs}
        if tag.lower() == "a" and amap.get("href"):
            self.links.add(amap["href"])
        if tag.lower() == "script" and amap.get("src"):
            self.scripts.add(amap["src"])


def _in_scope(url: str, target: str) -> bool:
    up = urlparse(url)
    return up.netloc in {"", target}


def _abs(base: str, raw: str) -> str:
    return raw if raw.startswith("http://") or raw.startswith("https://") else urljoin(base, raw)


class PluginImpl(Plugin):
    name = "intelligent_crawler"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        timeout = int(context["runtime"]["timeout_seconds"])
        max_pages = int(cfg.get("max_pages", 20))
        max_depth = int(cfg.get("max_depth", 2))
        delay_ms = int(cfg.get("crawl_delay_ms", 120))
        base = f"https://{task.target}/"

        queue: list[tuple[str, int]] = [(base, 0)]
        seen: set[str] = set()
        endpoints: set[str] = set()
        params: set[str] = set()
        js_assets: set[str] = set()
        req_resp_meta: list[dict[str, object]] = []

        while queue and len(seen) < max_pages:
            url, depth = queue.pop(0)
            if url in seen or not _in_scope(url, task.target):
                continue
            seen.add(url)
            r = await request_http_async("GET", url, headers={}, timeout=timeout)
            text = str(r.get("text", ""))
            up = urlparse(url)
            endpoints.add(up.path or "/")
            for k in parse_qs(up.query).keys():
                params.add(k)
            req_resp_meta.append(
                {
                    "request": {"method": "GET", "url": url, "headers": {}},
                    "response": {"status": r.get("status", 0), "length": r.get("length", 0)},
                    "headers": r.get("headers", {}),
                    "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                    "discovery_source": "intelligent_crawler",
                }
            )

            parser = _Parser()
            if "text/html" in str((r.get("headers") or {}).get("Content-Type", "")).lower():
                try:
                    parser.feed(text)
                except Exception:
                    pass
                for l in parser.links:
                    lu = _abs(url, l)
                    if _in_scope(lu, task.target):
                        endpoints.add(urlparse(lu).path or "/")
                        if depth + 1 <= max_depth:
                            queue.append((lu, depth + 1))
                for s in parser.scripts:
                    su = _abs(url, s)
                    if _in_scope(su, task.target):
                        js_assets.add(su)

            await asyncio.sleep(max(0.0, delay_ms / 1000.0))

        for js in sorted(js_assets)[:30]:
            r = await request_http_async("GET", js, headers={}, timeout=timeout)
            txt = str(r.get("text", ""))
            for raw in JS_ROUTE_RE.findall(txt) + FETCH_RE.findall(txt) + AXIOS_RE.findall(txt):
                ep = urlparse(_abs(base, raw)).path or "/"
                endpoints.add(ep)
                for k in parse_qs(urlparse(_abs(base, raw)).query).keys():
                    params.add(k)

        if not endpoints:
            return []
        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="intelligent_crawling",
                severity="info",
                title=f"Intelligent crawler discovered {len(endpoints)} routes and {len(params)} parameters",
                evidence={
                    "request_response_sample": req_resp_meta[:25],
                    "js_assets_sample": sorted(js_assets)[:40],
                    "endpoints_sample": sorted(endpoints)[:120],
                    "parameters_sample": sorted(params)[:120],
                },
                metadata={
                    "novelty": 78,
                    "confidence": 77,
                    "impact": 42,
                    "discovery_source": "crawler",
                    "endpoints": sorted(endpoints),
                },
            )
        ]
