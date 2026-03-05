from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlparse

from hunterops.http_client import request_http_async
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task

SCRIPT_RE = re.compile(r"""<script[^>]+src=['"]([^'"]+)['"]""", re.IGNORECASE)
QUERY_PARAM_RE = re.compile(r"""[?&]([A-Za-z0-9_\-]+)=""")
JS_PARAM_RE = re.compile(r"""['"]([A-Za-z0-9_\-]{2,40})['"]\s*:\s*""")


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.params: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "input":
            return
        amap = {k.lower(): (v or "") for k, v in attrs}
        n = amap.get("name", "").strip()
        if n:
            self.params.add(n)


class PluginImpl(Plugin):
    name = "parameter_enum"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        timeout = int(context["runtime"]["timeout_seconds"])
        seeds = cfg.get("seed_paths", ["/", "/search", "/api", "/api/users?id=1"])
        base = f"https://{task.target}"

        by_endpoint: dict[str, set[str]] = {}
        scripts: set[str] = set()
        all_params: set[str] = set()

        for p in seeds:
            url = p if p.startswith("http") else f"{base}{p}"
            r = await request_http_async("GET", url, headers={}, timeout=timeout)
            text = str(r.get("text", ""))
            ep = urlparse(url).path or "/"
            q_params = set(parse_qs(urlparse(url).query).keys())
            q_params |= set(QUERY_PARAM_RE.findall(url))
            if q_params:
                by_endpoint.setdefault(ep, set()).update(q_params)
                all_params |= q_params
            fp = _FormParser()
            try:
                fp.feed(text)
            except Exception:
                pass
            if fp.params:
                by_endpoint.setdefault(ep, set()).update(fp.params)
                all_params |= fp.params
            for s in SCRIPT_RE.findall(text):
                if s.startswith("/"):
                    scripts.add(base + s)
                elif s.startswith("http"):
                    scripts.add(s)

        for surl in sorted(scripts)[:25]:
            if urlparse(surl).netloc not in {"", task.target}:
                continue
            js = await request_http_async("GET", surl, headers={}, timeout=timeout)
            jst = str(js.get("text", ""))
            js_params = set(JS_PARAM_RE.findall(jst))
            if js_params:
                by_endpoint.setdefault(urlparse(surl).path or "/", set()).update(js_params)
                all_params |= js_params

        if not all_params:
            return []
        consolidated = {k: sorted(list(v)) for k, v in by_endpoint.items()}
        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="parameter_enumeration",
                severity="info",
                title=f"Parameter enumeration found {len(all_params)} unique parameters",
                evidence={"parameters_by_endpoint": dict(list(consolidated.items())[:80]), "all_parameters_sample": sorted(all_params)[:120]},
                metadata={"novelty": 68, "confidence": 80, "impact": 34},
            )
        ]
