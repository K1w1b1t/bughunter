from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse

from hunterops.http_client import request_http_async
from hunterops.plugin_base import Plugin
from hunterops.session_profiles import auth_header, load_sessions
from hunterops.types import Finding, Task

SCRIPT_RE = re.compile(r"""<script[^>]+src=['"]([^'"]+)['"]""", re.IGNORECASE)
API_RE = re.compile(r"""['"](/api/[A-Za-z0-9_/\-?=&{}]+)['"]""")


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: set[str] = set()
        self.forms: list[dict[str, object]] = []
        self._form: dict[str, object] | None = None
        self.scripts: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        amap = {k.lower(): (v or "") for k, v in attrs}
        t = tag.lower()
        if t == "a" and amap.get("href"):
            self.links.add(amap["href"])
        if t == "script" and amap.get("src"):
            self.scripts.add(amap["src"])
        if t == "form":
            self._form = {"action": amap.get("action", ""), "method": (amap.get("method", "GET") or "GET").upper(), "fields": []}
        if t in {"input", "select", "textarea"} and self._form is not None:
            n = amap.get("name", "").strip()
            if n:
                fields = self._form.get("fields", [])
                if isinstance(fields, list):
                    fields.append(n)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _path(value: str):
    from pathlib import Path

    return Path(value)


class PluginImpl(Plugin):
    name = "recon_engine"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        timeout = int(context["runtime"]["timeout_seconds"])
        base = f"https://{task.target}"
        seed_paths = cfg.get("seed_paths", ["/", "/login", "/api", "/docs"])
        max_pages = int(cfg.get("max_pages", 15))
        use_auth = bool(cfg.get("authenticated_crawling", False))
        sessions = load_sessions(_path(cfg.get("sessions_file", "data/sessions.yaml"))) if use_auth else {}

        queue = [f"{base}{p}" for p in seed_paths if isinstance(p, str)]
        seen: set[str] = set()
        endpoints: set[str] = set()
        parameters: set[str] = set()
        forms: list[dict[str, object]] = []
        methods: set[str] = {"GET"}
        js_assets: set[str] = set()

        while queue and len(seen) < max_pages:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            headers = {}
            if sessions:
                first = next(iter(sessions.values()))
                headers = auth_header(first)
            r = await request_http_async("GET", url, headers=headers, timeout=timeout)
            txt = str(r.get("text", ""))
            up = urlparse(url)
            endpoints.add(up.path or "/")
            for k in parse_qs(up.query).keys():
                parameters.add(k)

            p = _Parser()
            try:
                p.feed(txt)
            except Exception:
                pass
            for lk in p.links:
                lu = urljoin(url, lk)
                lup = urlparse(lu)
                if lup.netloc in {"", task.target}:
                    queue.append(lu)
                    endpoints.add(lup.path or "/")
                    for k in parse_qs(lup.query).keys():
                        parameters.add(k)
            for f in p.forms:
                forms.append(f)
                methods.add(str(f.get("method", "GET")).upper())
                action = str(f.get("action", "")).strip()
                if action:
                    endpoints.add(urlparse(urljoin(url, action)).path or "/")
                for fld in f.get("fields", []) if isinstance(f.get("fields"), list) else []:
                    parameters.add(str(fld))
            for s in p.scripts:
                su = urljoin(url, s)
                if urlparse(su).netloc in {"", task.target}:
                    js_assets.add(su)

        for su in sorted(js_assets)[:25]:
            jr = await request_http_async("GET", su, headers={}, timeout=timeout)
            jst = str(jr.get("text", ""))
            for ap in API_RE.findall(jst):
                endpoints.add(urlparse(urljoin(base + "/", ap)).path or "/")
                for k in parse_qs(urlparse(ap).query).keys():
                    parameters.add(k)

        if not endpoints:
            return []
        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="recon_engine",
                severity="info",
                title=f"Recon engine mapped {len(endpoints)} endpoints and {len(parameters)} parameters",
                evidence={
                    "endpoints": sorted(endpoints)[:160],
                    "parameters": sorted(parameters)[:160],
                    "forms": forms[:80],
                    "http_methods": sorted(methods),
                    "javascript_assets": sorted(js_assets)[:80],
                },
                metadata={"novelty": 78, "confidence": 80, "impact": 44, "discovery_source": "recon_engine", "endpoints": sorted(endpoints)},
            )
        ]
