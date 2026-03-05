from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse

from hunterops.http_client import json_keys, request_http_async
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task


class _HTMLSurfaceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: set[str] = set()
        self.forms: list[dict[str, str]] = []
        self.current_form: dict[str, str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        amap = {k.lower(): (v or "") for k, v in attrs}
        if tag.lower() == "a" and amap.get("href"):
            self.links.add(amap["href"])
        elif tag.lower() == "form":
            self.current_form = {
                "action": amap.get("action", ""),
                "method": (amap.get("method", "GET") or "GET").upper(),
            }
        elif tag.lower() == "input" and self.current_form is not None:
            name = amap.get("name", "").strip()
            if name:
                k = self.current_form.get("params", "")
                self.current_form["params"] = f"{k},{name}" if k else name

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None


def _normalize_path(u: str) -> str:
    p = urlparse(u)
    path = p.path or "/"
    if p.query:
        path = f"{path}?{p.query}"
    return path


class PluginImpl(Plugin):
    name = "crawler_intelligent"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        timeout = int(context["runtime"]["timeout_seconds"])
        max_pages = int(cfg.get("max_pages", 25))
        max_depth = int(cfg.get("max_depth", 2))
        start = f"https://{task.target}/"

        queue: list[tuple[str, int]] = [(start, 0)]
        seen: set[str] = set()
        endpoints: set[str] = set()
        params: set[str] = set()
        forms: list[dict[str, str]] = []
        snapshots: list[dict[str, object]] = []

        while queue and len(seen) < max_pages:
            url, depth = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)

            r = await request_http_async("GET", url, headers={}, timeout=timeout)
            body = str(r.get("text", ""))
            parsed = urlparse(url)
            endpoints.add(_normalize_path(url))
            for k in parse_qs(parsed.query).keys():
                params.add(k)
            snapshots.append(
                {
                    "asset_id": task.target,
                    "endpoint": parsed.path or "/",
                    "method": "GET",
                    "status": int(r.get("status", 0)),
                    "length": int(r.get("length", 0)),
                    "json_keys": json_keys(body),
                    "body_hash": hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest(),
                    "seen_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                }
            )

            if depth >= max_depth or "text/html" not in str((r.get("headers") or {}).get("Content-Type", "")).lower():
                continue

            hp = _HTMLSurfaceParser()
            try:
                hp.feed(body)
            except Exception:
                continue
            for f in hp.forms:
                forms.append(f)
                action = f.get("action", "") or parsed.path or "/"
                method = f.get("method", "GET")
                form_params = [x for x in (f.get("params", "") or "").split(",") if x]
                for p in form_params:
                    params.add(p)
                endpoints.add(action)
                snapshots.append(
                    {
                        "asset_id": task.target,
                        "endpoint": action,
                        "method": method,
                        "status": int(r.get("status", 0)),
                        "length": int(r.get("length", 0)),
                        "json_keys": [],
                        "body_hash": hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest(),
                        "seen_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                    }
                )
            for raw_link in hp.links:
                abs_url = urljoin(url, raw_link)
                up = urlparse(abs_url)
                if up.scheme not in {"http", "https"}:
                    continue
                if up.netloc and up.netloc != task.target:
                    continue
                endpoints.add(_normalize_path(abs_url))
                for k in parse_qs(up.query).keys():
                    params.add(k)
                if depth + 1 <= max_depth:
                    queue.append((abs_url, depth + 1))

        if not endpoints:
            return []
        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="surface_discovery_crawler",
                severity="info",
                title=f"Intelligent crawler discovered {len(endpoints)} endpoints and {len(params)} parameters",
                evidence={
                    "seed_url": start,
                    "endpoints_sample": sorted(endpoints)[:80],
                    "params_sample": sorted(params)[:80],
                    "forms_sample": forms[:30],
                },
                metadata={
                    "novelty": 72,
                    "confidence": 74,
                    "impact": 35,
                    "endpoints": sorted(endpoints),
                    "snapshots": snapshots[:200],
                },
            )
        ]
