from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from hunterops.async_io import read_json
from hunterops.http_client import request_http_async
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task

TOKEN_SPLIT = re.compile(r"[^a-z0-9._-]+")
VERSION_RE = re.compile(r"\b\d{1,4}(?:\.\d+){1,3}\b")


async def load_catalog(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        payload = await read_json(path)
    except Exception:
        return []
    rows = payload.get("cves", []) if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        return []
    return [x for x in rows if isinstance(x, dict)]


def tokenize(raw: str) -> set[str]:
    out: set[str] = set()
    for item in TOKEN_SPLIT.split(raw.lower()):
        v = item.strip()
        if len(v) >= 3:
            out.add(v)
    return out


def cve_tokens(row: dict[str, Any]) -> set[str]:
    toks: set[str] = set()
    for key in ("vendor", "product", "description"):
        toks |= tokenize(str(row.get(key, "")))
    for cpe in row.get("cpes", []) or []:
        toks |= tokenize(str(cpe))
    for kw in row.get("keywords", []) or []:
        toks |= tokenize(str(kw))
    return toks


def parse_versions(text: str) -> set[str]:
    return set(VERSION_RE.findall(text))


def rank(row: dict[str, Any], match_count: int, version_match: bool) -> float:
    cvss = float(row.get("cvss", 0.0) or 0.0)
    epss = float(row.get("epss", 0.0) or 0.0)
    kev_bonus = 25.0 if bool(row.get("kev", False)) else 0.0
    version_bonus = 15.0 if version_match else 0.0
    token_bonus = min(20.0, float(match_count) * 3.0)
    return round(min(100.0, cvss * 6.0 + epss * 20.0 + kev_bonus + version_bonus + token_bonus), 2)


class PluginImpl(Plugin):
    name = "cve_matcher"

    async def run(self, task: Task, context: dict[str, Any]) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        timeout = context["runtime"]["timeout_seconds"]
        catalog = await load_catalog(Path(cfg.get("catalog_file", "data/processed/cve_catalog.json")))
        if not catalog:
            return []

        probe_paths = cfg.get("probe_paths", ["/", "/api", "/graphql"])
        probes: list[dict[str, Any]] = []
        token_pool: set[str] = set()
        version_pool: set[str] = set()
        base = f"https://{task.target}"
        for p in probe_paths:
            url = base + p
            resp = await request_http_async("GET", url, headers={}, timeout=timeout)
            headers_txt = " ".join([f"{k}:{v}" for k, v in (resp.get("headers") or {}).items()])
            body = str(resp.get("text", ""))[:10000]
            combined = f"{headers_txt} {body}"
            p_tokens = tokenize(combined)
            p_versions = parse_versions(combined)
            token_pool |= p_tokens
            version_pool |= p_versions
            probes.append({"url": url, "status": resp.get("status", 0), "length": resp.get("length", 0)})

        if not token_pool:
            return []

        min_token_matches = int(cfg.get("min_token_matches", 2))
        top_n = int(cfg.get("top_n", 8))
        candidates: list[tuple[float, dict[str, Any], list[str], bool]] = []
        for row in catalog:
            toks = cve_tokens(row)
            if not toks:
                continue
            intersection = sorted(list(toks & token_pool))
            if len(intersection) < min_token_matches:
                continue
            cve_versions = {str(x) for x in (row.get("versions") or []) if str(x)}
            version_match = bool(cve_versions & version_pool) if cve_versions else False
            score = rank(row, len(intersection), version_match)
            candidates.append((score, row, intersection[:8], version_match))

        if not candidates:
            return []
        candidates.sort(key=lambda x: x[0], reverse=True)

        findings: list[Finding] = []
        for score, row, terms, version_match in candidates[:top_n]:
            cve_id = str(row.get("cve", "")).strip()
            if not cve_id:
                continue
            sev = "medium"
            if bool(row.get("kev", False)) or float(row.get("cvss", 0.0) or 0.0) >= 9.0:
                sev = "high"
            findings.append(
                Finding(
                    plugin=self.name,
                    target=task.target,
                    category="cve_relevance",
                    severity=sev,
                    title=f"Potentially relevant CVE matched: {cve_id}",
                    evidence={
                        "cve": cve_id,
                        "matched_terms": terms,
                        "version_match": version_match,
                        "probes": probes,
                    },
                    metadata={
                        "novelty": 70,
                        "confidence": 55 if not version_match else 72,
                        "impact": 62,
                        "cve": cve_id,
                        "cvss": row.get("cvss", 0.0),
                        "epss": row.get("epss", 0.0),
                        "kev": bool(row.get("kev", False)),
                        "matcher_score": score,
                    },
                )
            )
        return findings
