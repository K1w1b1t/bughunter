from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from hunterops.http_client import json_keys, request_http_async
from hunterops.intelligence import http_diff_score
from hunterops.plugin_base import Plugin
from hunterops.session_profiles import auth_header, load_sessions
from hunterops.types import Finding, Task


def _load_payloads(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    rows = doc.get("payloads", []) if isinstance(doc, dict) else []
    return [x for x in rows if isinstance(x, dict)]


def set_query(url: str, key: str, value: str) -> str:
    p = urlparse(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    replaced = False
    for i, (k, _) in enumerate(q):
        if k == key:
            q[i] = (k, value)
            replaced = True
            break
    if not replaced:
        q.append((key, value))
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(q), p.fragment))


def _path(value: str):
    from pathlib import Path

    return Path(value)


class PluginImpl(Plugin):
    name = "context_aware_fuzzing_engine"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        timeout = int(context["runtime"]["timeout_seconds"])
        payload_file = _path(cfg.get("payload_file", "data/processed/smart_payloads.json"))
        payloads = _load_payloads(payload_file)
        if not payloads:
            return []
        sessions = load_sessions(_path(cfg.get("sessions_file", "data/sessions.yaml")))
        base = f"https://{task.target}"

        findings: list[Finding] = []
        max_tests = int(cfg.get("max_tests", 80))
        tested = 0
        for item in payloads:
            if tested >= max_tests:
                break
            ep = str(item.get("endpoint", ""))
            param = str(item.get("parameter", ""))
            vals = item.get("payloads", [])
            if not ep or not param or not isinstance(vals, list):
                continue
            base_url = f"{base}{ep}" if ep.startswith("/") else ep
            anon = await request_http_async("GET", base_url, headers={}, timeout=timeout)
            anon_meta = {"status": anon.get("status", 0), "length": anon.get("length", 0), "json_keys": json_keys(str(anon.get("text", "")))}

            for v in vals[:4]:
                tested += 1
                murl = set_query(base_url, param, str(v))
                mr = await request_http_async("GET", murl, headers={}, timeout=timeout)
                diff = http_diff_score(anon_meta, {"status": mr.get("status", 0), "length": mr.get("length", 0), "json_keys": json_keys(str(mr.get("text", "")))})
                auth_diffs = []
                for s_name, s_cfg in list(sessions.items())[:2]:
                    ar = await request_http_async("GET", murl, headers=auth_header(s_cfg), timeout=timeout)
                    ad = http_diff_score(anon_meta, {"status": ar.get("status", 0), "length": ar.get("length", 0), "json_keys": json_keys(str(ar.get("text", "")))})
                    if ad["anomaly_score"] >= 40:
                        auth_diffs.append({"session": s_name, "diff": ad})
                if diff["anomaly_score"] >= 40 or auth_diffs:
                    findings.append(
                        Finding(
                            plugin=self.name,
                            target=task.target,
                            category="context_aware_fuzzing_anomaly",
                            severity="medium",
                            title=f"Context-aware anomaly on {ep} parameter {param}",
                            evidence={
                                "request": {"method": "GET", "url": murl, "headers": {}},
                                "response": {"status": mr.get("status", 0), "length": mr.get("length", 0)},
                                "headers": mr.get("headers", {}),
                                "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                                "discovery_source": "context_aware_fuzzing_engine",
                                "base_url": base_url,
                                "param": param,
                                "payload": str(v),
                                "diff": diff,
                                "auth_diffs": auth_diffs,
                            },
                            metadata={"novelty": 74, "confidence": 69, "impact": 60, "discovery_source": "context_aware_fuzzing"},
                        )
                    )
        return findings
