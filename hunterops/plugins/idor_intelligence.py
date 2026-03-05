from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from hunterops.http_client import json_keys, request_http_async
from hunterops.intelligence import http_diff_score
from hunterops.plugin_base import Plugin
from hunterops.session_profiles import auth_header, load_sessions
from hunterops.types import Finding, Task

ID_KEYS = {"id", "user_id", "account_id", "order_id", "invoice_id", "profile_id", "uid"}


def mutate(url: str) -> list[dict[str, str]]:
    p = urlparse(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    out: list[dict[str, str]] = []
    for i, (k, v) in enumerate(q):
        if k.lower() in ID_KEYS or v.isdigit():
            base = int(v) if v.isdigit() else 1
            for mv in (base + 1, max(1, base - 1)):
                nq = q[:]
                nq[i] = (k, str(mv))
                out.append({"parameter": k, "original": v, "modified": str(mv), "url": urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(nq), p.fragment))})
    return out


def _path(value: str):
    from pathlib import Path

    return Path(value)


class PluginImpl(Plugin):
    name = "idor_intelligence"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        timeout = int(context["runtime"]["timeout_seconds"])
        sessions = load_sessions(_path(cfg.get("sessions_file", "data/sessions.yaml")))
        urls = [str(x).format(target=task.target) for x in cfg.get("candidate_urls", [f"https://{task.target}/api/users?id=1"])]

        findings: list[Finding] = []
        for url in urls:
            muts = mutate(url)
            if not muts:
                continue
            for s_name, s_cfg in sessions.items():
                hdr = auth_header(s_cfg)
                base = await request_http_async("GET", url, headers=hdr, timeout=timeout)
                base_meta = {"status": base.get("status", 0), "length": base.get("length", 0), "json_keys": json_keys(str(base.get("text", "")))}
                for m in muts:
                    mr = await request_http_async("GET", m["url"], headers=hdr, timeout=timeout)
                    mod_meta = {"status": mr.get("status", 0), "length": mr.get("length", 0), "json_keys": json_keys(str(mr.get("text", "")))}
                    diff = http_diff_score(base_meta, mod_meta)
                    sensitive_fields = [k for k in ("email", "cpf", "phone", "address", "account") if k in str(mr.get("text", "")).lower()]
                    if diff["anomaly_score"] >= 40 and int(mr.get("status", 0)) == 200:
                        findings.append(
                            Finding(
                                plugin=self.name,
                                target=task.target,
                                category="idor_inconsistency_indicator",
                                severity="medium" if not sensitive_fields else "high",
                                title=f"IDOR intelligence detected response inconsistency ({s_name})",
                                evidence={
                                    "request": {"method": "GET", "url": m["url"], "headers": hdr},
                                    "response": {"status": mr.get("status", 0), "length": mr.get("length", 0)},
                                    "headers": mr.get("headers", {}),
                                    "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                                    "discovery_source": "idor_intelligence",
                                    "base_url": url,
                                    "tested_parameter": m["parameter"],
                                    "original_value": m["original"],
                                    "modified_value": m["modified"],
                                    "response_diff": diff,
                                    "sensitive_field_indicators": sensitive_fields,
                                },
                                metadata={
                                    "novelty": 86,
                                    "confidence": 70 if sensitive_fields else 64,
                                    "impact": 82 if sensitive_fields else 64,
                                    "discovery_source": "idor_intelligence",
                                },
                            )
                        )
        return findings
