from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from hunterops.evidence import save_http_evidence
from hunterops.http_client import request_http_async
from hunterops.plugin_base import Plugin
from hunterops.session_profiles import auth_header, load_sessions
from hunterops.types import Finding, Task


NUMERIC_KEYS = {"id", "user_id", "account_id", "invoice_id", "tenant_id", "order_id"}


def mutate_numeric_params(url: str) -> list[str]:
    p = urlparse(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    out: list[str] = []
    for i, (k, v) in enumerate(q):
        if k.lower() in NUMERIC_KEYS or v.isdigit():
            new_q = q[:]
            base = int(v) if v.isdigit() else 1
            new_q[i] = (k, str(base + 1))
            out.append(urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(new_q), p.fragment)))
            new_q[i] = (k, str(max(1, base - 1)))
            out.append(urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(new_q), p.fragment)))
    return out


class PluginImpl(Plugin):
    name = "idor_auto"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get("idor_auto", {})
        sessions = load_sessions(PathLike(cfg.get("sessions_file", "data/sessions.yaml")))
        timeout = context["runtime"]["timeout_seconds"]
        evidence_root = PathLike(cfg.get("evidence_dir", "data/evidence/engine"))
        findings: list[Finding] = []

        urls = [str(u).format(target=task.target) for u in cfg.get("candidate_urls", [f"https://{task.target}/api/profile?id=1"])]
        for url in urls:
            mutated = mutate_numeric_params(url)
            if not mutated:
                continue
            for sess_name, sess in sessions.items():
                hdr = auth_header(sess)
                base = await request_http_async("GET", url, headers=hdr, timeout=timeout)
                for murl in mutated:
                    mr = await request_http_async("GET", murl, headers=hdr, timeout=timeout)
                    if base["status"] == 200 and mr["status"] == 200 and base["text"] != mr["text"]:
                        ev = save_http_evidence(
                            evidence_root,
                            self.name,
                            task.target,
                            {"method": "GET", "url": murl, "headers": hdr},
                            {"base_url": url, "base": base, "mutated": mr, "session": sess_name},
                        )
                        findings.append(
                            Finding(
                                plugin=self.name,
                                target=task.target,
                                category="idor_candidate",
                                severity="high",
                                title=f"Possible IDOR via parameter mutation ({sess_name})",
                                evidence=ev | {"base_url": url, "mutated_url": murl},
                                metadata={"novelty": 92, "confidence": 72, "impact": 85},
                            )
                        )
        return findings


def PathLike(value: str):
    from pathlib import Path
    return Path(value)
