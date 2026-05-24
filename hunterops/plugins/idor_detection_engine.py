from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from hunterops.evidence import save_http_evidence
from hunterops.http_client import json_keys, request_http_async
from hunterops.intelligence import http_diff_score
from hunterops.plugin_base import Plugin
from hunterops.session_profiles import auth_header, load_sessions
from hunterops.types import Finding, Task

ID_KEYS = {"id", "user_id", "account_id", "order_id", "invoice_id", "document_id", "profile_id", "uid"}


def mutate_id_params(url: str) -> list[dict[str, str]]:
    p = urlparse(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    out: list[dict[str, str]] = []
    for i, (k, v) in enumerate(q):
        if k.lower() in ID_KEYS or v.isdigit():
            base = int(v) if v.isdigit() else 1
            for mv in (base + 1, max(1, base - 1)):
                nq = q[:]
                nq[i] = (k, str(mv))
                out.append(
                    {
                        "param": k,
                        "original_value": v,
                        "modified_value": str(mv),
                        "url": urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(nq), p.fragment)),
                    }
                )
    return out


def _path(value: str):
    from pathlib import Path

    return Path(value)


class PluginImpl(Plugin):
    name = "idor_detection_engine"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        timeout = int(context["runtime"]["timeout_seconds"])
        evidence_root = _path(cfg.get("evidence_dir", "data/evidence/engine"))
        sessions = load_sessions(_path(cfg.get("sessions_file", "data/sessions.yaml")))
        targets = [str(x).format(target=task.target) for x in cfg.get("candidate_urls", [f"https://{task.target}/api/users?id=1"])]

        findings: list[Finding] = []
        for base_url in targets:
            variants = mutate_id_params(base_url)
            if not variants:
                continue
            for s_name, s_cfg in sessions.items():
                headers = auth_header(s_cfg)
                base = await request_http_async("GET", base_url, headers=headers, timeout=timeout)
                base_meta = {"status": base.get("status", 0), "length": base.get("length", 0), "json_keys": json_keys(str(base.get("text", "")))}
                for v in variants:
                    mod = await request_http_async("GET", v["url"], headers=headers, timeout=timeout)
                    mod_meta = {"status": mod.get("status", 0), "length": mod.get("length", 0), "json_keys": json_keys(str(mod.get("text", "")))}
                    diff = http_diff_score(base_meta, mod_meta)
                    sensitive_hint = any(k in str(mod.get("text", "")).lower() for k in ("email", "cpf", "phone", "address", "account"))
                    if diff["anomaly_score"] >= 40 and int(mod.get("status", 0)) == 200:
                        ev = save_http_evidence(
                            evidence_root,
                            self.name,
                            task.target,
                            {"method": "GET", "url": v["url"], "headers": headers},
                            {"session": s_name, "base": base_meta, "modified": mod_meta, "diff": diff},
                        )
                        sev = "high" if sensitive_hint else "medium"
                        findings.append(
                            Finding(
                                plugin=self.name,
                                target=task.target,
                                category="idor_behavior_indicator",
                                severity=sev,
                                title=f"Possible IDOR behavior via {v['param']} mutation ({s_name})",
                                evidence=ev
                                | {
                                    "tested_parameter": v["param"],
                                    "original_value": v["original_value"],
                                    "modified_value": v["modified_value"],
                                    "base_url": base_url,
                                    "modified_url": v["url"],
                                    "diff": diff,
                                },
                                metadata={
                                    "novelty": 88,
                                    "confidence": 72 if sensitive_hint else 66,
                                    "impact": 82 if sensitive_hint else 66,
                                    "discovery_source": "idor_detection_engine",
                                },
                            )
                        )
        return findings
