from __future__ import annotations

from hunterops.evidence import save_http_evidence
from hunterops.http_client import json_keys, request_http_async
from hunterops.intelligence import http_diff_score
from hunterops.plugin_base import Plugin
from hunterops.session_profiles import auth_header, load_sessions
from hunterops.types import Finding, Task


class PluginImpl(Plugin):
    name = "auth_compare"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get("auth_compare", {})
        sessions = load_sessions(PathLike(cfg.get("sessions_file", "data/sessions.yaml")))
        timeout = context["runtime"]["timeout_seconds"]
        evidence_root = PathLike(cfg.get("evidence_dir", "data/evidence/engine"))
        findings: list[Finding] = []

        test_paths = cfg.get("paths", ["/", "/api/me", "/api/profile"])
        base = f"https://{task.target}"
        for p in test_paths:
            url = base + p
            unauth = await request_http_async("GET", url, headers={}, timeout=timeout)
            unauth_meta = {"status": unauth["status"], "length": unauth["length"], "json_keys": json_keys(unauth["text"])}

            for sess_name, sess in sessions.items():
                headers = auth_header(sess)
                auth_resp = await request_http_async("GET", url, headers=headers, timeout=timeout)
                auth_meta = {"status": auth_resp["status"], "length": auth_resp["length"], "json_keys": json_keys(auth_resp["text"])}
                diff = http_diff_score(unauth_meta, auth_meta)
                if diff["anomaly_score"] >= 40:
                    ev = save_http_evidence(
                        evidence_root,
                        self.name,
                        task.target,
                        {"method": "GET", "url": url, "headers": headers},
                        {"unauth": unauth, "auth": auth_resp, "diff": diff, "session": sess_name},
                    )
                    findings.append(
                        Finding(
                            plugin=self.name,
                            target=task.target,
                            category="auth_vs_unauth_behavior_change",
                            severity="high",
                            title=f"Behavior differs between unauth and {sess_name} at {p}",
                            evidence=ev | {"diff": diff, "session": sess_name},
                            metadata={"novelty": 90, "confidence": 75, "impact": 80},
                        )
                    )
        return findings


def PathLike(value: str):
    from pathlib import Path
    return Path(value)
