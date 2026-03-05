from __future__ import annotations

from hunterops.evidence import save_http_evidence
from hunterops.http_client import request_http_async
from hunterops.plugin_base import Plugin
from hunterops.session_profiles import auth_header, load_sessions
from hunterops.types import Finding, Task


class PluginImpl(Plugin):
    name = "role_access"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get("role_access", {})
        sessions = load_sessions(PathLike(cfg.get("sessions_file", "data/sessions.yaml")))
        timeout = context["runtime"]["timeout_seconds"]
        evidence_root = PathLike(cfg.get("evidence_dir", "data/evidence/engine"))
        findings: list[Finding] = []

        role_order = cfg.get("role_order", ["user", "admin"])
        test_paths = cfg.get("paths", ["/admin", "/api/admin/users"])
        if len(role_order) < 2:
            return findings

        low = sessions.get(role_order[0], {})
        high = sessions.get(role_order[-1], {})
        if not low or not high:
            return findings
        low_h = auth_header(low)
        high_h = auth_header(high)

        for p in test_paths:
            url = f"https://{task.target}{p}"
            low_r = await request_http_async("GET", url, headers=low_h, timeout=timeout)
            high_r = await request_http_async("GET", url, headers=high_h, timeout=timeout)
            if low_r["status"] == high_r["status"] == 200 and low_r["text"] == high_r["text"]:
                ev = save_http_evidence(
                    evidence_root,
                    self.name,
                    task.target,
                    {"method": "GET", "url": url, "roles": role_order},
                    {"low": low_r, "high": high_r},
                )
                findings.append(
                    Finding(
                        plugin=self.name,
                        target=task.target,
                        category="role_access_anomaly",
                        severity="high",
                        title=f"Low role may access high-role endpoint: {p}",
                        evidence=ev,
                        metadata={"novelty": 88, "confidence": 70, "impact": 90},
                    )
                )
        return findings


def PathLike(value: str):
    from pathlib import Path
    return Path(value)
