from __future__ import annotations

from hunterops.evidence import save_http_evidence
from hunterops.http_client import request_http_async
from hunterops.plugin_base import Plugin
from hunterops.session_profiles import auth_header, load_sessions
from hunterops.types import Finding, Task


class PluginImpl(Plugin):
    name = "stateful_flows"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get("stateful_flows", {})
        timeout = context["runtime"]["timeout_seconds"]
        sessions = load_sessions(PathLike(cfg.get("sessions_file", "data/sessions.yaml")))
        evidence_root = PathLike(cfg.get("evidence_dir", "data/evidence/engine"))
        flows = cfg.get(
            "flows",
            [
                {"name": "checkout", "steps": ["/api/cart", "/api/checkout", "/api/payment/confirm"]},
                {"name": "upgrade", "steps": ["/api/plan/current", "/api/plan/upgrade", "/api/plan/confirm"]},
                {"name": "reset", "steps": ["/api/password/request-reset", "/api/password/confirm-reset"]},
                {"name": "approval", "steps": ["/api/request/create", "/api/request/approve"]},
            ],
        )
        findings: list[Finding] = []
        if not sessions:
            return findings
        sess_name, sess = next(iter(sessions.items()))
        headers = auth_header(sess)

        for flow in flows:
            statuses = []
            bodies = []
            for step in flow.get("steps", []):
                url = f"https://{task.target}{step}"
                r = await request_http_async("GET", url, headers=headers, timeout=timeout)
                statuses.append(r["status"])
                bodies.append(r["text"][:300])
            # suspicious when later step succeeds while earlier precondition fails
            suspicious = any(s in {200, 201, 202} for s in statuses[1:]) and statuses[0] in {401, 403, 404}
            if suspicious:
                ev = save_http_evidence(
                    evidence_root,
                    self.name,
                    task.target,
                    {"flow": flow.get("name"), "session": sess_name, "steps": flow.get("steps", [])},
                    {"statuses": statuses, "bodies_sample": bodies},
                )
                findings.append(
                    Finding(
                        plugin=self.name,
                        target=task.target,
                        category="stateful_flow_bypass",
                        severity="high",
                        title=f"Possible workflow bypass in flow `{flow.get('name')}`",
                        evidence=ev | {"statuses": statuses},
                        metadata={"novelty": 93, "confidence": 70, "impact": 88},
                    )
                )
        return findings


def PathLike(value: str):
    from pathlib import Path
    return Path(value)

