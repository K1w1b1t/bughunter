from __future__ import annotations

from hunterops.evidence import save_http_evidence
from hunterops.http_client import request_http_async
from hunterops.plugin_base import Plugin
from hunterops.session_profiles import auth_header, load_sessions
from hunterops.types import Finding, Task


class PluginImpl(Plugin):
    name = "auth_token_tests"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get("auth_token_tests", {})
        sessions = load_sessions(PathLike(cfg.get("sessions_file", "data/sessions.yaml")))
        timeout = context["runtime"]["timeout_seconds"]
        evidence_root = PathLike(cfg.get("evidence_dir", "data/evidence/engine"))
        test_path = cfg.get("path", "/api/me")
        url = f"https://{task.target}{test_path}"
        findings: list[Finding] = []

        if not sessions:
            return findings
        base_sess = next(iter(sessions.values()))
        base_headers = auth_header(base_sess)

        tests = [
            ("no_token", {}),
            ("valid_token", base_headers),
            ("invalid_token", {**base_headers, "Authorization": "Bearer invalid.invalid.invalid"}),
            ("expired_like_token", {**base_headers, "Authorization": "Bearer expired.token.value"}),
        ]
        if len(sessions) >= 2:
            second = list(sessions.values())[1]
            tests.append(("other_user_token", auth_header(second)))

        responses = []
        for name, hdr in tests:
            r = await request_http_async("GET", url, headers=hdr, timeout=timeout)
            responses.append({"name": name, "response": r})

        status_map = {x["name"]: x["response"]["status"] for x in responses}
        if status_map.get("no_token", 0) == 200 or status_map.get("invalid_token", 0) == 200:
            ev = save_http_evidence(
                evidence_root,
                self.name,
                task.target,
                {"method": "GET", "url": url, "tests": [x[0] for x in tests]},
                {"responses": responses},
            )
            findings.append(
                Finding(
                    plugin=self.name,
                    target=task.target,
                    category="auth_token_control_weakness",
                    severity="high",
                    title="Authentication control anomaly in token tests",
                    evidence=ev | {"statuses": status_map},
                    metadata={"novelty": 90, "confidence": 74, "impact": 86},
                )
            )
        return findings


def PathLike(value: str):
    from pathlib import Path
    return Path(value)
