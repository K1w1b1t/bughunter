from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from pathlib import Path

import hunterops.plugins.differential_auth_prover as mod
from hunterops.types import Task


class _FakeStorage:
    def __init__(self, dsn: str, enabled: bool = False) -> None:
        self.dsn = dsn
        self.enabled = enabled

    def ensure_research_schema(self) -> None:
        return

    def fetch_run_findings(self, run_id: str, target: str) -> list[dict]:
        return [
            {
                "category": "js_discovery",
                "evidence": {
                    "endpoints": ["/api/v1/user/settings"],
                },
            }
        ]

    def list_known_endpoints(self, target: str, run_id: str = "", limit: int = 500) -> list[str]:
        return ["/api/v1/user/settings"]

    def list_endpoint_parameters(self, run_id: str, limit: int = 1000) -> list[dict]:
        return [{"endpoint": "/api/v1/user/settings", "param_name": "user_id"}]

    def list_recent_entities(self, target: str, limit: int = 200, entity_types: list[str] | None = None) -> list[dict]:
        return [{"entity_type": "numeric_id", "entity_value": "1001"}]


async def _stub_request(method: str, url: str, headers: dict | None = None, body: object = None, timeout: int = 20) -> dict:
    h = headers or {}
    auth = h.get("Authorization", "")
    if "user_b" in auth:
        text = '{"email":"owner@example.com","user_id":1001,"timestamp":"2026-03-05T10:00:00Z"}'
        return {"ok": True, "status": 200, "headers": {"Content-Type": "application/json"}, "text": text, "length": len(text)}
    if "user_token" in auth:
        text = '{"email":"owner@example.com","user_id":1001,"timestamp":"2026-03-05T10:00:01Z"}'
        return {"ok": True, "status": 200, "headers": {"Content-Type": "application/json"}, "text": text, "length": len(text)}
    return {"ok": False, "status": 403, "headers": {"Content-Type": "application/json"}, "text": '{"error":"forbidden"}', "length": 21}


class DifferentialAuthProverTests(unittest.TestCase):
    def test_plugin_detects_high_confidence_idor_signal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sessions = Path(tmp) / "sessions.yaml"
            sessions.write_text(
                "\n".join(
                    [
                        "sessions:",
                        "  - name: user",
                        "    token_type: Bearer",
                        "    token: user_token",
                        "  - name: user_b",
                        "    token_type: Bearer",
                        "    token: user_b_token",
                    ]
                ),
                encoding="utf-8",
            )
            plugin = mod.PluginImpl()
            task = Task(plugin="differential_auth_prover", target="api.example.com", payload={"run_id": "run_123", "seed_paths": ["/api/v1/user/settings"]})
            context = {
                "config": {
                    "storage": {"postgres": {"enabled": True, "dsn_env": "HUNTEROPS_POSTGRES_DSN"}},
                    "modules": {
                        "differential_auth_prover": {
                            "sessions_file": str(sessions),
                            "session_owner": "user",
                            "session_other": "user_b",
                            "min_structure_similarity_pct": 90,
                            "min_content_similarity_pct": 85,
                            "max_probes": 10,
                        }
                    },
                },
                "runtime": {"timeout_seconds": 5},
            }
            prev_storage = mod.PostgresStorage
            prev_request = mod.request_http_async
            os.environ["HUNTEROPS_POSTGRES_DSN"] = "postgres://fake"
            try:
                mod.PostgresStorage = _FakeStorage  # type: ignore[assignment]
                mod.request_http_async = _stub_request  # type: ignore[assignment]
                findings = asyncio.run(plugin.run(task, context))
            finally:
                mod.PostgresStorage = prev_storage  # type: ignore[assignment]
                mod.request_http_async = prev_request  # type: ignore[assignment]
                os.environ.pop("HUNTEROPS_POSTGRES_DSN", None)
            self.assertTrue(findings)
            f = findings[0]
            self.assertIn(f.category, {"critical_idor_vulnerability", "idor_behavior_indicator"})
            self.assertIn("diff_map", f.evidence)
            self.assertEqual(f.evidence.get("entity_id"), "1001")


if __name__ == "__main__":
    unittest.main()
