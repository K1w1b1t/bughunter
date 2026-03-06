from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from pathlib import Path

import hunterops.plugins.auth_matrix_engine as mod
from hunterops.types import Task


class _FakeStorage:
    saved_rows: list[dict] = []

    def __init__(self, dsn: str, enabled: bool = False) -> None:
        self.dsn = dsn
        self.enabled = enabled

    def ensure_research_schema(self) -> None:
        return

    def list_known_endpoints(self, target: str, run_id: str = "", limit: int = 500) -> list[str]:
        return ["/api/internal/debug"]

    def list_endpoint_parameters(self, run_id: str, limit: int = 1000) -> list[dict]:
        return [{"endpoint": "/api/internal/debug", "param_name": "account_id", "param_type": "numeric_id"}]

    def list_objects(self, run_id: str, target: str = "", limit: int = 300) -> list[dict]:
        return [{"object_type": "numeric_id", "object_key": "1002"}]

    def list_recent_entities(self, target: str, limit: int = 200) -> list[dict]:
        return [{"entity_type": "email", "entity_value": "victim@example.com"}]

    def upsert_verified_finding(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        _FakeStorage.saved_rows.append(kwargs)


async def _stub_request_with_proxy(method: str, url: str, headers: dict[str, str], timeout: int, proxy: str = "") -> dict:
    auth = headers.get("Authorization", "")
    if "owner_token" in auth:
        text = '{"id":1002,"email":"owner@example.com","phone":"111","address":"A","wallet":"10","account":"A1","invoice":"INV-1"}'
        return {"ok": True, "status": 200, "headers": {"Content-Type": "application/json"}, "text": text, "length": len(text)}
    if "other_token" in auth:
        text = '{"id":1002,"email":"victim@example.com","phone":"222","address":"B","wallet":"20","account":"B2","invoice":"INV-2"}'
        return {"ok": True, "status": 200, "headers": {"Content-Type": "application/json"}, "text": text, "length": len(text)}
    return {"ok": False, "status": 403, "headers": {"Content-Type": "application/json"}, "text": '{"error":"forbidden"}', "length": 21}


class AuthMatrixEngineTests(unittest.TestCase):
    def test_detects_cross_session_signal_and_saves_verified_finding(self) -> None:
        _FakeStorage.saved_rows = []
        with tempfile.TemporaryDirectory() as td:
            sessions = Path(td) / "sessions.yaml"
            sessions.write_text(
                "\n".join(
                    [
                        "sessions:",
                        "  - name: user",
                        "    token_type: Bearer",
                        "    token: owner_token",
                        "  - name: user_b",
                        "    token_type: Bearer",
                        "    token: other_token",
                    ]
                ),
                encoding="utf-8",
            )
            prev_storage = mod.PostgresStorage
            prev_request = mod._request_with_proxy
            os.environ["HUNTEROPS_POSTGRES_DSN"] = "postgres://fake"
            try:
                mod.PostgresStorage = _FakeStorage  # type: ignore[assignment]
                mod._request_with_proxy = _stub_request_with_proxy  # type: ignore[assignment]
                plugin = mod.PluginImpl()
                task = Task(plugin="auth_matrix_engine", target="api.example.com", payload={"run_id": "run-auth", "seed_paths": ["/api/internal/debug"]})
                context = {
                    "config": {
                        "storage": {"postgres": {"enabled": True, "dsn_env": "HUNTEROPS_POSTGRES_DSN"}},
                        "modules": {
                            "auth_matrix_engine": {
                                "sessions_file": str(sessions),
                                "auth_context_a": "user",
                                "auth_context_b": "user_b",
                                "verified_dir": str(Path(td) / "verified"),
                                "max_probes": 8,
                                "verified_threshold": 85,
                                "min_confidence": 50,
                            }
                        },
                    },
                    "runtime": {"timeout_seconds": 5, "concurrency": 2, "recursion_max_depth": 4},
                }
                findings = asyncio.run(plugin.run(task, context))
            finally:
                mod.PostgresStorage = prev_storage  # type: ignore[assignment]
                mod._request_with_proxy = prev_request  # type: ignore[assignment]
                os.environ.pop("HUNTEROPS_POSTGRES_DSN", None)

            self.assertTrue(findings)
            self.assertEqual(findings[0].category, "broken_access_control_matrix_signal")
            self.assertGreater(float(findings[0].metadata.get("confidence_score", 0) or 0), 85.0)
            self.assertTrue(_FakeStorage.saved_rows)
            self.assertTrue(str(findings[0].evidence.get("poc_path", "")).endswith(".py"))


if __name__ == "__main__":
    unittest.main()

