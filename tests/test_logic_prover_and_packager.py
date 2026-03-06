from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from pathlib import Path

import hunterops.plugins.evidence_packager as packager_mod
import hunterops.plugins.logic_prover as logic_mod
from hunterops.types import Task


class _FakeLogicStorage:
    def __init__(self, dsn: str, enabled: bool = False) -> None:
        self.dsn = dsn
        self.enabled = enabled

    def ensure_research_schema(self) -> None:
        return

    def list_endpoint_parameters(self, run_id: str, limit: int = 1000) -> list[dict]:
        return [{"endpoint": "/api/users", "param_name": "user_id"}]

    def list_objects(self, run_id: str, target: str = "", limit: int = 300, object_types: list[str] | None = None) -> list[dict]:
        return [{"object_key": "1002"}]

    def list_recent_entities(self, target: str, limit: int = 200, entity_types: list[str] | None = None) -> list[dict]:
        return [{"entity_type": "numeric_id", "entity_value": "1002"}]

    def upsert_discovered_entities(self, run_id: str, target: str, rows: list[dict]) -> int:
        return len(rows)

    def upsert_objects(self, run_id: str, target: str, rows: list[dict]) -> int:
        return len(rows)

    def upsert_attack_graph_edges(self, *, run_id: str, target: str, edges: list[dict], discovery_source: str = "", confidence_score: float = 0.0) -> int:
        return len(edges)

    def mark_verified_vulnerability_chain(
        self,
        *,
        run_id: str,
        target: str,
        endpoint: str,
        relation: str = "verified_vulnerability_chain",
        confidence_score: float = 95.0,
        metadata: dict | None = None,
        evidence_ref: str = "",
    ) -> None:
        return


async def _stub_logic_request(method: str, url: str, headers: dict | None = None, body: object = None, timeout: int = 20) -> dict:
    auth = (headers or {}).get("Authorization", "")
    if "user_token" in auth:
        text = '{"id":1002,"email":"owner@example.com","name":"owner"}'
        return {"status": 200, "length": len(text), "headers": {"Content-Type": "application/json"}, "text": text}
    if "user_b_token" in auth:
        text = '{"id":1002,"email":"leaked@example.com","name":"attacker"}'
        return {"status": 200, "length": len(text), "headers": {"Content-Type": "application/json"}, "text": text}
    return {"status": 403, "length": 21, "headers": {"Content-Type": "application/json"}, "text": '{"error":"forbidden"}'}


class LogicProverAndPackagerTests(unittest.TestCase):
    def test_logic_prover_emits_access_control_signal(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sessions = Path(td) / "sessions.yaml"
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
            prev_storage = logic_mod.PostgresStorage
            prev_request = logic_mod.request_http_async
            os.environ["HUNTEROPS_POSTGRES_DSN"] = "postgres://fake"
            try:
                logic_mod.PostgresStorage = _FakeLogicStorage  # type: ignore[assignment]
                logic_mod.request_http_async = _stub_logic_request  # type: ignore[assignment]
                plugin = logic_mod.PluginImpl()
                task = Task(plugin="logic_prover", target="api.example.com", payload={"run_id": "run-logic", "seed_paths": ["/api/users"]})
                context = {
                    "config": {
                        "storage": {"postgres": {"enabled": True, "dsn_env": "HUNTEROPS_POSTGRES_DSN"}},
                        "modules": {"logic_prover": {"sessions_file": str(sessions), "max_candidates": 4, "max_depth": 3}},
                    },
                    "runtime": {"timeout_seconds": 5, "concurrency": 2},
                }
                findings = asyncio.run(plugin.run(task, context))
            finally:
                logic_mod.PostgresStorage = prev_storage  # type: ignore[assignment]
                logic_mod.request_http_async = prev_request  # type: ignore[assignment]
                os.environ.pop("HUNTEROPS_POSTGRES_DSN", None)

            self.assertTrue(findings)
            self.assertIn(findings[0].category, {"Broken_Object_Level_Authorization", "Potential_IDOR_Signal"})
            self.assertTrue(findings[0].metadata.get("verified_vulnerability_chain", False))

    def test_evidence_packager_writes_redacted_markdown_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td) / "bundles"
            plugin = packager_mod.PluginImpl()
            finding_row = {
                "plugin": "logic_prover",
                "target": "api.example.com",
                "category": "Broken_Object_Level_Authorization",
                "severity": "critical",
                "title": "Logic discrepancy confirmed",
                "metadata": {"confidence_score": 92, "impact": 95, "discovery_source": "logic_prover"},
                "evidence": {
                    "endpoint": "/api/users?user_id=1002",
                    "parameter": "user_id",
                    "request_auth_a": {"method": "GET", "url": "https://api.example.com/api/users?user_id=1002", "headers": {"Authorization": "Bearer owner-secret-token"}},
                    "request_auth_b": {"method": "GET", "url": "https://api.example.com/api/users?user_id=1002", "headers": {"Authorization": "Bearer attacker-secret-token"}},
                    "request_unauthenticated": {"method": "GET", "url": "https://api.example.com/api/users?user_id=1002", "headers": {}},
                    "response_auth_a": {"status": 200, "length": 48, "headers": {}, "body": '{"email":"owner@example.com","token":"abc123"}'},
                    "response_auth_b": {"status": 200, "length": 50, "headers": {}, "body": '{"email":"leaked@example.com","token":"def456"}'},
                    "response_unauthenticated": {"status": 403, "length": 21, "headers": {}, "body": '{"error":"forbidden"}'},
                },
            }
            task = Task(plugin="evidence_packager", target="api.example.com", payload={"run_id": "run-packager", "findings": [finding_row]})
            context = {"config": {"modules": {"evidence_packager": {"out_dir": str(out_dir), "confidence_threshold": 80}}}}
            findings = asyncio.run(plugin.run(task, context))
            self.assertEqual(len(findings), 1)
            report_path = Path(str(findings[0].evidence.get("report_path", "")))
            self.assertTrue(report_path.exists())
            content = report_path.read_text(encoding="utf-8")
            self.assertIn("Raw Request/Response Logs", content)
            self.assertIn("Bear...oken", content)


if __name__ == "__main__":
    unittest.main()

