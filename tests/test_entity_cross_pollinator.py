from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from pathlib import Path

import hunterops.plugins.entity_cross_pollinator as mod
from hunterops.types import Task


class _FakeStorage:
    def __init__(self, dsn: str, enabled: bool = False) -> None:
        self.dsn = dsn
        self.enabled = enabled
        self.edges_written = 0

    def ensure_research_schema(self) -> None:
        return

    def fetch_run_findings(self, run_id: str, target: str) -> list[dict]:
        if run_id == "prev_run":
            return [
                {
                    "category": "js_discovery",
                    "evidence": {"endpoints": ["/api/public"]},
                }
            ]
        return [
            {
                "category": "js_discovery",
                "evidence": {"endpoints": ["/api/public", "/api/internal/users"]},
            },
            {
                "category": "surface_map",
                "evidence": {"mapped_sample": [{"endpoint": "/admin/export"}]},
            },
        ]

    def get_previous_run_id(self, target: str, current_run_id: str) -> str:
        return "prev_run"

    def list_known_endpoints(self, target: str, run_id: str = "", limit: int = 500) -> list[str]:
        return ["/api/internal/users", "/admin/export"]

    def list_endpoint_parameters(self, run_id: str, limit: int = 1000) -> list[dict]:
        return [{"endpoint": "/api/internal/users", "param_name": "user_id"}]

    def list_objects(self, run_id: str, target: str = "", limit: int = 300, object_types: list[str] | None = None) -> list[dict]:
        return [
            {
                "object_type": "numeric_id",
                "object_key": "1001",
                "source_endpoint": "/api/internal/users",
                "confidence_score": 88,
                "discovery_source": "deep_js_intelligence",
                "metadata": {},
            }
        ]

    def list_recent_entities(self, target: str, limit: int = 200, entity_types: list[str] | None = None) -> list[dict]:
        return []

    def upsert_attack_graph_edges(self, *, run_id: str, target: str, edges: list[dict], discovery_source: str = "", confidence_score: float = 0.0) -> int:
        self.edges_written += len(edges)
        return len(edges)


async def _stub_request(method: str, url: str, headers: dict | None = None, body: object = None, timeout: int = 20) -> dict:
    h = headers or {}
    auth = h.get("Authorization", "")
    if "user_b_token" in auth:
        text = '{"user_id":1001,"email":"owner@example.com","role":"user"}'
        return {"ok": True, "status": 200, "headers": {"Content-Type": "application/json"}, "text": text, "length": len(text)}
    return {"ok": False, "status": 403, "headers": {"Content-Type": "application/json"}, "text": '{"error":"forbidden"}', "length": 21}


class EntityCrossPollinatorTests(unittest.TestCase):
    def test_generates_recursive_tasks_and_leakage_signal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sessions = Path(tmp) / "sessions.yaml"
            sessions.write_text(
                "\n".join(
                    [
                        "sessions:",
                        "  - name: user_b",
                        "    token_type: Bearer",
                        "    token: user_b_token",
                    ]
                ),
                encoding="utf-8",
            )
            plugin = mod.PluginImpl()
            task = Task(plugin="entity_cross_pollinator", target="api.example.com", payload={"run_id": "run_123", "_depth": 0})
            context = {
                "config": {
                    "storage": {"postgres": {"enabled": True, "dsn_env": "HUNTEROPS_POSTGRES_DSN"}},
                    "modules": {
                        "entity_cross_pollinator": {
                            "sessions_file": str(sessions),
                            "auth_context_b": "user_b",
                            "max_probe_requests": 4,
                            "max_generated_tasks": 50,
                        }
                    },
                },
                "runtime": {"timeout_seconds": 5, "concurrency": 4, "recursion_max_depth": 5},
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
            summary = findings[0]
            self.assertEqual(summary.category, "entity_cross_pollination_queue")
            spawn_tasks = summary.metadata.get("spawn_tasks", [])
            self.assertTrue(isinstance(spawn_tasks, list) and spawn_tasks)
            categories = {f.category for f in findings}
            self.assertIn("object_leakage_indicator", categories)


if __name__ == "__main__":
    unittest.main()
