from __future__ import annotations

import os
import unittest
from unittest.mock import AsyncMock, patch

from hunterops.plugins.deep_js_intelligence import PluginImpl
from hunterops.types import Task


class DeepJSIntelligenceTests(unittest.IsolatedAsyncioTestCase):
    async def test_extracts_endpoints_and_secrets(self) -> None:
        plugin = PluginImpl()
        ctx = {
            "config": {
                "modules": {"deep_js_intelligence": {"seed_paths": ["/"], "max_scripts": 5, "entropy_threshold": 3.0}},
                "storage": {"postgres": {"enabled": False}},
            },
            "runtime": {"timeout_seconds": 5},
        }

        async def fake_http(method: str, url: str, headers: dict | None = None, body: object | None = None, timeout: int = 5) -> dict:
            if url.endswith("/"):
                return {"status": 200, "length": 80, "headers": {"Content-Type": "text/html"}, "text": '<script src="/main.js"></script>'}
            return {
                "status": 200,
                "length": 300,
                "headers": {"Content-Type": "application/javascript"},
                "text": "fetch('/api/users?id=1'); const k='AAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBB'; const q='query Users($id:Int){user(id:$id){id}}';",
            }

        with patch("hunterops.plugins.deep_js_intelligence.request_http_async", new=AsyncMock(side_effect=fake_http)):
            findings = await plugin.run(Task(plugin="deep_js_intelligence", target="api.example.com", payload={"run_id": "r1"}), ctx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "js_discovery")
        self.assertIn("endpoints", findings[0].evidence)

    async def test_persists_attack_graph_nodes_when_postgres_enabled(self) -> None:
        plugin = PluginImpl()
        ctx = {
            "config": {
                "modules": {"deep_js_intelligence": {"seed_paths": ["/"], "max_scripts": 2}},
                "storage": {"postgres": {"enabled": True, "dsn_env": "HUNTEROPS_POSTGRES_DSN"}},
            },
            "runtime": {"timeout_seconds": 5},
        }

        async def fake_http(method: str, url: str, headers: dict | None = None, body: object | None = None, timeout: int = 5) -> dict:
            if url.endswith("/"):
                return {"status": 200, "length": 80, "headers": {"Content-Type": "text/html"}, "text": '<script src="/main.js"></script>'}
            return {"status": 200, "length": 120, "headers": {"Content-Type": "application/javascript"}, "text": "fetch('/api/orders?id=1')"}

        with patch.dict(os.environ, {"HUNTEROPS_POSTGRES_DSN": "postgresql://x:y@localhost:5432/db"}), patch(
            "hunterops.plugins.deep_js_intelligence.request_http_async",
            new=AsyncMock(side_effect=fake_http),
        ), patch("hunterops.plugins.deep_js_intelligence.PostgresStorage.ensure_research_schema"), patch(
            "hunterops.plugins.deep_js_intelligence.PostgresStorage.upsert_attack_graph_nodes"
        ) as upsert:
            await plugin.run(Task(plugin="deep_js_intelligence", target="api.example.com", payload={"run_id": "r2"}), ctx)
        self.assertTrue(upsert.called)


if __name__ == "__main__":
    unittest.main()
