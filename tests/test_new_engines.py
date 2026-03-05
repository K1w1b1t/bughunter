from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch

from hunterops.plugins.idor_detection_engine import PluginImpl as IDOREnginePlugin
from hunterops.plugins.parameter_intelligence import PluginImpl as ParamIntelPlugin
from hunterops.plugins.response_diff_engine import PluginImpl as ResponseDiffPlugin
from hunterops.plugins.surface_mapper import PluginImpl as SurfaceMapperPlugin
from hunterops.types import Task


class NewEnginesTests(unittest.IsolatedAsyncioTestCase):
    async def test_surface_mapper_classifies_endpoints(self) -> None:
        plugin = SurfaceMapperPlugin()
        ctx = {"config": {"modules": {"surface_mapper": {"seed_paths": ["/api/users", "/admin"]}}}, "runtime": {"timeout_seconds": 5}}

        async def fake_http(method: str, url: str, headers: dict | None = None, body: object | None = None, timeout: int = 5) -> dict:
            return {"status": 200, "length": 40, "headers": {"Content-Type": "application/json"}, "text": '{"ok":true}'}

        with patch("hunterops.plugins.surface_mapper.request_http_async", new=AsyncMock(side_effect=fake_http)):
            findings = await plugin.run(Task(plugin="surface_mapper", target="api.example.com"), ctx)
        self.assertEqual(len(findings), 1)
        self.assertIn("class_distribution", findings[0].evidence)

    async def test_parameter_intelligence_extracts_parameters(self) -> None:
        plugin = ParamIntelPlugin()
        ctx = {"config": {"modules": {"parameter_intelligence": {"seed_paths": ["/search?q=test"]}}}, "runtime": {"timeout_seconds": 5}}

        async def fake_http(method: str, url: str, headers: dict | None = None, body: object | None = None, timeout: int = 5) -> dict:
            return {"status": 200, "length": 120, "headers": {"Content-Type": "text/html"}, "text": '<form><input name="user_id"/></form>'}

        with patch("hunterops.plugins.parameter_intelligence.request_http_async", new=AsyncMock(side_effect=fake_http)):
            findings = await plugin.run(Task(plugin="parameter_intelligence", target="api.example.com"), ctx)
        self.assertEqual(len(findings), 1)
        self.assertIn("parameter_map_sample", findings[0].evidence)

    async def test_response_diff_engine_detects_anomaly(self) -> None:
        plugin = ResponseDiffPlugin()
        ctx = {"config": {"modules": {"response_diff_engine": {"paths": ["/api/me"]}}}, "runtime": {"timeout_seconds": 5}}
        with patch(
            "hunterops.plugins.response_diff_engine.request_http_async",
            new=AsyncMock(
                side_effect=[
                    {"status": 200, "length": 120, "text": '{"id":1,"name":"a"}'},
                    {"status": 200, "length": 340, "text": '{"id":1,"name":"a","details":{"x":1}}'},
                ]
            ),
        ):
            findings = await plugin.run(Task(plugin="response_diff_engine", target="api.example.com"), ctx)
        self.assertGreaterEqual(len(findings), 1)

    async def test_idor_detection_engine_flags_behavior_change(self) -> None:
        plugin = IDOREnginePlugin()
        ctx = {
            "config": {
                "modules": {
                    "idor_detection_engine": {
                        "sessions_file": "data/sessions.yaml",
                        "evidence_dir": "data/evidence/engine",
                        "candidate_urls": ["https://{target}/api/users?id=1"],
                    }
                }
            },
            "runtime": {"timeout_seconds": 5},
        }
        with patch("hunterops.plugins.idor_detection_engine.load_sessions", return_value={"user": {"token": "x"}}), patch(
            "hunterops.plugins.idor_detection_engine.auth_header", return_value={"Authorization": "Bearer x"}
        ), patch(
            "hunterops.plugins.idor_detection_engine.request_http_async",
            new=AsyncMock(
                side_effect=[
                    {"status": 200, "length": 100, "text": '{"id":1,"email":"a@x.com"}'},
                    {"status": 200, "length": 220, "text": '{"id":2,"email":"b@x.com","phone":"123"}'},
                    {"status": 200, "length": 100, "text": '{"id":1,"email":"a@x.com"}'},
                ]
            ),
        ), patch(
            "hunterops.plugins.idor_detection_engine.save_http_evidence",
            return_value={"request_file": "r.json", "response_file": "s.json", "timestamp_utc": "2026-03-05T00:00:00Z"},
        ):
            findings = await plugin.run(Task(plugin="idor_detection_engine", target="api.example.com"), ctx)
        self.assertGreaterEqual(len(findings), 1)


if __name__ == "__main__":
    unittest.main()
