from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from hunterops.plugins.deep_js_analyzer import PluginImpl as DeepJSAnalyzer
from hunterops.plugins.hidden_route_detector import PluginImpl as HiddenRouteDetector
from hunterops.plugins.idor_intelligence import PluginImpl as IDORIntelligence
from hunterops.plugins.intelligent_crawler import PluginImpl as IntelligentCrawler
from hunterops.plugins.report_builder import PluginImpl as ReportBuilder
from hunterops.types import Task


class DeeperDiscoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_intelligent_crawler_discovers_internal_routes(self) -> None:
        plugin = IntelligentCrawler()
        ctx = {"config": {"modules": {"intelligent_crawler": {"max_pages": 5, "max_depth": 1, "crawl_delay_ms": 0}}}, "runtime": {"timeout_seconds": 5}}

        async def fake_http(method: str, url: str, headers: dict | None = None, body: object | None = None, timeout: int = 5) -> dict:
            if url.endswith("/"):
                return {
                    "status": 200,
                    "length": 120,
                    "headers": {"Content-Type": "text/html"},
                    "text": '<a href="/admin">a</a><script src="/main.js"></script>',
                }
            if url.endswith("main.js"):
                return {"status": 200, "length": 100, "headers": {"Content-Type": "application/javascript"}, "text": "fetch('/api/users?id=1')"}
            return {"status": 200, "length": 20, "headers": {"Content-Type": "text/html"}, "text": "ok"}

        with patch("hunterops.plugins.intelligent_crawler.request_http_async", new=AsyncMock(side_effect=fake_http)):
            findings = await plugin.run(Task(plugin="intelligent_crawler", target="api.example.com"), ctx)
        self.assertEqual(len(findings), 1)
        self.assertIn("request_response_sample", findings[0].evidence)

    async def test_deep_js_analyzer_extracts_graphql_and_tokens(self) -> None:
        plugin = DeepJSAnalyzer()
        ctx = {"config": {"modules": {"deep_js_analyzer": {"seed_paths": ["/"], "max_scripts": 5}}}, "runtime": {"timeout_seconds": 5}}

        async def fake_http(method: str, url: str, headers: dict | None = None, body: object | None = None, timeout: int = 5) -> dict:
            if url.endswith("/"):
                return {"status": 200, "length": 80, "headers": {"Content-Type": "text/html"}, "text": '<script src="/main.js"></script>'}
            return {
                "status": 200,
                "length": 250,
                "headers": {"Content-Type": "application/javascript"},
                "text": "fetch('/api/profile?id=1'); axios.get('/graphql'); const headers={'Authorization':'Bearer x'}; const body={'user_id':1};",
            }

        with patch("hunterops.plugins.deep_js_analyzer.request_http_async", new=AsyncMock(side_effect=fake_http)):
            findings = await plugin.run(Task(plugin="deep_js_analyzer", target="api.example.com"), ctx)
        self.assertEqual(len(findings), 1)
        self.assertIn("graphql_endpoints", findings[0].evidence)
        self.assertIn("token_names", findings[0].evidence)

    async def test_hidden_route_detector_uses_schema_and_redirect(self) -> None:
        plugin = HiddenRouteDetector()
        ctx = {"config": {"modules": {"hidden_route_detector": {"source_paths": ["/swagger.json"]}}}, "runtime": {"timeout_seconds": 5}}

        async def fake_http(method: str, url: str, headers: dict | None = None, body: object | None = None, timeout: int = 5) -> dict:
            if url.endswith("swagger.json"):
                return {"status": 200, "length": 120, "headers": {"Location": "/api/v1/users"}, "text": '{"paths":{"/internal/status":{}}}'}
            return {"status": 200, "length": 10, "headers": {}, "text": "ok"}

        with patch("hunterops.plugins.hidden_route_detector.request_http_async", new=AsyncMock(side_effect=fake_http)):
            findings = await plugin.run(Task(plugin="hidden_route_detector", target="api.example.com"), ctx)
        self.assertEqual(len(findings), 1)
        self.assertGreater(len(findings[0].evidence.get("validated_routes", [])), 0)

    async def test_idor_intelligence_detects_inconsistency(self) -> None:
        plugin = IDORIntelligence()
        ctx = {
            "config": {"modules": {"idor_intelligence": {"sessions_file": "data/sessions.yaml", "candidate_urls": ["https://{target}/api/users?id=1"]}}},
            "runtime": {"timeout_seconds": 5},
        }
        with patch("hunterops.plugins.idor_intelligence.load_sessions", return_value={"user": {"token": "x"}}), patch(
            "hunterops.plugins.idor_intelligence.auth_header", return_value={"Authorization": "Bearer x"}
        ), patch(
            "hunterops.plugins.idor_intelligence.request_http_async",
            new=AsyncMock(
                side_effect=[
                    {"status": 200, "length": 100, "text": '{"id":1,"email":"a@x.com"}', "headers": {}},
                    {"status": 200, "length": 240, "text": '{"id":2,"email":"b@x.com","phone":"1"}', "headers": {}},
                    {"status": 200, "length": 100, "text": '{"id":1,"email":"a@x.com"}', "headers": {}},
                ]
            ),
        ):
            findings = await plugin.run(Task(plugin="idor_intelligence", target="api.example.com"), ctx)
        self.assertGreaterEqual(len(findings), 1)

    async def test_report_builder_enriches_fields(self) -> None:
        plugin = ReportBuilder()
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "findings.json"
            out = Path(td) / "reports"
            src.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "plugin": "behavioral_diff_engine",
                                "target": "api.example.com",
                                "severity": "high",
                                "risk_score": 75,
                                "category": "behavioral_response_anomaly",
                                "title": "Behavior anomaly",
                                "evidence": {"base_url": "https://api.example.com/api/users?id=1", "tested_parameter": "user_id", "diff": {"status_changed": True}},
                                "metadata": {"confidence": 80, "discovery_source": "behavioral_diff"},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            ctx = {"config": {"modules": {"report_builder": {"findings_source": str(src), "out_dir": str(out), "min_risk": 50}}}}
            findings = await plugin.run(Task(plugin="report_builder", target="api.example.com"), ctx)
            self.assertEqual(len(findings), 1)
            report_path = Path(findings[0].evidence["json_report"])
            self.assertTrue(report_path.exists())
            report_doc = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertIn("endpoint_classification", report_doc["items"][0])


if __name__ == "__main__":
    unittest.main()
