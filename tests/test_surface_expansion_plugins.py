from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch

from hunterops.plugins.crawler_intelligent import PluginImpl as CrawlerIntelligentPlugin
from hunterops.plugins.javascript_deep_analysis import PluginImpl as JSDeepPlugin
from hunterops.plugins.surface_expansion import PluginImpl as SurfaceExpansionPlugin
from hunterops.types import Task


class SurfaceExpansionPluginTests(unittest.IsolatedAsyncioTestCase):
    async def test_crawler_intelligent_collects_links_forms_and_params(self) -> None:
        plugin = CrawlerIntelligentPlugin()
        ctx = {"config": {"modules": {"crawler_intelligent": {"max_pages": 10, "max_depth": 1}}}, "runtime": {"timeout_seconds": 5}}

        async def fake_http(method: str, url: str, headers: dict | None = None, body: object | None = None, timeout: int = 5) -> dict:
            if url.endswith("/"):
                return {
                    "status": 200,
                    "length": 220,
                    "headers": {"Content-Type": "text/html"},
                    "text": '<a href="/users?id=1">u</a><form action="/api/search" method="post"><input name="q"/></form>',
                }
            return {"status": 200, "length": 20, "headers": {"Content-Type": "text/html"}, "text": "ok"}

        with patch("hunterops.plugins.crawler_intelligent.request_http_async", new=AsyncMock(side_effect=fake_http)):
            findings = await plugin.run(Task(plugin="crawler_intelligent", target="api.example.com"), ctx)
        self.assertEqual(len(findings), 1)
        self.assertIn("endpoints_sample", findings[0].evidence)
        self.assertIn("params_sample", findings[0].evidence)

    async def test_javascript_deep_analysis_extracts_fetch_and_xhr(self) -> None:
        plugin = JSDeepPlugin()
        ctx = {
            "config": {"modules": {"javascript_deep_analysis": {"seed_paths": ["/"], "max_scripts": 5}}},
            "runtime": {"timeout_seconds": 5},
        }

        async def fake_http(method: str, url: str, headers: dict | None = None, body: object | None = None, timeout: int = 5) -> dict:
            if url.endswith("/"):
                return {"status": 200, "length": 100, "headers": {"Content-Type": "text/html"}, "text": '<script src="/app.js"></script>'}
            return {
                "status": 200,
                "length": 180,
                "headers": {"Content-Type": "application/javascript"},
                "text": "fetch('/api/users?id=1'); const x=new XMLHttpRequest();x.open('GET','/api/orders');",
            }

        with patch("hunterops.plugins.javascript_deep_analysis.request_http_async", new=AsyncMock(side_effect=fake_http)):
            findings = await plugin.run(Task(plugin="javascript_deep_analysis", target="api.example.com"), ctx)
        self.assertEqual(len(findings), 1)
        self.assertIn("endpoints_sample", findings[0].evidence)

    async def test_surface_expansion_validates_probable_routes(self) -> None:
        plugin = SurfaceExpansionPlugin()
        ctx = {"config": {"modules": {"surface_expansion": {"seed_endpoints": ["/api/users"]}}}, "runtime": {"timeout_seconds": 5}}

        async def fake_http(method: str, url: str, headers: dict | None = None, body: object | None = None, timeout: int = 5) -> dict:
            if "/api/users" in url:
                return {"status": 200, "length": 50, "headers": {}, "text": "[]"}
            if "/api/user" in url:
                return {"status": 403, "length": 30, "headers": {}, "text": "forbidden"}
            return {"status": 404, "length": 0, "headers": {}, "text": ""}

        with patch("hunterops.plugins.surface_expansion.request_http_async", new=AsyncMock(side_effect=fake_http)):
            findings = await plugin.run(Task(plugin="surface_expansion", target="api.example.com"), ctx)
        self.assertEqual(len(findings), 1)
        self.assertGreater(len(findings[0].evidence.get("validated_routes", [])), 0)


if __name__ == "__main__":
    unittest.main()
