from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from hunterops.plugins.asset_discovery_engine import PluginImpl as AssetDiscoveryPlugin
from hunterops.plugins.attack_graph_builder import PluginImpl as AttackGraphPlugin
from hunterops.plugins.recon_engine import PluginImpl as ReconEnginePlugin
from hunterops.plugins.security_report_builder import PluginImpl as SecurityReportPlugin
from hunterops.plugins.vulnerability_correlation_engine import PluginImpl as VulnCorrelationPlugin
from hunterops.types import Task


class PipelineExpansionTests(unittest.IsolatedAsyncioTestCase):
    async def test_asset_discovery_engine_finds_live_host(self) -> None:
        plugin = AssetDiscoveryPlugin()
        ctx = {"config": {"modules": {"asset_discovery_engine": {"subdomain_prefixes": ["api"], "allowed_scope_suffixes": ["example.com"]}}}, "runtime": {"timeout_seconds": 5}}
        with patch("hunterops.plugins.asset_discovery_engine.resolve_host", new=AsyncMock(return_value="1.1.1.1")), patch(
            "hunterops.plugins.asset_discovery_engine.request_http_async",
            new=AsyncMock(return_value={"status": 200, "length": 10, "headers": {"Server": "nginx"}, "text": "ok"}),
        ):
            findings = await plugin.run(Task(plugin="asset_discovery_engine", target="example.com"), ctx)
        self.assertEqual(len(findings), 1)
        self.assertIn("live_hosts", findings[0].evidence)

    async def test_recon_engine_maps_links_and_forms(self) -> None:
        plugin = ReconEnginePlugin()
        ctx = {"config": {"modules": {"recon_engine": {"seed_paths": ["/"], "max_pages": 3}}}, "runtime": {"timeout_seconds": 5}}

        async def fake_http(method: str, url: str, headers: dict | None = None, body: object | None = None, timeout: int = 5) -> dict:
            if url.endswith("/"):
                return {
                    "status": 200,
                    "length": 180,
                    "headers": {"Content-Type": "text/html"},
                    "text": '<a href="/api/users?id=1">u</a><form action="/login" method="post"><input name="email"/></form><script src="/main.js"></script>',
                }
            if url.endswith("main.js"):
                return {"status": 200, "length": 80, "headers": {"Content-Type": "application/javascript"}, "text": "const p='/api/orders?order_id=1';"}
            return {"status": 200, "length": 20, "headers": {"Content-Type": "text/html"}, "text": "ok"}

        with patch("hunterops.plugins.recon_engine.request_http_async", new=AsyncMock(side_effect=fake_http)):
            findings = await plugin.run(Task(plugin="recon_engine", target="api.example.com"), ctx)
        self.assertEqual(len(findings), 1)
        self.assertIn("forms", findings[0].evidence)

    async def test_attack_graph_and_correlation_from_findings(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "findings.json"
            src.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "plugin": "parameter_intelligence",
                                "target": "api.example.com",
                                "category": "parameter_intelligence",
                                "risk_score": 40,
                                "evidence": {"parameter": "user_id", "url": "https://api.example.com/api/users?id=1"},
                                "metadata": {"discovery_source": "parameter_intelligence"},
                            },
                            {
                                "plugin": "idor_intelligence",
                                "target": "api.example.com",
                                "category": "idor_inconsistency_indicator",
                                "risk_score": 82,
                                "evidence": {"base_url": "https://api.example.com/api/users?id=1"},
                                "metadata": {"discovery_source": "idor_intelligence"},
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            ag = AttackGraphPlugin()
            vg = VulnCorrelationPlugin()
            ctx = {"config": {"modules": {"attack_graph_builder": {"findings_source": str(src)}, "vulnerability_correlation_engine": {"findings_source": str(src)}}}}
            ag_f = await ag.run(Task(plugin="attack_graph_builder", target="api.example.com"), ctx)
            vg_f = await vg.run(Task(plugin="vulnerability_correlation_engine", target="api.example.com"), ctx)
            self.assertEqual(len(ag_f), 1)
            self.assertGreaterEqual(len(vg_f), 1)

    async def test_security_report_builder_outputs_package(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "findings.json"
            out = Path(td) / "reports"
            src.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "plugin": "vulnerability_correlation_engine",
                                "target": "api.example.com",
                                "category": "vulnerability_correlation",
                                "severity": "high",
                                "risk_score": 80,
                                "title": "Correlated signal",
                                "evidence": {"base_url": "https://api.example.com/api/users?id=1"},
                                "metadata": {"discovery_source": "vulnerability_correlation_engine", "confidence": 85},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            plugin = SecurityReportPlugin()
            ctx = {"config": {"modules": {"security_report_builder": {"findings_source": str(src), "out_dir": str(out)}}}}
            findings = await plugin.run(Task(plugin="security_report_builder", target="api.example.com"), ctx)
            self.assertEqual(len(findings), 1)
            self.assertTrue(Path(findings[0].evidence["json_report"]).exists())


if __name__ == "__main__":
    unittest.main()
