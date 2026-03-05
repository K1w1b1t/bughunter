from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hunterops.plugins.cve_intel import PluginImpl as CVEIntelPlugin
from hunterops.plugins.cve_matcher import PluginImpl as CVEMatcherPlugin
from hunterops.types import Task


class CVEPluginTests(unittest.IsolatedAsyncioTestCase):
    async def test_cve_intel_loads_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            catalog = Path(td) / "catalog.json"
            catalog.write_text(
                json.dumps(
                    {
                        "cves": [
                            {"cve": "CVE-2025-0001", "cvss": 9.8, "epss": 0.8, "kev": True},
                            {"cve": "CVE-2025-0002", "cvss": 7.5, "epss": 0.1, "kev": False},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            plugin = CVEIntelPlugin()
            ctx = {"config": {"modules": {"cve_intel": {"catalog_file": str(catalog)}}}, "runtime": {"timeout_seconds": 5}}
            findings = await plugin.run(Task(plugin="cve_intel", target="api.example.com"), ctx)
            self.assertEqual(len(findings), 1)
            self.assertIn("top_candidates", findings[0].evidence)

    async def test_cve_matcher_matches_by_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            catalog = Path(td) / "catalog.json"
            catalog.write_text(
                json.dumps(
                    {
                        "cves": [
                            {
                                "cve": "CVE-2024-1111",
                                "vendor": "apache",
                                "product": "struts",
                                "description": "Apache Struts vulnerable endpoint",
                                "cpes": ["cpe:2.3:a:apache:struts:2.5.30:*:*:*:*:*:*:*"],
                                "versions": ["2.5.30"],
                                "cvss": 9.1,
                                "epss": 0.62,
                                "kev": False,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            plugin = CVEMatcherPlugin()
            ctx = {
                "config": {"modules": {"cve_matcher": {"catalog_file": str(catalog), "probe_paths": ["/"], "min_token_matches": 2, "top_n": 5}}},
                "runtime": {"timeout_seconds": 5},
            }
            with patch(
                "hunterops.plugins.cve_matcher.request_http_async",
                return_value={
                    "status": 200,
                    "headers": {"Server": "Apache/2.4.58"},
                    "text": "<html>running struts 2.5.30</html>",
                    "length": 33,
                },
            ):
                findings = await plugin.run(Task(plugin="cve_matcher", target="api.example.com"), ctx)
            self.assertGreaterEqual(len(findings), 1)
            self.assertIn("CVE-2024-1111", findings[0].title)


if __name__ == "__main__":
    unittest.main()
