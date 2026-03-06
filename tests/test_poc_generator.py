from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from hunterops.plugins.poc_generator import PluginImpl
from hunterops.types import Task


class PocGeneratorTests(unittest.IsolatedAsyncioTestCase):
    async def test_generated_poc_includes_business_impact_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            source = tmp_root / "findings.json"
            out_dir = tmp_root / "pocs"
            source.write_text(
                json.dumps(
                    [
                        {
                            "plugin": "business_logic_sniper",
                            "target": "api.example.com",
                            "category": "financial_tampering_indicator",
                            "severity": "high",
                            "title": "Price tampering",
                            "evidence": {
                                "url": "https://api.example.com/api/checkout?price=-1",
                                "tested_parameter": "price",
                                "diff": "HTTP 200 accepted negative price",
                            },
                            "metadata": {"impact": 88, "confidence": 92},
                        }
                    ],
                    ensure_ascii=True,
                    indent=2,
                ),
                encoding="utf-8",
            )

            plugin = PluginImpl()
            findings = await plugin.run(
                Task(plugin="poc_generator", target="api.example.com", payload={"run_id": "run-1"}),
                {
                    "config": {
                        "modules": {
                            "poc_generator": {
                                "findings_source": str(source),
                                "out_dir": str(out_dir),
                            }
                        }
                    }
                },
            )
            self.assertEqual(len(findings), 1)

            generated = sorted(out_dir.glob("poc_*.json"))
            self.assertEqual(len(generated), 1)
            doc = json.loads(generated[0].read_text(encoding="utf-8"))
            self.assertIn("business_impact", doc)
            self.assertIn("business_impact_section", doc)
            self.assertIn("## Business Impact", str(doc["business_impact_section"]))
            self.assertGreater(float(doc.get("impact_score", 0.0)), 0.0)


if __name__ == "__main__":
    unittest.main()
