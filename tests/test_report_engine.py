from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from hunterops.report_engine import ReportEngine
from hunterops.types import Finding


class _FakeStorage:
    def __init__(self) -> None:
        self.enabled = True

    def list_recent_entities(self, target: str, limit: int = 500) -> list[dict]:
        return [
            {
                "entity_type": "email",
                "entity_value": "owner@example.com",
                "source_plugin": "deep_js_intelligence",
                "source_endpoint": "/api/v2/admin/users",
                "confidence_score": 88,
            }
        ]


class ReportEngineTests(unittest.TestCase):
    def test_process_round_generates_ready_to_submit_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evidence_dir = Path(tmp) / "evidence"
            ready_dir = Path(tmp) / "ready"
            state_file = Path(tmp) / "processed" / "state.json"
            evidence_dir.mkdir(parents=True, exist_ok=True)
            evidence_file = evidence_dir / "evidence_abc123.md"
            evidence_file.write_text(
                "\n".join(
                    [
                        "# HunterOps ADE Evidence abc123",
                        "",
                        "## URL Afetada",
                        "`https://api.example.com/api/v2/admin/users?user_id=1001`",
                        "",
                        "## Parametro Vulneravel",
                        "`user_id`",
                        "",
                        "## Requisicao (CURL)",
                        "```bash",
                        "curl -i -sS -X GET 'https://api.example.com/api/v2/admin/users?user_id=1001'",
                        "```",
                        "",
                        "## Prova de Vazamento (Impacto)",
                        "Cross-account private profile data was returned to a non-owner session.",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            engine = ReportEngine(
                {
                    "enabled": True,
                    "evidence_dir": str(evidence_dir),
                    "ready_dir": str(ready_dir),
                    "state_file": str(state_file),
                    "auto_submit_h1_draft": False,
                },
                storage=_FakeStorage(),
            )

            round_findings = [
                Finding(
                    plugin="deep_js_intelligence",
                    target="api.example.com",
                    category="js_discovery",
                    severity="info",
                    title="js endpoints",
                    evidence={"endpoints": ["/api/v2/admin/users"]},
                    metadata={},
                ),
                Finding(
                    plugin="differential_auth_prover",
                    target="api.example.com",
                    category="critical_idor_vulnerability",
                    severity="high",
                    title="idor",
                    evidence={},
                    metadata={},
                ),
            ]
            generated = asyncio.run(engine.process_round(target="api.example.com", run_id="run_01", round_findings=round_findings))
            self.assertTrue(generated)
            self.assertEqual(generated[0].category, "submission_draft_ready")
            report_path = Path(str(generated[0].evidence.get("report_path", "")))
            self.assertTrue(report_path.exists())
            report_text = report_path.read_text(encoding="utf-8")
            self.assertIn("IDOR on /api/v2/admin/users leading to Sensitive Data Exposure", report_text)
            self.assertIn("## Steps to Reproduce", report_text)
            self.assertIn("X-H1-Client-Identifier", report_text)
            self.assertIn("Deep JS Intelligence", report_text)


if __name__ == "__main__":
    unittest.main()
