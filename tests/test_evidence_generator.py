from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hunterops.evidence_generator import generate_research_artifacts
from hunterops.types import Finding


class EvidenceGeneratorTests(unittest.TestCase):
    def test_generates_markdown_and_json_exports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            findings = [
                Finding(
                    plugin="differential_auth_prover",
                    target="api.example.com",
                    category="critical_idor_vulnerability",
                    severity="critical",
                    title="Potential IDOR via differential auth replay",
                    evidence={
                        "request_auth_a": {
                            "method": "GET",
                            "url": "https://api.example.com/api/v1/users?user_id=1001",
                            "headers": {"Authorization": "Bearer ownertoken_abcdef123456"},
                        },
                        "request_auth_b": {
                            "method": "GET",
                            "url": "https://api.example.com/api/v1/users?user_id=1001",
                            "headers": {"Authorization": "Bearer attacker_abcdef987654"},
                        },
                        "response_auth_a": {"status": 200, "length": 120},
                        "response_auth_b": {"status": 200, "length": 120},
                    },
                    metadata={"confidence_score": 91, "discovery_source": "differential_auth_prover"},
                )
            ]
            summary = generate_research_artifacts(findings=findings, out_root=Path(tmp), run_id="run_abc", min_confidence=85.0)
            self.assertEqual(summary["generated_reports"], 1)
            run_dir = Path(summary["run_dir"])
            self.assertTrue((run_dir / "findings.json").exists())
            md_files = list(run_dir.glob("autopoc_*.md"))
            self.assertEqual(len(md_files), 1)
            content = md_files[0].read_text(encoding="utf-8")
            self.assertIn("Side-by-Side Response Comparison", content)
            self.assertNotIn("ownertoken_abcdef123456", content)
            self.assertIn("owne...3456", content)

    def test_oob_markdown_contains_confirmation_phrase(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            findings = [
                Finding(
                    plugin="oob_engine",
                    target="api.example.com",
                    category="oob_interaction_detected",
                    severity="critical",
                    title="OOB interaction detected",
                    evidence={
                        "request_auth_a": {"method": "GET", "url": "https://api.example.com/api/v1/check", "headers": {}},
                        "request_auth_b": {"method": "GET", "url": "https://api.example.com/api/v1/check", "headers": {}},
                        "response_auth_a": {"status": 200, "length": 10},
                        "response_auth_b": {"status": 200, "length": 10},
                    },
                    metadata={"confidence_score": 95, "discovery_source": "oob_engine"},
                )
            ]
            summary = generate_research_artifacts(findings=findings, out_root=Path(tmp), run_id="run_oob", min_confidence=85.0)
            run_dir = Path(summary["run_dir"])
            md_files = list(run_dir.glob("autopoc_*.md"))
            self.assertEqual(len(md_files), 1)
            content = md_files[0].read_text(encoding="utf-8")
            self.assertIn("O servidor do alvo tentou conectar-se ao nosso listener externo, confirmando Blind SSRF/RCE", content)


if __name__ == "__main__":
    unittest.main()
