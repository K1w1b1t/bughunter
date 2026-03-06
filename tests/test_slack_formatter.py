from __future__ import annotations

import unittest

from hunterops.slack_formatter import build_finding_blocks
from hunterops.types import Finding


class SlackFormatterTests(unittest.TestCase):
    def test_build_finding_blocks_includes_section_context_and_actions(self) -> None:
        finding = Finding(
            plugin="business_logic_sniper",
            target="api.example.com",
            category="financial_tampering_indicator",
            severity="critical",
            title="Financial flaw",
            evidence={},
            metadata={},
        )
        payload = build_finding_blocks(
            finding=finding,
            run_id="run-001",
            endpoint_text="GET /api/checkout",
            vuln_type="Price Tampering",
            confidence_score=92.5,
            impact_score=96.0,
            severity_label="CRITICAL",
            curl_command="curl -i https://api.example.com/api/checkout?price=-1",
            poc_snippet="# Poc",
            report_path="/opt/hunterops/data/reports/research/auto_poc/poc_001.md",
            report_url_base="https://reports.local",
        )
        blocks = payload.get("blocks", [])
        self.assertGreaterEqual(len(blocks), 3)
        self.assertEqual(blocks[0]["type"], "section")
        self.assertEqual(blocks[1]["type"], "context")
        self.assertEqual(blocks[2]["type"], "actions")


if __name__ == "__main__":
    unittest.main()

