from __future__ import annotations

import unittest

from hunterops.findings import calculate_impact
from hunterops.intelligence import serialize_findings
from hunterops.types import Finding


class FindingsImpactTests(unittest.TestCase):
    def test_calculate_impact_escalates_financial_admin_context(self) -> None:
        finding = Finding(
            plugin="business_logic_sniper",
            target="api.example.com",
            category="financial_tampering_indicator",
            severity="medium",
            title="Tampering at admin billing endpoint",
            evidence={"endpoint": "/admin/billing/checkout", "tested_parameter": "price"},
            metadata={"impact": 60},
        )
        profile = calculate_impact(finding)
        self.assertTrue(profile["financial_context"])
        self.assertTrue(profile["administrative_context"])
        self.assertGreaterEqual(float(profile["impact_score"]), 80.0)
        self.assertEqual(str(profile["adjusted_severity"]), "critical")

    def test_serialize_findings_uses_adjusted_severity(self) -> None:
        finding = Finding(
            plugin="business_logic_sniper",
            target="api.example.com",
            category="coupon_abuse_indicator",
            severity="high",
            title="Coupon stacking on payment endpoint",
            evidence={"endpoint": "/api/payment/apply", "parameter": "coupon"},
            metadata={"impact": 70, "confidence": 80, "novelty": 70},
        )
        rows = serialize_findings([finding], feedback=None)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "critical")
        profile = rows[0]["metadata"]["impact_profile"]
        self.assertTrue(bool(profile["financial_context"]))


if __name__ == "__main__":
    unittest.main()

