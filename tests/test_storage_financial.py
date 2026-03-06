from __future__ import annotations

import unittest

from hunterops.storage import _is_financial_entity


class StorageFinancialEntityTests(unittest.TestCase):
    def test_detects_financial_entity_types_and_context(self) -> None:
        self.assertTrue(
            _is_financial_entity(
                entity_type="invoice_id",
                entity_value="INV-1001",
                source_endpoint="/api/invoices/1001",
                metadata={},
            )
        )
        self.assertTrue(
            _is_financial_entity(
                entity_type="object_reference",
                entity_value="wallet_7788",
                source_endpoint="/api/account",
                metadata={},
            )
        )
        self.assertTrue(
            _is_financial_entity(
                entity_type="numeric_id",
                entity_value="1002",
                source_endpoint="/api/orders/1002",
                metadata={"financial_flow": True},
            )
        )
        self.assertFalse(
            _is_financial_entity(
                entity_type="email",
                entity_value="user@example.com",
                source_endpoint="/api/profile",
                metadata={},
            )
        )


if __name__ == "__main__":
    unittest.main()

