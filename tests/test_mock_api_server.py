from __future__ import annotations

import unittest

try:
    from fastapi.testclient import TestClient
    from tests.mock_api.app import app

    _FASTAPI_OK = True
except Exception:
    _FASTAPI_OK = False


@unittest.skipUnless(_FASTAPI_OK, "fastapi/testclient not installed")
class MockApiServerTests(unittest.TestCase):
    def test_mock_api_exposes_idor_negative_price_and_race_paths(self) -> None:
        client = TestClient(app)
        idor = client.get("/api/v1/profile?user_id=2")
        self.assertEqual(idor.status_code, 200)
        self.assertIn("victim@example.com", idor.text)

        negative = client.get("/api/cart?price=-1&quantity=1")
        self.assertEqual(negative.status_code, 200)
        self.assertIn('"status":"success"', negative.text.replace(" ", ""))

        race = client.get("/api/wallet/withdraw?amount=1")
        self.assertEqual(race.status_code, 200)
        self.assertIn("transaction_id", race.text)


if __name__ == "__main__":
    unittest.main()

