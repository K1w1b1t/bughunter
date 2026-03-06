from __future__ import annotations

import unittest
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

from hunterops.plugins.business_logic_sniper import PluginImpl
from hunterops.types import Task


def _fake_response(status: int, text: str) -> dict[str, object]:
    return {
        "ok": status in {200, 201},
        "status": status,
        "headers": {"Content-Type": "application/json"},
        "text": text,
        "length": len(text.encode("utf-8")),
    }


class BusinessLogicSniperTests(unittest.IsolatedAsyncioTestCase):
    async def test_detects_financial_logic_abuse_vectors(self) -> None:
        plugin = PluginImpl()
        context = {
            "config": {
                "storage": {"postgres": {"enabled": False}},
                "modules": {
                    "business_logic_sniper": {
                        "base_scheme": "http",
                        "sessions_file": "data/sessions.yaml",
                        "auth_context_a": "user",
                        "auth_context_b": "user_b",
                        "seed_paths": [
                            "/api/cart?price=100&quantity=1",
                            "/api/checkout?amount=100&currency=USD",
                            "/api/coupon/apply?coupon=WELCOME10&total=100",
                        ],
                    }
                },
            },
            "runtime": {"timeout_seconds": 5},
            "logger": type("L", (), {"exception": lambda self, msg: None})(),
        }

        async def fake_request(method: str, url: str, headers: dict[str, str] | None = None, **kwargs: object) -> dict[str, object]:  # noqa: ANN401
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            headers = headers or {}
            path = parsed.path
            if path == "/api/success":
                return _fake_response(200, '{"status":"success","message":"completed"}')
            if path == "/api/cart":
                price = (params.get("price") or ["100"])[0]
                if price in {"-1", "-9999", "0", "0.01"}:
                    return _fake_response(200, '{"status":"success","total":0,"transaction_id":"txn_1234"}')
                return _fake_response(200, '{"status":"ok","total":100}')
            if path == "/api/checkout":
                amount = (params.get("amount") or ["100"])[0]
                currency = (params.get("currency") or ["USD"])[0]
                if amount in {"-1", "-9999"} or currency == "INR":
                    return _fake_response(200, '{"status":"success","transaction_id":"txn_999"}')
                return _fake_response(200, '{"status":"ok"}')
            if path == "/api/coupon/apply":
                coupon_values = params.get("coupon", [])
                if len(coupon_values) >= 2:
                    return _fake_response(200, '{"status":"success","discount":30}')
                if headers.get("Authorization") in {"Bearer user-a", "Bearer user-b"}:
                    return _fake_response(200, '{"status":"success","discount":10}')
                return _fake_response(200, '{"status":"ok"}')
            return _fake_response(404, '{"error":"not-found"}')

        with patch("hunterops.plugins.business_logic_sniper.request_http_async", side_effect=fake_request), patch(
            "hunterops.plugins.business_logic_sniper.load_sessions",
            return_value={"user": {"token": "user-a"}, "user_b": {"token": "user-b"}},
        ), patch(
            "hunterops.plugins.business_logic_sniper.auth_header",
            side_effect=[{"Authorization": "Bearer user-a"}, {"Authorization": "Bearer user-b"}],
        ):
            findings = await plugin.run(Task(plugin="business_logic_sniper", target="mock.local", payload={"run_id": "r1"}), context)

        categories = {f.category for f in findings}
        self.assertIn("financial_tampering_indicator", categories)
        self.assertIn("coupon_abuse_indicator", categories)
        self.assertIn("coupon_cross_account_reuse", categories)
        self.assertIn("currency_manipulation_indicator", categories)
        self.assertIn("state_machine_violation_indicator", categories)
        self.assertTrue(any(f.severity == "critical" for f in findings))


if __name__ == "__main__":
    unittest.main()

