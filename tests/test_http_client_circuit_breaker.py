from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch

from hunterops.http_client import request_http_async, reset_circuit_breaker_state


class _429Response:
    def __init__(self) -> None:
        self.is_success = False
        self.status_code = 429
        self.headers = {"Content-Type": "text/plain"}
        self.text = "rate limited"
        self.content = b"rate limited"


class _Always429Client:
    def __init__(self) -> None:
        self.calls = 0

    async def request(self, method: str, url: str, headers: dict[str, str] | None = None, **kwargs: object) -> _429Response:  # noqa: ANN401
        self.calls += 1
        return _429Response()


class HttpClientCircuitBreakerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        reset_circuit_breaker_state()

    async def asyncTearDown(self) -> None:
        reset_circuit_breaker_state()

    async def test_target_circuit_breaker_opens_after_10_consecutive_429(self) -> None:
        client = _Always429Client()
        with patch(
            "hunterops.http_client.get_async_http_client",
            new=AsyncMock(return_value=client),
        ):
            for _ in range(10):
                res = await request_http_async("GET", "https://api.example.com/rate", headers={}, timeout=5)
                self.assertEqual(int(res["status"]), 429)
            blocked = await request_http_async("GET", "https://api.example.com/rate", headers={}, timeout=5)
            self.assertTrue(bool(blocked.get("circuit_open", False)))
            self.assertEqual(int(blocked["status"]), 429)
            self.assertGreater(float(blocked.get("cooldown_remaining_seconds", 0) or 0), 0.0)

            # Different host should continue flowing.
            _ = await request_http_async("GET", "https://other.example.com/rate", headers={}, timeout=5)

        self.assertEqual(client.calls, 11)


if __name__ == "__main__":
    unittest.main()

