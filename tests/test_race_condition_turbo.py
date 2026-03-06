from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from hunterops.plugins.race_condition_turbo import PluginImpl
from hunterops.types import Task


class RaceConditionTurboTests(unittest.IsolatedAsyncioTestCase):
    async def test_detects_toctou_window_from_parallel_responses(self) -> None:
        plugin = PluginImpl()
        context = {
            "config": {
                "storage": {"postgres": {"enabled": False}},
                "modules": {
                    "race_condition_turbo": {
                        "base_scheme": "http",
                        "sessions_file": "data/sessions.yaml",
                        "auth_context": "user",
                        "burst_size": 20,
                        "max_candidates": 4,
                        "variance_threshold_ms": 1.0,
                        "seed_paths": ["/api/wallet/withdraw?amount=1"],
                    }
                },
            },
            "runtime": {"timeout_seconds": 5},
            "logger": type("L", (), {"exception": lambda self, msg: None})(),
        }
        counter = {"i": 0}

        async def fake_request(method: str, url: str, headers: dict[str, str] | None = None, **kwargs: object) -> dict[str, object]:  # noqa: ANN401
            idx = counter["i"]
            counter["i"] += 1
            if idx % 3 == 0:
                await asyncio.sleep(0.04)
                status = 200
                text = '{"ok":true,"transaction_id":"tx_1"}'
            elif idx % 3 == 1:
                await asyncio.sleep(0.005)
                status = 409
                text = '{"ok":false,"error":"conflict"}'
            else:
                await asyncio.sleep(0.02)
                status = 200
                text = '{"ok":true,"transaction_id":"tx_2"}'
            return {
                "ok": status in {200, 201},
                "status": status,
                "headers": {"Content-Type": "application/json"},
                "text": text,
                "length": len(text.encode("utf-8")),
            }

        with patch("hunterops.plugins.race_condition_turbo.request_http_async", side_effect=fake_request), patch(
            "hunterops.plugins.race_condition_turbo.load_sessions",
            return_value={},
        ):
            findings = await plugin.run(Task(plugin="race_condition_turbo", target="mock.local", payload={"run_id": "r1", "burst_size": 20}), context)

        self.assertGreaterEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.category, "race_condition_turbo_indicator")
        self.assertIn(finding.severity, {"high", "critical"})
        self.assertTrue(bool(finding.evidence.get("toctou_window_detected", False)))


if __name__ == "__main__":
    unittest.main()

