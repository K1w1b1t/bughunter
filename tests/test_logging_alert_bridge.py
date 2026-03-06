from __future__ import annotations

import logging
import tempfile
import unittest
from pathlib import Path

from hunterops.logging_utils import attach_alert_router, setup_logging


class _FakeRouter:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def enqueue_critical_log(self, *, message: str, run_id: str = "runtime") -> None:
        self.calls.append((message, run_id))


class LoggingAlertBridgeTests(unittest.TestCase):
    def test_critical_logs_are_forwarded_to_router(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_file = Path(tmp) / "app.jsonl"
            logger = setup_logging(log_file, verbose=False)
            router = _FakeRouter()
            attach_alert_router(logger, router)
            logger.critical("critical failure")
            logger.error("non-critical failure")
            self.assertEqual(len(router.calls), 1)
            self.assertIn("critical failure", router.calls[0][0])
            self.assertEqual(router.calls[0][1], "runtime")
            for handler in list(logger.handlers):
                try:
                    handler.flush()
                    handler.close()
                except Exception:
                    pass
                logger.removeHandler(handler)


if __name__ == "__main__":
    unittest.main()
