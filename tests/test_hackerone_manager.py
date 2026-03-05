from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hunterops.hackerone_manager import HackerOneManager


class HackerOneManagerTests(unittest.TestCase):
    def test_filter_targets_by_cached_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "scope.json"
            cache.write_text('{"hosts":["api.example.com","app.example.com"]}', encoding="utf-8")
            mgr = HackerOneManager(
                cfg={
                    "enabled": True,
                    "strict_scope_enforcement": True,
                    "scope_cache_file": str(cache),
                }
            )
            targets = ["api.example.com", "out.example.com"]
            self.assertEqual(mgr.filter_targets(targets), ["api.example.com"])

    def test_suppress_probable_duplicates(self) -> None:
        mgr = HackerOneManager(cfg={"enabled": False})
        rows = [
            {
                "title": "low confidence",
                "evidence": {"endpoint": "/api/v1/users"},
                "metadata": {"confidence": 70},
            },
            {
                "title": "high confidence",
                "evidence": {"endpoint": "/api/v1/users"},
                "metadata": {"confidence": 95},
            },
        ]
        out = mgr.suppress_probable_duplicates(rows, {"/api/v1/users"})
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["title"], "high confidence")
        self.assertEqual(out[0]["metadata"].get("duplicate_risk"), "medium")


if __name__ == "__main__":
    unittest.main()
