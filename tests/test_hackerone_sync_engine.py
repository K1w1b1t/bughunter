from __future__ import annotations

import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

from hunterops.hackerone_sync_engine import HackerOneSyncEngine


class _FakeStorage:
    def __init__(self) -> None:
        self.enabled = True
        self.state: dict[str, dict[str, Any]] = {}
        self.attack_graph_rows: list[dict[str, Any]] = []

    def get_h1_sync_state(self, sync_key: str) -> dict[str, Any]:
        return self.state.get(sync_key, {})

    def upsert_h1_sync_state(self, *, sync_key: str, payload: dict[str, Any]) -> None:
        self.state[sync_key] = {
            "sync_key": sync_key,
            "last_synced_at": datetime.now(UTC),
            "payload": payload,
        }

    def upsert_attack_graph_nodes(
        self,
        *,
        run_id: str,
        target: str,
        nodes: list[dict[str, Any]],
        discovery_source: str,
        confidence_score: float,
    ) -> None:
        self.attack_graph_rows.append(
            {
                "run_id": run_id,
                "target": target,
                "nodes": nodes,
                "discovery_source": discovery_source,
                "confidence_score": confidence_score,
            }
        )


class HackerOneSyncEngineTests(unittest.TestCase):
    def test_sync_filters_scope_and_updates_targets_and_attack_graph(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            targets_file = Path(tmp) / "targets.txt"
            targets_file.write_text("api.old.com\napi.example.com\n", encoding="utf-8")
            storage = _FakeStorage()
            cfg = {
                "enabled": True,
                "targets_file": str(targets_file),
                "exclude_low_signal": True,
                "min_signal": 80,
                "sync_interval_seconds": 0,
            }
            with patch.dict(os.environ, {"H1_API_IDENTIFIER": "id", "H1_API_TOKEN": "token"}, clear=False):
                engine = HackerOneSyncEngine(cfg=cfg, storage=storage)
                engine._fetch_public_programs = lambda timeout: [  # type: ignore[method-assign]
                    {
                        "handle": "good",
                        "offers_bounties": True,
                        "response_efficiency_percentage": 92,
                    },
                    {
                        "handle": "low",
                        "offers_bounties": True,
                        "response_efficiency_percentage": 40,
                    },
                    {
                        "handle": "nobounty",
                        "offers_bounties": False,
                        "response_efficiency_percentage": 99,
                    },
                ]

                def _fake_scopes(*, handle: str, timeout: int) -> list[dict[str, Any]]:
                    if handle == "good":
                        return [
                            {"asset_identifier": "https://api.example.com/v1/users", "asset_type": "URL", "eligible_for_bounty": True},
                            {"asset_identifier": "*.corp.example.com", "asset_type": "DOMAIN", "eligible_for_bounty": True},
                            {"asset_identifier": "https://ignore.example.com", "asset_type": "URL", "eligible_for_bounty": False},
                            {"asset_identifier": "10.0.0.1", "asset_type": "IP_ADDRESS", "eligible_for_bounty": True},
                        ]
                    return [{"asset_identifier": "low.example.com", "asset_type": "DOMAIN", "eligible_for_bounty": True}]

                engine._fetch_structured_scopes = _fake_scopes  # type: ignore[method-assign]
                result = engine.sync(run_id="run-1")

            self.assertTrue(result["enabled"])
            self.assertTrue(result["api_called"])
            self.assertEqual(result["programs_excluded_low_signal"], 1)
            self.assertEqual(set(result["domains"]), {"api.example.com", "corp.example.com"})
            file_lines = [x.strip() for x in targets_file.read_text(encoding="utf-8").splitlines() if x.strip()]
            self.assertEqual(file_lines, ["api.example.com", "api.old.com", "corp.example.com"])
            self.assertEqual(len(storage.attack_graph_rows), 2)
            self.assertIn("h1_public_bounty_scope_sync", storage.state)

    def test_sync_uses_recent_state_to_skip_api(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            targets_file = Path(tmp) / "targets.txt"
            storage = _FakeStorage()
            storage.upsert_h1_sync_state(
                sync_key="h1_public_bounty_scope_sync",
                payload={
                    "programs_total": 10,
                    "programs_selected": 8,
                    "programs_excluded_low_signal": 2,
                    "domains": ["cached.example.com"],
                    "domain_programs": {"cached.example.com": ["good"]},
                },
            )
            cfg = {
                "enabled": True,
                "targets_file": str(targets_file),
                "sync_interval_seconds": 3600,
            }
            with patch.dict(os.environ, {"H1_API_IDENTIFIER": "id", "H1_API_TOKEN": "token"}, clear=False):
                engine = HackerOneSyncEngine(cfg=cfg, storage=storage)

                def _should_not_fetch(timeout: int) -> list[dict[str, Any]]:
                    raise AssertionError("network call should be skipped due fresh sync state")

                engine._fetch_public_programs = _should_not_fetch  # type: ignore[method-assign]
                result = engine.sync(run_id="run-cache")

            self.assertTrue(result["enabled"])
            self.assertFalse(result["api_called"])
            self.assertTrue(result["used_cache"])
            self.assertEqual(result["domains"], ["cached.example.com"])
            self.assertEqual(
                [x.strip() for x in targets_file.read_text(encoding="utf-8").splitlines() if x.strip()],
                ["cached.example.com"],
            )
            self.assertEqual(len(storage.attack_graph_rows), 1)


if __name__ == "__main__":
    unittest.main()
