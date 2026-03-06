from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from unittest.mock import patch

from hunterops.hackerone_sync_engine import HackerOneSyncEngine
from hunterops.intelligence import serialize_findings
from hunterops.plugins.business_logic_sniper import PluginImpl as BusinessLogicSniper
from hunterops.plugins.poc_generator import PluginImpl as PocGenerator
from hunterops.types import Task

try:
    from fastapi.testclient import TestClient
    from tests.mock_api.app import app

    _FASTAPI_OK = True
except Exception:
    _FASTAPI_OK = False


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


def _resp(status: int, text: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "ok": status in {200, 201},
        "status": status,
        "headers": headers or {"Content-Type": "application/json"},
        "text": text,
        "length": len(text.encode("utf-8")),
    }


@unittest.skipUnless(_FASTAPI_OK, "fastapi/testclient not installed")
class H1ToPocFlowIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_h1_scope_sync_to_poc_generation_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            targets_file = tmp_root / "targets.txt"
            findings_source = tmp_root / "findings.json"
            out_dir = tmp_root / "poc_auto"
            storage = _FakeStorage()

            with patch.dict(os.environ, {"H1_API_IDENTIFIER": "id", "H1_API_TOKEN": "token"}, clear=False):
                sync_engine = HackerOneSyncEngine(
                    cfg={
                        "enabled": True,
                        "targets_file": str(targets_file),
                        "sync_interval_seconds": 0,
                    },
                    storage=storage,
                )
                sync_engine._fetch_public_programs = lambda timeout: [  # type: ignore[method-assign]
                    {"handle": "mock", "offers_bounties": True, "response_efficiency_percentage": 99}
                ]
                sync_engine._fetch_structured_scopes = (  # type: ignore[method-assign]
                    lambda handle, timeout: [  # noqa: ARG005
                        {"asset_identifier": "mock.local", "asset_type": "DOMAIN", "eligible_for_bounty": True}
                    ]
                )
                sync = sync_engine.sync(run_id="run-int")
            self.assertTrue(sync["enabled"])
            self.assertIn("mock.local", sync["domains"])

            test_client = TestClient(app)
            sniper = BusinessLogicSniper()

            async def fake_request_http_async(method: str, url: str, headers: dict[str, str] | None = None, **kwargs: object) -> dict[str, Any]:  # noqa: ANN401
                parsed = urlparse(url)
                path = parsed.path or "/"
                query = parsed.query
                if path == "/api/checkout":
                    return _resp(200, '{"status":"success","transaction_id":"txn_88"}')
                req_path = path if not query else f"{path}?{query}"
                response = test_client.get(req_path, headers=headers or {})
                return _resp(response.status_code, response.text, dict(response.headers))

            context = {
                "config": {
                    "storage": {"postgres": {"enabled": False}},
                    "modules": {
                        "business_logic_sniper": {
                            "base_scheme": "http",
                            "seed_paths": [
                                "/api/cart?price=100&quantity=1",
                                "/api/checkout?amount=100&currency=USD",
                                "/api/coupon/apply?coupon=WELCOME10&total=100",
                            ],
                            "sessions_file": str(tmp_root / "sessions.yaml"),
                        },
                        "poc_generator": {
                            "findings_source": str(findings_source),
                            "out_dir": str(out_dir),
                        },
                    },
                },
                "runtime": {"timeout_seconds": 5},
                "logger": type("L", (), {"exception": lambda self, msg: None})(),
            }
            with patch("hunterops.plugins.business_logic_sniper.request_http_async", side_effect=fake_request_http_async), patch(
                "hunterops.plugins.business_logic_sniper.load_sessions",
                return_value={"user": {"token": "A"}, "user_b": {"token": "B"}},
            ), patch(
                "hunterops.plugins.business_logic_sniper.auth_header",
                side_effect=[{"Authorization": "Bearer A"}, {"Authorization": "Bearer B"}],
            ):
                findings = await sniper.run(Task(plugin="business_logic_sniper", target="mock.local", payload={"run_id": "run-int"}), context)

            self.assertGreaterEqual(len(findings), 1)
            rows = serialize_findings(findings)
            findings_source.write_text(json.dumps(rows, ensure_ascii=True, indent=2), encoding="utf-8")

            poc = PocGenerator()
            poc_findings = await poc.run(Task(plugin="poc_generator", target="mock.local", payload={"run_id": "run-int"}), context)
            self.assertEqual(len(poc_findings), 1)
            generated = list(out_dir.glob("poc_*.json"))
            self.assertGreaterEqual(len(generated), 1)


if __name__ == "__main__":
    unittest.main()
