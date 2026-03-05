from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

import hunterops.oob_engine as mod
from hunterops.types import Finding


async def _stub_request_http_async(method: str, url: str, headers: dict | None = None, body: object = None, timeout: int = 20) -> dict:
    return {"ok": True, "status": 200, "headers": {"Content-Type": "text/plain"}, "text": "ok", "length": 2}


class OOBEngineTests(unittest.TestCase):
    def test_inject_from_findings_registers_correlations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = {
                "enabled": True,
                "provider": "custom",
                "callback_domain": "oob.local",
                "poll_url": "https://listener.local/events",
                "state_file": str(Path(tmp) / "oob_state.json"),
                "events_file": str(Path(tmp) / "oob_events.jsonl"),
                "max_injections_per_target": 5,
            }
            engine = mod.OOBEngine(cfg=cfg, runtime={"timeout_seconds": 5}, logger=None)
            prev = mod.request_http_async
            mod.request_http_async = _stub_request_http_async  # type: ignore[assignment]
            try:
                findings = [
                    Finding(
                        plugin="deep_js_intelligence",
                        target="api.example.com",
                        category="js_discovery",
                        severity="info",
                        title="x",
                        evidence={"endpoints": ["/api/status"]},
                        metadata={},
                    ),
                    Finding(
                        plugin="parameter_intelligence",
                        target="api.example.com",
                        category="parameter_intelligence",
                        severity="info",
                        title="y",
                        evidence={"parameter_map_sample": [{"endpoint": "/api/redirect", "parameter": "redirect_url"}]},
                        metadata={},
                    ),
                ]
                injected = asyncio.run(engine.inject_from_findings(target="api.example.com", run_id="run1", findings=findings))
            finally:
                mod.request_http_async = prev  # type: ignore[assignment]
            self.assertGreaterEqual(injected, 1)
            self.assertTrue(engine._registry)  # noqa: SLF001

    def test_poll_and_correlate_generates_critical_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = {
                "enabled": True,
                "provider": "custom",
                "callback_domain": "oob.local",
                "poll_url": "https://listener.local/events",
                "state_file": str(Path(tmp) / "oob_state.json"),
                "events_file": str(Path(tmp) / "oob_events.jsonl"),
            }
            engine = mod.OOBEngine(cfg=cfg, runtime={"timeout_seconds": 5}, logger=None)
            engine._registry["abc123"] = {  # noqa: SLF001
                "run_id": "run1",
                "target": "api.example.com",
                "endpoint": "/api/admin/export",
            }
            engine._fetch_events = lambda: [  # type: ignore[method-assign]
                {"id": "evt-1", "host": "abc123.oob.local", "timestamp": "2026-03-05T10:00:00Z", "request_headers": {"x": "y"}}
            ]
            findings = asyncio.run(engine.poll_and_correlate())
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "critical")
            self.assertEqual(findings[0].category, "oob_interaction_detected")


if __name__ == "__main__":
    unittest.main()
