from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

import hunterops.ade_brain as mod
from hunterops.types import Task


async def _stub_request(method: str, url: str, headers: dict | None = None, body: object = None, timeout: int = 20) -> dict:
    if "user_id=1" in url:
        return {"ok": False, "status": 403, "headers": {"Content-Type": "application/json"}, "text": '{"error":"forbidden"}', "length": 21}
    if "user_id=0" in url:
        text = '{"id":0,"name":"root","role":"admin","email":"root@example.com"}'
        return {"ok": True, "status": 200, "headers": {"Content-Type": "application/json"}, "text": text, "length": len(text)}
    if "user_id=-1" in url:
        text = '{"error":"invalid id"}'
        return {"ok": False, "status": 400, "headers": {"Content-Type": "application/json"}, "text": text, "length": len(text)}
    if "user_id=999999" in url:
        text = '{"id":999999,"name":"ghost"}'
        return {"ok": True, "status": 200, "headers": {"Content-Type": "application/json"}, "text": text, "length": len(text)}
    if "user_id=null" in url:
        text = '{"id":null,"name":"null-user"}'
        return {"ok": True, "status": 200, "headers": {"Content-Type": "application/json"}, "text": text, "length": len(text)}
    return {"ok": True, "status": 200, "headers": {"Content-Type": "application/json"}, "text": "{}", "length": 2}


class ADEBrainTests(unittest.TestCase):
    def test_generates_critical_tasks_boundary_findings_and_evidence_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            plugin = mod.PluginImpl()
            task = Task(
                plugin="ade_brain",
                target="api.example.com",
                payload={
                    "run_id": "run-ade-1",
                    "round_findings": [
                        {
                            "plugin": "deep_js_intelligence",
                            "target": "api.example.com",
                            "category": "js_discovery",
                            "severity": "info",
                            "title": "deep js",
                            "evidence": {"endpoints": ["/api/v2/admin/users", "/public/ping"]},
                            "metadata": {},
                        },
                        {
                            "plugin": "parameter_intelligence",
                            "target": "api.example.com",
                            "category": "parameter_intelligence",
                            "severity": "info",
                            "title": "params",
                            "evidence": {
                                "parameter_map_sample": [
                                    {"endpoint": "/api/v2/admin/users", "parameter": "user_id", "type": "numeric_id"},
                                    {"endpoint": "/api/v2/admin/users", "parameter": "account_id", "type": "identifier"},
                                ]
                            },
                            "metadata": {},
                        },
                        {
                            "plugin": "differential_auth_prover",
                            "target": "api.example.com",
                            "category": "critical_idor_vulnerability",
                            "severity": "high",
                            "title": "idor signal",
                            "evidence": {
                                "request_auth_b": {"url": "https://api.example.com/api/v2/admin/users?user_id=1001", "headers": {"Authorization": "Bearer user_b"}},
                                "response_auth_a": {"status": 200, "length": 240, "body": '{"id":1001,"email":"owner@example.com"}'},
                                "response_auth_b": {"status": 200, "length": 480, "body": '{"id":1001,"email":"owner@example.com","ssn":"123"}'},
                                "tested_parameter": "user_id",
                                "diff_map": {"content_similarity_pct": 70.0, "sensitive_object_hits": ["owner@example.com"]},
                            },
                            "metadata": {},
                        },
                    ],
                },
            )
            context = {
                "config": {"modules": {"ade_brain": {"evidence_dir": tmp, "max_boundary_candidates": 10, "max_spawn_tasks": 100}}},
                "runtime": {"timeout_seconds": 5},
            }
            prev_request = mod.request_http_async
            try:
                mod.request_http_async = _stub_request  # type: ignore[assignment]
                findings = asyncio.run(plugin.run(task, context))
            finally:
                mod.request_http_async = prev_request  # type: ignore[assignment]

            self.assertTrue(findings)
            categories = {f.category for f in findings}
            self.assertIn("ade_decision_cycle", categories)
            self.assertIn("state_machine_boundary_anomaly", categories)
            summary = [f for f in findings if f.category == "ade_decision_cycle"][0]
            spawn_tasks = summary.metadata.get("spawn_tasks", [])
            self.assertTrue(isinstance(spawn_tasks, list) and spawn_tasks)
            self.assertTrue(any(str(item.get("plugin")) == "parameter_intelligence" for item in spawn_tasks if isinstance(item, dict)))
            self.assertTrue(any(str(item.get("plugin")) == "differential_auth_prover" for item in spawn_tasks if isinstance(item, dict)))
            reports = summary.evidence.get("evidence_reports", [])
            self.assertTrue(isinstance(reports, list) and reports)
            report_path = Path(str(reports[0]))
            self.assertTrue(report_path.exists())
            text = report_path.read_text(encoding="utf-8")
            self.assertIn("URL Afetada", text)
            self.assertIn("Requisicao (CURL)", text)
            self.assertIn("Prova de Vazamento (Impacto)", text)


if __name__ == "__main__":
    unittest.main()
