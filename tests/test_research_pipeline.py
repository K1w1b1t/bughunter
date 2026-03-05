from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

from hunterops.types import Finding


def load_module():
    p = Path("scripts/research_pipeline.py")
    spec = importlib.util.spec_from_file_location("research_pipeline", p)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["research_pipeline"] = mod
    spec.loader.exec_module(mod)
    return mod


class ResearchPipelineTests(unittest.TestCase):
    def test_reaction_logic_generates_parameter_task(self) -> None:
        mod = load_module()
        logic = mod.ReactionLogic(max_seed_paths=10)
        findings = [
            Finding(
                plugin="deep_js_intelligence",
                target="api.example.com",
                category="js_discovery",
                severity="info",
                title="x",
                evidence={"endpoints": ["/api/users", "/api/orders?id=1"]},
                metadata={"endpoints": ["/graphql"]},
            )
        ]
        tasks = logic.tasks_from_saved_findings(findings, run_id="run-1", pack={"name": "p"})
        self.assertEqual(len(tasks), 2)
        plugins = {t.plugin for t in tasks}
        self.assertIn("parameter_intelligence", plugins)
        self.assertIn("differential_auth_prover", plugins)
        self.assertTrue(all("seed_paths" in t.payload for t in tasks))

    def test_task_endpoints_normalization(self) -> None:
        mod = load_module()
        t = mod.Task(plugin="parameter_intelligence", target="api.example.com", payload={"seed_paths": ["https://api.example.com/api/users?id=1", "/admin"]})
        eps = mod._task_endpoints(t)
        self.assertIn("/api/users", eps)
        self.assertIn("/admin", eps)

    def test_delta_monitor_no_storage(self) -> None:
        mod = load_module()
        dm = mod.DeltaMonitor(storage=None)
        findings = [
            mod.Finding(
                plugin="deep_js_intelligence",
                target="api.example.com",
                category="js_discovery",
                severity="info",
                title="x",
                evidence={"endpoints": ["/api/users"], "javascript_artifacts": [{"url": "https://api.example.com/main.js", "sha256": "abc"}]},
                metadata={},
            )
        ]
        delta = dm.compare(target="api.example.com", run_id="r1", current_findings=findings)
        self.assertEqual(delta["new_endpoints"], [])
        self.assertEqual(delta["changed_js"], [])

    def test_logic_chaining_builds_tasks_from_idor_signal(self) -> None:
        mod = load_module()
        lc = mod.LogicChainingEngine()
        findings = [
            mod.Finding(
                plugin="parameter_intelligence",
                target="api.example.com",
                category="idor_logic_signal",
                severity="high",
                title="x",
                evidence={"leaked_identifiers": ["user@example.com"]},
                metadata={},
            )
        ]
        tasks = lc.build_tasks(findings, run_id="r2", pack={"name": "p"}, available_plugins={"behavioral_diff_engine"})
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0].plugin, "behavioral_diff_engine")
        self.assertIn("priority_score", tasks[0].payload)


if __name__ == "__main__":
    unittest.main()
