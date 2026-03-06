from __future__ import annotations

from unittest import TestCase

from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task


class _DummyPlugin(Plugin):
    name = "dummy"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        return []


class PluginBaseMetadataTests(TestCase):
    def test_normalize_findings_enforces_metadata_fields(self) -> None:
        plugin = _DummyPlugin()
        task = Task(plugin="dummy", target="example.com", payload={})
        findings = [
            Finding(
                plugin="dummy",
                target="example.com",
                category="test",
                severity="info",
                title="sample",
                evidence={"endpoint": "/api/me"},
                metadata={"confidence": 71},
            )
        ]
        normalized = plugin.normalize_findings(findings, task)
        self.assertEqual(len(normalized), 1)
        meta = normalized[0].metadata
        self.assertEqual(meta.get("discovery_source"), "dummy")
        self.assertGreater(float(meta.get("confidence_score", 0)), 0)
        self.assertTrue(str(meta.get("structural_hash", "")))
