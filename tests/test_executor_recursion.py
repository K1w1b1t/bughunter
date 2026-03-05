from __future__ import annotations

import logging
import unittest

from hunterops.executor import TaskExecutor
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task


class RootPlugin(Plugin):
    name = "root_plugin"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="root",
                severity="info",
                title="root",
                evidence={},
                metadata={
                    "spawn_tasks": [
                        {
                            "plugin": "child_plugin",
                            "target": task.target,
                            "payload": {"seed_paths": ["/api/users"]},
                        }
                    ]
                },
            )
        ]


class ChildPlugin(Plugin):
    name = "child_plugin"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        return [Finding(plugin=self.name, target=task.target, category="child", severity="info", title="child", evidence={}, metadata={})]


class AnomalyPlugin(Plugin):
    name = "anomaly_plugin"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="behavioral_response_anomaly",
                severity="medium",
                title="anomaly",
                evidence={"response_diff": {"anomaly_score": 70}},
                metadata={
                    "spawn_tasks": [
                        {
                            "plugin": "child_plugin",
                            "target": task.target,
                            "payload": {"seed_paths": ["/admin/export"]},
                        }
                    ]
                },
            )
        ]


class ExecutorRecursionTests(unittest.IsolatedAsyncioTestCase):
    async def test_executor_spawns_recursive_tasks(self) -> None:
        plugins = {"root_plugin": RootPlugin(), "child_plugin": ChildPlugin()}
        context = {
            "runtime": {
                "task_queue_size": 100,
                "rate_limit_per_sec": 100.0,
                "concurrency": 2,
                "max_retries": 0,
                "backoff_base_seconds": 0.1,
                "enable_recursive_tasks": True,
                "recursion_max_depth": 2,
                "recursion_max_tasks": 10,
            }
        }
        logger = logging.getLogger("test-executor-recursion")
        ex = TaskExecutor(plugins=plugins, context=context, logger=logger)
        res = await ex.run([Task(plugin="root_plugin", target="api.example.com", payload={})])
        cats = {r.category for r in res}
        self.assertIn("root", cats)
        self.assertIn("child", cats)

    async def test_executor_priority_and_dynamic_recursion_budget(self) -> None:
        plugins = {"anomaly_plugin": AnomalyPlugin(), "child_plugin": ChildPlugin()}
        context = {
            "runtime": {
                "task_queue_size": 100,
                "rate_limit_per_sec": 100.0,
                "concurrency": 2,
                "max_retries": 0,
                "backoff_base_seconds": 0.1,
                "enable_recursive_tasks": True,
                "recursion_max_depth": 5,
                "recursion_max_tasks": 1,
                "recursion_max_tasks_step": 5,
                "recursion_max_tasks_cap": 20,
            }
        }
        logger = logging.getLogger("test-executor-priority")
        ex = TaskExecutor(plugins=plugins, context=context, logger=logger)
        # Keyword "admin/export" should force max priority.
        self.assertEqual(ex._task_priority(Task(plugin="child_plugin", target="api.example.com", payload={"seed_paths": ["/admin/export"]})), 100)
        res = await ex.run([Task(plugin="anomaly_plugin", target="api.example.com", payload={})])
        cats = {r.category for r in res}
        self.assertIn("behavioral_response_anomaly", cats)
        self.assertIn("child", cats)
        self.assertGreater(ex.recursion_max_tasks, 1)


if __name__ == "__main__":
    unittest.main()
