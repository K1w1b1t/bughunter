from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any

from hunterops.async_runtime import install_uvloop_if_available
from hunterops.plugin_base import Plugin
from hunterops.rate_limit import AsyncRateLimiter
from hunterops.retry import retry_async
from hunterops.types import Finding, Task

SENSITIVE_PRIORITY_KEYWORDS = ("admin", "internal", "v1/debug", "config", "staging", "export", "graphiql")


class TaskExecutor:
    def __init__(
        self,
        plugins: dict[str, Plugin],
        context: dict[str, Any],
        logger: logging.Logger,
    ) -> None:
        install_uvloop_if_available(logger=logger)
        self.plugins = plugins
        self.context = context
        self.logger = logger
        runtime = context["runtime"]
        self.queue: asyncio.PriorityQueue[tuple[int, int, Task]] = asyncio.PriorityQueue(maxsize=runtime["task_queue_size"])
        self.results: list[Finding] = []
        self.rate_limiter = AsyncRateLimiter(runtime["rate_limit_per_sec"])
        cpu_workers = max(2, (os.cpu_count() or 1) * 2)
        configured_workers = int(runtime.get("concurrency", 0) or 0)
        self.concurrency = max(1, configured_workers, cpu_workers)
        self.max_retries = runtime["max_retries"]
        self.backoff = runtime["backoff_base_seconds"]
        self.enable_recursive_tasks = bool(runtime.get("enable_recursive_tasks", True))
        self.recursion_max_depth = int(runtime.get("recursion_max_depth", 2))
        self.recursion_max_tasks = int(runtime.get("recursion_max_tasks", 500))
        self.recursion_max_tasks_step = int(runtime.get("recursion_max_tasks_step", 150))
        self.recursion_max_tasks_cap = int(runtime.get("recursion_max_tasks_cap", 5000))
        self.spawned_tasks = 0
        self.spawn_signatures: set[str] = set()
        self._spawn_lock = asyncio.Lock()
        self.metrics: dict[str, dict[str, float]] = {}
        self._task_counter = 0

    def _task_priority(self, task: Task) -> int:
        payload = task.payload if isinstance(task.payload, dict) else {}
        base = int(payload.get("priority", payload.get("priority_score", 0)) or 0)
        endpoint_hints: list[str] = [task.target]
        for key in ("seed_paths", "paths", "known_endpoints", "endpoints"):
            arr = payload.get(key)
            if isinstance(arr, list):
                endpoint_hints.extend([str(x) for x in arr if isinstance(x, str)])
        joined = " ".join(endpoint_hints).lower()
        if any(k in joined for k in SENSITIVE_PRIORITY_KEYWORDS):
            base = max(base, 100)
        return max(0, base)

    async def _enqueue(self, task: Task) -> None:
        priority = self._task_priority(task)
        # Lower numeric priority comes first in PriorityQueue.
        item = (-priority, self._task_counter, task)
        self._task_counter += 1
        await self.queue.put(item)

    async def add_tasks(self, tasks: list[Task]) -> None:
        for t in tasks:
            await self._enqueue(t)

    async def worker(self, idx: int) -> None:
        while True:
            _priority, _seq, task = await self.queue.get()
            if task.plugin == "__stop__":
                self.queue.task_done()
                return
            try:
                start = time.perf_counter()
                await self.rate_limiter.wait()
                pack = task.payload.get("program_pack", {}) if isinstance(task.payload, dict) else {}
                blocked = {str(x) for x in pack.get("blocked_checks", [])} if isinstance(pack, dict) else set()
                allowed = {str(x) for x in pack.get("allowed_checks", [])} if isinstance(pack, dict) else set()
                if blocked and task.plugin in blocked:
                    continue
                if allowed and task.plugin not in allowed and task.plugin != "platform_sync":
                    continue
                plugin = self.plugins[task.plugin]

                async def invoke() -> list[Finding]:
                    try:
                        return await plugin.run(task, self.context)
                    except Exception as err:
                        self.logger.exception(f"plugin_run_failed plugin={task.plugin} target={task.target} err={err}")
                        return []

                findings = await retry_async(invoke, retries=self.max_retries, base_delay=self.backoff)
                findings = plugin.normalize_findings(findings, task)
                if findings:
                    self.results.extend(findings)
                    await self._spawn_from_findings(task, findings)
                elapsed = time.perf_counter() - start
                m = self.metrics.setdefault(task.plugin, {"runs": 0.0, "errors": 0.0, "latency_sum": 0.0, "findings": 0.0})
                m["runs"] += 1
                m["latency_sum"] += elapsed
                m["findings"] += float(len(findings or []))
            except Exception as err:
                self.logger.exception(f"worker_failed worker={idx} plugin={task.plugin} target={task.target} err={err}")
                m = self.metrics.setdefault(task.plugin, {"runs": 0.0, "errors": 0.0, "latency_sum": 0.0, "findings": 0.0})
                m["runs"] += 1
                m["errors"] += 1
            finally:
                self.queue.task_done()

    async def run(self, tasks: list[Task]) -> list[Finding]:
        await self.add_tasks(tasks)
        workers = [asyncio.create_task(self.worker(i)) for i in range(self.concurrency)]
        await self.queue.join()
        for _ in workers:
            await self._enqueue(Task(plugin="__stop__", target="", payload={"priority": 1000}))
        await asyncio.gather(*workers)
        return self.results

    @staticmethod
    def _finding_is_anomaly(finding: Finding) -> bool:
        cat = str(finding.category).lower()
        sev = str(finding.severity).lower()
        if sev in {"critical", "high"}:
            return True
        if any(k in cat for k in ("anomaly", "idor", "leak", "auth_bypass", "behavior")):
            return True
        ev = finding.evidence if isinstance(finding.evidence, dict) else {}
        diff = ev.get("diff_map", ev.get("response_diff", ev.get("base_vs_variant_diff", {})))
        if isinstance(diff, dict):
            if float(diff.get("structure_similarity_pct", 0) or 0) >= 90 and int(diff.get("status_other", 0) or 0) == 200:
                return True
            if int(diff.get("anomaly_score", 0) or 0) >= 60:
                return True
        return False

    async def _spawn_from_findings(self, parent: Task, findings: list[Finding]) -> None:
        if not self.enable_recursive_tasks:
            return
        depth = 0
        if isinstance(parent.payload, dict):
            try:
                depth = int(parent.payload.get("_depth", 0))
            except Exception:
                depth = 0
        if depth >= self.recursion_max_depth:
            return
        if any(self._finding_is_anomaly(f) for f in findings):
            self.recursion_max_tasks = min(
                self.recursion_max_tasks + self.recursion_max_tasks_step,
                self.recursion_max_tasks_cap,
            )
        for f in findings:
            meta = f.metadata if isinstance(f.metadata, dict) else {}
            spawn = meta.get("spawn_tasks", [])
            if not isinstance(spawn, list):
                continue
            for raw in spawn:
                if not isinstance(raw, dict):
                    continue
                plugin = str(raw.get("plugin", "")).strip()
                target = str(raw.get("target", parent.target)).strip() or parent.target
                if not plugin:
                    continue
                payload = raw.get("payload", {})
                if not isinstance(payload, dict):
                    payload = {}
                payload = payload.copy()
                payload["_depth"] = depth + 1
                if isinstance(parent.payload, dict) and "program_pack" in parent.payload and "program_pack" not in payload:
                    payload["program_pack"] = parent.payload.get("program_pack", {})
                sig = f"{plugin}|{target}|{json.dumps(payload, sort_keys=True, ensure_ascii=True)}"
                async with self._spawn_lock:
                    if self.spawned_tasks >= self.recursion_max_tasks:
                        return
                    if sig in self.spawn_signatures:
                        continue
                    self.spawn_signatures.add(sig)
                    self.spawned_tasks += 1
                await self._enqueue(Task(plugin=plugin, target=target, payload=payload))

    def summarize_metrics(self) -> dict[str, dict[str, float]]:
        out: dict[str, dict[str, float]] = {}
        for plugin, m in self.metrics.items():
            runs = max(1.0, m.get("runs", 1.0))
            out[plugin] = {
                "runs": m.get("runs", 0.0),
                "errors": m.get("errors", 0.0),
                "error_rate": round((m.get("errors", 0.0) / runs) * 100, 2),
                "avg_latency_sec": round(m.get("latency_sum", 0.0) / runs, 4),
                "findings": m.get("findings", 0.0),
            }
        return out
