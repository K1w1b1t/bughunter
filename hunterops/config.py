from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    suffix = path.suffix.lower()
    raw = path.read_text(encoding="utf-8")
    if suffix in {".yaml", ".yml"}:
        return yaml.safe_load(raw) or {}
    if suffix == ".json":
        return json.loads(raw)
    raise ValueError("Unsupported config format. Use YAML or JSON.")


def get_runtime(config: dict[str, Any]) -> dict[str, Any]:
    runtime = config.get("runtime", {})
    return {
        "concurrency": int(runtime.get("concurrency", 8)),
        "timeout_seconds": int(runtime.get("timeout_seconds", 25)),
        "rate_limit_per_sec": float(runtime.get("rate_limit_per_sec", 4.0)),
        "max_retries": int(runtime.get("max_retries", 2)),
        "backoff_base_seconds": float(runtime.get("backoff_base_seconds", 1.2)),
        "task_queue_size": int(runtime.get("task_queue_size", 2000)),
        "enable_recursive_tasks": bool(runtime.get("enable_recursive_tasks", True)),
        "recursion_max_depth": int(runtime.get("recursion_max_depth", 5)),
        "recursion_max_tasks": int(runtime.get("recursion_max_tasks", 500)),
        "recursion_max_tasks_step": int(runtime.get("recursion_max_tasks_step", 150)),
        "recursion_max_tasks_cap": int(runtime.get("recursion_max_tasks_cap", 5000)),
        "stealth_mode": bool(runtime.get("stealth_mode", True)),
        "proxies": runtime.get("proxies", []),
        "wordlists": runtime.get("wordlists", {"default": "wordlists/common.txt"}),
    }
