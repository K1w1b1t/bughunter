#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hunterops.config import get_runtime, load_config
from hunterops.async_runtime import install_uvloop_if_available
from hunterops.env_utils import evaluate_runtime_dependencies, filter_enabled_plugins
from hunterops.executor import TaskExecutor
from hunterops.http_client import close_async_http_client, configure_http_pool
from hunterops.intelligence import dedupe_findings, http_diff_score, load_feedback, serialize_findings, to_jsonl
from hunterops.logging_utils import setup_logging
from hunterops.plugin_loader import enabled_plugins, load_plugins
from hunterops.program_packs import load_program_packs, resolve_pack
from hunterops.reporting import export_csv, export_dashboard, export_html, export_json, export_markdown, write_json
from hunterops.runtime_paths import ensure_directory, resolve_path
from hunterops.storage import PostgresStorage
from hunterops.types import Task


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="HunterOps Professional CLI")
    parser.add_argument("--config", default="config/engine.yaml")
    parser.add_argument("--target", default="")
    parser.add_argument("--targets-file", default="data/targets/in_scope_hosts.txt")
    parser.add_argument("--full-scan", action="store_true")
    parser.add_argument("--plugins", default="")
    parser.add_argument("--out-dir", default="data/reports/engine")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def collect_targets(args: argparse.Namespace) -> list[str]:
    if args.target:
        return [args.target.strip()]
    path = resolve_path(args.targets_file)
    if not path.exists():
        return []
    return [x.strip() for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def resolve_plugins(config: dict[str, Any], args: argparse.Namespace) -> list[str]:
    if args.plugins:
        return [x.strip().lower() for x in args.plugins.split(",") if x.strip()]
    names = enabled_plugins(config)
    if args.full_scan:
        return names
    # sane default
    default_set = {"recon", "fingerprint", "scan", "cors", "takeover", "playwright_capture", "business_logic_sniper", "race_condition_turbo"}
    return [n for n in names if n in default_set]


def build_tasks(
    targets: list[str], plugin_names: list[str], include_platform_sync: bool, packs: list[dict[str, Any]]
) -> list[Task]:
    tasks: list[Task] = []
    for t in targets:
        pack = resolve_pack(t, packs)
        for p in plugin_names:
            tasks.append(Task(plugin=p, target=t, payload={"program_pack": pack or {}}))
    if include_platform_sync and "platform_sync" in plugin_names:
        tasks.append(Task(plugin="platform_sync", target="__platforms__"))
    return tasks


def baseline_compare(rows: list[dict[str, Any]], baseline_path: Path) -> dict[str, Any]:
    if not baseline_path.exists():
        return {"baseline_exists": False, "diffs": []}
    import json

    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    old = baseline.get("findings", [])
    old_map = {f"{x.get('plugin')}|{x.get('target')}|{x.get('title')}": x for x in old}
    diffs: list[dict[str, Any]] = []
    for row in rows:
        key = f"{row.get('plugin')}|{row.get('target')}|{row.get('title')}"
        old_row = old_map.get(key)
        if not old_row:
            diffs.append({"type": "new", "key": key})
            continue
        baseline_resp = {
            "status": old_row.get("metadata", {}).get("status", 0),
            "length": old_row.get("metadata", {}).get("length", 0),
            "json_keys": old_row.get("metadata", {}).get("json_keys", []),
        }
        current_resp = {
            "status": row.get("metadata", {}).get("status", 0),
            "length": row.get("metadata", {}).get("length", 0),
            "json_keys": row.get("metadata", {}).get("json_keys", []),
        }
        diff = http_diff_score(baseline_resp, current_resp)
        if diff["anomaly_score"] > 0:
            diffs.append({"type": "changed", "key": key, "diff": diff})
    return {"baseline_exists": True, "diffs": diffs}


async def run_async(args: argparse.Namespace) -> int:
    config_path = resolve_path(args.config)
    config = load_config(config_path)
    runtime = get_runtime(config)
    pool_cfg = config.get("http_pool", {}) if isinstance(config.get("http_pool"), dict) else {}
    configure_http_pool(
        max_connections=int(pool_cfg.get("max_connections", max(50, int(runtime.get("concurrency", 8)) * 12))),
        max_keepalive_connections=int(pool_cfg.get("max_keepalive_connections", max(20, int(runtime.get("concurrency", 8)) * 4))),
        keepalive_expiry=float(pool_cfg.get("keepalive_expiry", 10.0)),
        verify_ssl=bool(pool_cfg.get("verify_ssl", True)),
        http2=bool(pool_cfg.get("http2", False)),
        retries=int(pool_cfg.get("retries", 0)),
        linux_socket_tuning=bool(pool_cfg.get("linux_socket_tuning", True)),
    )
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    out_dir = ensure_directory(resolve_path(args.out_dir), mode=0o755)
    logger = setup_logging(out_dir / f"engine_{ts}.jsonl", verbose=args.verbose)
    config_hash = hashlib.sha256(config_path.read_bytes()).hexdigest() if config_path.exists() else ""

    targets = collect_targets(args)
    if not targets:
        logger.error("No targets provided.")
        await close_async_http_client()
        return 2

    plugin_names = resolve_plugins(config, args)
    dep_report = evaluate_runtime_dependencies(config, plugin_names)
    for msg in dep_report["critical_warnings"]:
        logger.critical(msg)
    plugin_names = filter_enabled_plugins(plugin_names, dep_report["disabled_plugins"])
    if not plugin_names:
        logger.error("No runnable plugins after dependency checks.")
        await close_async_http_client()
        return 5
    plugins = load_plugins(plugin_names)
    packs = load_program_packs(resolve_path(config.get("program_packs", {}).get("file", "config/program_packs.yaml")))
    context = {"config": config, "runtime": runtime, "logger": logger}

    tasks = build_tasks(targets, plugin_names, include_platform_sync=True, packs=packs)
    logger.info(f"starting execution targets={len(targets)} plugins={len(plugin_names)} tasks={len(tasks)}")
    write_json(
        out_dir / "run_audit.json",
        {
            "run_id": ts,
            "started_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "config_file": args.config,
            "config_hash_sha256": config_hash,
            "targets_count": len(targets),
            "plugins": plugin_names,
        },
    )

    executor = TaskExecutor(plugins=plugins, context=context, logger=logger)
    findings = await executor.run(tasks)
    findings = dedupe_findings(findings)
    feedback = load_feedback(resolve_path(config.get("feedback", {}).get("file", "data/processed/feedback_weights.json")))
    rows = serialize_findings(findings, feedback=feedback)

    label = args.target if args.target else f"{len(targets)}-targets"
    export_json(out_dir / "findings.json", rows)
    export_csv(out_dir / "findings.csv", rows)
    export_markdown(out_dir / "findings.md", rows, label)
    export_html(out_dir / "findings.html", rows, label)
    export_dashboard(out_dir / "dashboard.html", rows)
    (out_dir / "findings.jsonl").write_text(to_jsonl(rows), encoding="utf-8")

    pg_cfg = config.get("storage", {}).get("postgres", {})
    pg_enabled = bool(pg_cfg.get("enabled", False))
    dsn_env = str(pg_cfg.get("dsn_env", "HUNTEROPS_POSTGRES_DSN"))
    dsn = os.getenv(dsn_env, "")
    db_optional = os.getenv("HUNTEROPS_DB_OPTIONAL", "0") == "1"
    if pg_enabled and not dsn and not db_optional:
        logger.error(f"postgres enabled but missing env {dsn_env}")
        await close_async_http_client()
        return 3
    if pg_enabled and dsn:
        try:
            storage = PostgresStorage(dsn=dsn, enabled=True)
            storage.write_findings(run_id=ts, rows=rows)
            logger.info("postgres_write=ok")
        except Exception as err:
            logger.error(f"postgres_write=failed err={err}")
            if not db_optional:
                await close_async_http_client()
                return 4

    baseline = baseline_compare(rows, out_dir / "baseline.json")
    write_json(out_dir / "baseline_diff.json", baseline)
    write_json(out_dir / "baseline.json", {"generated_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"), "findings": rows})
    write_json(out_dir / "metrics.json", {"plugin_metrics": executor.summarize_metrics()})

    logger.info(f"completed findings={len(rows)}")
    if baseline.get("diffs"):
        logger.info(f"baseline_diffs={len(baseline['diffs'])}")
    write_json(
        out_dir / "run_audit.json",
        {
            "run_id": ts,
            "completed_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "config_file": args.config,
            "config_hash_sha256": config_hash,
            "targets_count": len(targets),
            "plugins": plugin_names,
            "findings_count": len(rows),
        },
    )
    await close_async_http_client()
    return 0


def main() -> int:
    install_uvloop_if_available()
    args = parse_args()
    try:
        return asyncio.run(run_async(args))
    except KeyboardInterrupt:
        return 130
    except Exception as err:
        # global fail-safe
        print(f"[fatal] unhandled exception: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
