#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import shutil
import sys
import traceback
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from aiohttp import web

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from hunterops.alert_router import AlertRouter
from hunterops.config import get_runtime, load_config
from hunterops.intelligence import dedupe_findings, serialize_findings
from hunterops.plugin_loader import load_plugins
from hunterops.runtime_paths import ensure_directory, resolve_path
from hunterops.storage import PostgresStorage
from hunterops.types import Finding, Task

RECON_TOOL_CANDIDATES = ("subfinder", "amass", "assetfinder", "gau", "waybackurls")
REQUIRED_TOOLS = ("httpx", "nuclei")
logging.basicConfig(level=logging.INFO, stream=sys.stdout, force=True)
LOG = logging.getLogger("test_pipeline")
_ERROR_FILE_HANDLER_READY = False


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _ensure_error_file_logging() -> Path:
    global _ERROR_FILE_HANDLER_READY
    log_dir = ensure_directory(ROOT / "logs", mode=0o755)
    error_log = log_dir / "error.log"
    if _ERROR_FILE_HANDLER_READY:
        return error_log
    root_logger = logging.getLogger()
    for handler in list(root_logger.handlers):
        if isinstance(handler, logging.FileHandler):
            try:
                if Path(handler.baseFilename).resolve() == error_log.resolve():  # type: ignore[attr-defined]
                    _ERROR_FILE_HANDLER_READY = True
                    return error_log
            except Exception:
                continue
    file_handler = logging.FileHandler(error_log, encoding="utf-8")
    file_handler.setLevel(logging.ERROR)
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root_logger.addHandler(file_handler)
    _ERROR_FILE_HANDLER_READY = True
    return error_log


def _normalize_target(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlparse(raw)
        host = str(parsed.hostname or "").strip()
    else:
        host = raw
    host = host.strip().strip("/").split("/")[0]
    if ":" in host:
        host = host.split(":", 1)[0]
    return host


class _WebhookSink:
    def __init__(self, *, host: str = "127.0.0.1", preferred_port: int = 8081) -> None:
        self._events: list[dict[str, Any]] = []
        self._host = str(host or "127.0.0.1")
        self._preferred_port = int(preferred_port)
        self._app: web.Application | None = None
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None
        self._bound_port: int | None = None

    @property
    def events(self) -> list[dict[str, Any]]:
        return list(self._events)

    async def _handle_post(self, request: web.Request) -> web.Response:
        raw = await request.read()
        payload: Any
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            payload = {"raw": raw.decode("utf-8", errors="ignore")}
        self._events.append(
            {
                "path": request.path,
                "headers": {str(k): str(v) for k, v in request.headers.items()},
                "payload": payload,
                "received_at": _utc_now(),
            }
        )
        return web.Response(status=204)

    async def start(self) -> dict[str, str]:
        self._app = web.Application()
        self._app.router.add_post("/{tail:.*}", self._handle_post)
        self._runner = web.AppRunner(self._app, access_log=None)
        await self._runner.setup()

        ports_to_try = [self._preferred_port] if self._preferred_port == 0 else [self._preferred_port, 0]
        last_error: Exception | None = None

        for port in ports_to_try:
            try:
                self._site = web.TCPSite(self._runner, self._host, int(port))
                await self._site.start()
                addresses = list(self._runner.addresses or [])
                if addresses:
                    self._bound_port = int(addresses[0][1])
                if not self._bound_port and self._site._server and self._site._server.sockets:  # type: ignore[attr-defined]
                    self._bound_port = int(self._site._server.sockets[0].getsockname()[1])  # type: ignore[attr-defined]
                break
            except OSError as err:
                last_error = err
                self._site = None
                continue

        if not self._bound_port:
            await self.close()
            if last_error is not None:
                raise last_error
            raise RuntimeError("webhook sink failed to bind on localhost")

        base = f"http://{self._host}:{self._bound_port}"
        return {
            "discord_research_webhook": f"{base}/discord/research",
            "discord_critical_webhook": f"{base}/discord/critical",
            "slack_research_webhook": f"{base}/slack/research",
            "slack_critical_webhook": f"{base}/slack/critical",
        }

    async def close(self) -> None:
        if self._runner is not None:
            try:
                await self._runner.cleanup()
            except Exception:
                pass
        self._site = None
        self._runner = None
        self._app = None
        self._bound_port = None


def _resolve_plugins_arg(value: str) -> list[str]:
    return [str(item).strip().lower() for item in str(value or "").split(",") if str(item).strip()]


def _toolchain_report() -> tuple[list[str], list[str], list[str]]:
    recon_available = [tool for tool in RECON_TOOL_CANDIDATES if shutil.which(tool)]
    required_missing = [tool for tool in REQUIRED_TOOLS if not shutil.which(tool)]
    hard_missing = list(required_missing)
    if not recon_available:
        hard_missing.append("recon_tool(subfinder|amass|assetfinder|gau|waybackurls)")
    return recon_available, required_missing, hard_missing


async def _run_plugin(plugin_name: str, plugin: Any, *, target: str, context: dict[str, Any]) -> list[Finding]:
    task = Task(plugin=plugin_name, target=target)
    raw_findings = await plugin.run(task, context)
    return plugin.normalize_findings(raw_findings, task)


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    return {
        "plugin": finding.plugin,
        "target": finding.target,
        "category": finding.category,
        "severity": finding.severity,
        "title": finding.title,
        "evidence": finding.evidence,
        "metadata": finding.metadata,
    }


def _build_router_config(out_dir: Path, sink_urls: dict[str, str]) -> dict[str, Any]:
    return {
        "enabled": True,
        "timeout_seconds": 4,
        "discord_dispatch_retries": 3,
        "dispatch_retry_backoff_seconds": 1.0,
        "dedupe_ttl_seconds": 120,
        "dedupe_query_mode": "keys_only",
        "dedupe_persist_file": str(out_dir / "alert_dedupe_smoke.json"),
        "dedupe_persist_ttl_seconds": 3600,
        "dedupe_persist_max_entries": 5000,
        "dedupe_persist_flush_seconds": 1,
        **sink_urls,
    }


def _pick_alert_candidates(findings: list[Finding], max_alerts: int) -> list[Finding]:
    ranked = sorted(
        findings,
        key=lambda item: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(str(item.severity).lower(), 0),
        reverse=True,
    )
    return ranked[: max(1, int(max_alerts))]


async def run_async(args: argparse.Namespace) -> int:
    error_log_path = _ensure_error_file_logging()
    normalized_target = _normalize_target(args.target)
    if not normalized_target:
        raise ValueError("target is empty after normalization")
    if normalized_target != str(args.target):
        LOG.info("Target normalized input=%s normalized=%s", args.target, normalized_target)
    LOG.info("Smoke test bootstrap started target=%s config=%s", normalized_target, args.config)
    run_id = str(args.run_id or datetime.now(UTC).strftime("smoke_%Y%m%d_%H%M%S")).strip()
    out_dir = ensure_directory(resolve_path(args.out_dir, base=ROOT, prefer_existing=False), mode=0o755)
    report_path = out_dir / f"test_pipeline_report_{run_id}.json"
    findings_path = out_dir / f"test_pipeline_findings_{run_id}.json"

    LOG.info("Loading Config")
    cfg = load_config(resolve_path(args.config, base=ROOT))
    runtime = get_runtime(cfg)
    runtime["timeout_seconds"] = max(20, int(args.timeout_seconds))
    runtime["stealth_mode"] = True
    runtime["proxies"] = runtime.get("proxies", []) if isinstance(runtime.get("proxies", []), list) else []
    plugin_names = _resolve_plugins_arg(args.plugins)
    plugins = load_plugins(plugin_names)
    LOG.info("Plugins loaded=%s", ",".join(plugin_names))

    LOG.info("Checking Toolchain")
    recon_available, required_missing, hard_missing = _toolchain_report()
    stage: dict[str, Any] = {
        "started_at": _utc_now(),
        "target": normalized_target,
        "target_input": str(args.target),
        "run_id": run_id,
        "error_log": str(error_log_path),
        "config": str(resolve_path(args.config, base=ROOT)),
        "plugins": plugin_names,
        "toolchain": {
            "recon_available": recon_available,
            "required_missing": required_missing,
        },
        "steps": {},
        "overall_ok": False,
    }
    if hard_missing:
        LOG.error("Toolchain check failed missing=%s", ",".join(hard_missing))
        stage["steps"]["toolchain"] = {
            "ok": False,
            "missing": hard_missing,
            "message": "Install missing binaries and retry smoke test.",
        }
        report_path.write_text(json.dumps(stage, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        print(f"FATAL: Binários não encontrados: {hard_missing}")
        print(json.dumps(stage["steps"]["toolchain"], ensure_ascii=True))
        return 2
    stage["steps"]["toolchain"] = {"ok": True, "missing": []}
    LOG.info("Toolchain check passed")

    context = {"config": cfg, "runtime": runtime}
    findings_by_plugin: dict[str, list[Finding]] = {}
    all_findings: list[Finding] = []
    LOG.info("Iniciando plugins de ataque...")
    for name in plugin_names:
        if name == "recon":
            LOG.info("Starting Recon")
        if name == "scan":
            LOG.info("Running Nuclei")
        LOG.info("Running plugin=%s target=%s", name, normalized_target)
        plugin = plugins[name]
        findings = await _run_plugin(name, plugin, target=normalized_target, context=context)
        findings_by_plugin[name] = findings
        all_findings.extend(findings)
        stage["steps"][name] = {
            "ok": len(findings) > 0,
            "findings": len(findings),
            "sample_titles": [f.title for f in findings[:3]],
        }

    deduped_findings = dedupe_findings(all_findings)
    rows = serialize_findings(deduped_findings)
    findings_path.write_text(json.dumps(rows, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    stage["steps"]["findings"] = {
        "total_raw": len(all_findings),
        "total_deduped": len(deduped_findings),
        "path": str(findings_path),
    }

    scan_findings = findings_by_plugin.get("scan", [])
    scan_ok = len(scan_findings) > 0 or bool(args.allow_empty_scan)
    if not scan_ok:
        scan_step = stage["steps"].setdefault("scan", {"ok": False, "findings": 0, "sample_titles": []})
        scan_step["ok"] = False
        scan_step["message"] = "Nuclei did not produce findings for this run."

    pg_cfg = cfg.get("storage", {}).get("postgres", {}) if isinstance(cfg.get("storage"), dict) else {}
    dsn_env = str(pg_cfg.get("dsn_env", "HUNTEROPS_POSTGRES_DSN")).strip() or "HUNTEROPS_POSTGRES_DSN"
    storage, dsn_meta = PostgresStorage.from_env(enabled=True, dsn_env=dsn_env)
    if storage is None:
        LOG.error(
            "Postgres storage unavailable dsn_env=%s source=%s profile=%s",
            dsn_env,
            dsn_meta.get("dsn_source", "missing"),
            dsn_meta.get("runtime_profile", "unknown"),
        )
        stage["steps"]["db"] = {
            "ok": False,
            "error": "postgres_dsn_unresolved",
            "dsn_env": dsn_env,
            "dsn_source": dsn_meta.get("dsn_source", "missing"),
            "runtime_profile": dsn_meta.get("runtime_profile", "unknown"),
        }
        report_path.write_text(json.dumps(stage, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        return 3

    try:
        LOG.info("Writing to Postgres")
        storage.write_findings(run_id=run_id, rows=rows)
        stored_rows = storage.list_findings(run_id=run_id)
    except Exception as err:
        LOG.exception("Postgres write/read failed run_id=%s err=%s", run_id, type(err).__name__)
        stage["steps"]["db"] = {
            "ok": False,
            "error": f"postgres_write_failed:{type(err).__name__}",
            "dsn_source": dsn_meta.get("dsn_source", "unknown"),
        }
        report_path.write_text(json.dumps(stage, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        return 4

    stage["steps"]["db"] = {
        "ok": len(stored_rows) >= len(rows) and len(rows) > 0,
        "rows_written": len(rows),
        "rows_read_back": len(stored_rows),
        "dsn_source": dsn_meta.get("dsn_source", "unknown"),
        "runtime_profile": dsn_meta.get("runtime_profile", "unknown"),
    }

    use_local_sink = str(args.webhook_mode or "local").strip().lower() != "real"
    sink = _WebhookSink(host="127.0.0.1", preferred_port=8081) if use_local_sink else None
    router: AlertRouter | None = None
    alert_candidates: list[Finding] = []
    alerts_sent = 0
    events: list[dict[str, Any]] = []
    try:
        sink_urls: dict[str, str] = {}
        if sink is not None:
            sink_urls = await sink.start()
            LOG.info("Webhook sink online routes=%s", ",".join(sorted(sink_urls.keys())))
        router_cfg = _build_router_config(out_dir, sink_urls)
        router = AlertRouter(router_cfg)
        alert_candidates = _pick_alert_candidates(deduped_findings, args.max_alerts)
        for finding in alert_candidates:
            if router and await router.send_finding(finding, run_id=run_id, source="smoke_test"):
                alerts_sent += 1
    finally:
        if router is not None:
            await router.close()
        if sink is not None:
            await sink.close()
            events = sink.events
    stage["steps"]["webhook"] = {
        "ok": (alerts_sent > 0 and len(events) > 0) if use_local_sink else (alerts_sent > 0),
        "mode": "local" if use_local_sink else "real",
        "alerts_attempted": len(alert_candidates),
        "alerts_sent": alerts_sent,
        "events_received": len(events),
        "event_paths": [str(item.get("path", "")) for item in events[:6]],
    }

    stage["completed_at"] = _utc_now()
    full_ok = bool(
        stage["steps"].get("toolchain", {}).get("ok")
        and stage["steps"].get("recon", {}).get("ok")
        and stage["steps"].get("fingerprint", {}).get("ok")
        and scan_ok
        and stage["steps"].get("db", {}).get("ok")
        and stage["steps"].get("webhook", {}).get("ok")
    )
    db_only_ok = bool(stage["steps"].get("db", {}).get("ok"))
    overall_mode = str(args.overall_ok_mode or "full").strip().lower()
    if overall_mode == "db_only":
        stage["overall_ok"] = db_only_ok
        stage["overall_ok_mode"] = "db_only"
    else:
        stage["overall_ok"] = full_ok
        stage["overall_ok_mode"] = "full"
    report_path.write_text(json.dumps(stage, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"overall_ok": stage["overall_ok"], "report": str(report_path)}, ensure_ascii=True))
    return 0 if stage["overall_ok"] else 5


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Smoke-test end-to-end flow: Recon -> Fingerprint -> Nuclei -> DB -> Webhook"
    )
    parser.add_argument("--config", default="config/engine.yaml")
    parser.add_argument("--target", default="http://brokencrystals.com")
    parser.add_argument("--plugins", default="recon,fingerprint,scan")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--out-dir", default="data/reports/smoke")
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--max-alerts", type=int, default=4)
    parser.add_argument("--allow-empty-scan", action="store_true")
    parser.add_argument("--overall-ok-mode", choices=("full", "db_only"), default="full")
    parser.add_argument("--webhook-mode", choices=("local", "real"), default="local")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        return asyncio.run(run_async(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        try:
            _ensure_error_file_logging()
            LOG.exception("fatal_unhandled_exception")
        except Exception:
            pass
        traceback.print_exc()
        raise
