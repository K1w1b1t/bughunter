#!/usr/bin/env python3
"""Autonomous research pipeline for HunterOps (incremental, non-core orchestration)."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hunterops.config import get_runtime, load_config
from hunterops.ade_brain import PluginImpl as ADEBrainPlugin
from hunterops.alert_router import AlertRouter
from hunterops.discord_notifier import DiscordDispatch
from hunterops.env_utils import evaluate_runtime_dependencies, filter_enabled_plugins
from hunterops.evidence_generator import generate_research_artifacts
from hunterops.hackerone_manager import HackerOneManager
from hunterops.hackerone_sync_engine import HackerOneSyncEngine
from hunterops.http_client import close_async_http_client, configure_http_pool, json_keys, request_http_async
from hunterops.intelligence import dedupe_findings, serialize_findings, to_jsonl
from hunterops.logging_utils import attach_alert_router, setup_logging
from hunterops.oob_engine import OOBEngine
from hunterops.plugin_loader import load_plugins
from hunterops.program_packs import load_program_packs, resolve_pack
from hunterops.report_engine import ReportEngine
from hunterops.rate_limit import AsyncRateLimiter
from hunterops.reporting import export_csv, export_dashboard, export_html, export_json, export_markdown
from hunterops.retry import retry_async
from hunterops.async_runtime import install_uvloop_if_available
from hunterops.runtime_paths import ensure_directory, resolve_path
from hunterops.session_profiles import auth_header, load_sessions
from hunterops.storage import PostgresStorage
from hunterops.types import Finding, Task

EMAIL_RE = re.compile(r"""[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}""")
UUID_RE = re.compile(r"""\b[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\b""")
NUMERIC_ID_RE = re.compile(r"""\b[1-9][0-9]{2,18}\b""")
SENSITIVE_PRIORITY_KEYWORDS = ("admin", "internal", "v1/debug", "config", "staging", "export", "graphiql")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="HunterOps autonomous research pipeline")
    parser.add_argument("--config", default="config/engine.yaml")
    parser.add_argument("--targets-file", default="data/targets/in_scope_hosts.txt")
    parser.add_argument("--target", default="")
    parser.add_argument("--plugins", default="")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--out-dir", default="data/reports/research")
    parser.add_argument(
        "--alert-dry-run",
        action="store_true",
        help="Bypass scan flow and dispatch synthetic critical/research alerts to Discord and Slack",
    )
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def collect_targets(args: argparse.Namespace) -> list[str]:
    if args.target:
        return [args.target.strip()]
    p = resolve_path(args.targets_file)
    if not p.exists():
        return []
    return [x.strip() for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def _task_endpoints(task: Task) -> list[str]:
    if not isinstance(task.payload, dict):
        return ["/"]
    eps = task.payload.get("seed_paths") or task.payload.get("paths") or task.payload.get("endpoints") or task.payload.get("known_endpoints")
    if isinstance(eps, list):
        out = []
        for e in eps:
            if not isinstance(e, str) or not e.strip():
                continue
            if e.startswith("http://") or e.startswith("https://"):
                out.append(urlparse(e).path or "/")
            else:
                out.append(e if e.startswith("/") else f"/{e}")
        return sorted(list(set(out))) or ["/"]
    return ["/"]


def _iter_strings(value: Any, max_depth: int = 4, _depth: int = 0) -> list[str]:
    if _depth > max_depth:
        return []
    if isinstance(value, str):
        if value.strip():
            return [value]
        return []
    out: list[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str) and k.strip():
                out.append(k)
            out.extend(_iter_strings(v, max_depth=max_depth, _depth=_depth + 1))
    elif isinstance(value, list):
        for item in value:
            out.extend(_iter_strings(item, max_depth=max_depth, _depth=_depth + 1))
    return out


def _detect_entities_from_text(text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for hit in EMAIL_RE.findall(text):
        found.append(("email", hit.strip()))
    for hit in UUID_RE.findall(text):
        found.append(("uuid", hit.strip()))
    for hit in NUMERIC_ID_RE.findall(text):
        found.append(("numeric_id", hit.strip()))
    return found


def _finding_source_endpoint(finding: Finding) -> str:
    ev = finding.evidence if isinstance(finding.evidence, dict) else {}
    req = ev.get("request", {}) if isinstance(ev.get("request"), dict) else {}
    req_url = req.get("url")
    if isinstance(req_url, str) and req_url.strip():
        return urlparse(req_url).path or "/"
    for key in ("endpoint", "path", "base_url", "modified_url", "url"):
        raw = ev.get(key)
        if isinstance(raw, str) and raw.strip():
            if raw.startswith("http://") or raw.startswith("https://"):
                return urlparse(raw).path or "/"
            return raw if raw.startswith("/") else f"/{raw}"
    return "/"


def extract_entity_rows(findings: list[Finding], target: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    dedupe: set[str] = set()
    for f in findings:
        ev = f.evidence if isinstance(f.evidence, dict) else {}
        md = f.metadata if isinstance(f.metadata, dict) else {}
        source_endpoint = _finding_source_endpoint(f)
        confidence = float(md.get("confidence_score", md.get("confidence", 65)) or 65)

        explicit = ev.get("discovered_entities", [])
        if isinstance(explicit, list):
            for item in explicit:
                if not isinstance(item, dict):
                    continue
                etype = str(item.get("entity_type", "")).strip().lower()
                evalue = str(item.get("entity_value", "")).strip()
                if not etype or not evalue:
                    continue
                sig = f"{target}|{etype}|{evalue.lower()}|{f.plugin}|{source_endpoint}"
                if sig in dedupe:
                    continue
                dedupe.add(sig)
                rows.append(
                    {
                        "entity_type": etype,
                        "entity_value": evalue,
                        "source_plugin": f.plugin,
                        "source_endpoint": str(item.get("source_endpoint", source_endpoint)),
                        "confidence_score": float(item.get("confidence_score", confidence) or confidence),
                        "metadata": {
                            "finding_category": f.category,
                            "finding_title": f.title,
                            "origin": "explicit_discovered_entities",
                            "source_target": target,
                        },
                    }
                )

        for key in ("leaked_identifiers", "object_identifiers"):
            values = ev.get(key, [])
            if isinstance(values, list):
                for raw in values:
                    if not isinstance(raw, str):
                        continue
                    for etype, evalue in _detect_entities_from_text(raw):
                        sig = f"{target}|{etype}|{evalue.lower()}|{f.plugin}|{source_endpoint}"
                        if sig in dedupe:
                            continue
                        dedupe.add(sig)
                        rows.append(
                            {
                                "entity_type": etype,
                                "entity_value": evalue,
                                "source_plugin": f.plugin,
                                "source_endpoint": source_endpoint,
                                "confidence_score": confidence,
                                "metadata": {
                                    "finding_category": f.category,
                                    "finding_title": f.title,
                                    "origin": key,
                                    "source_target": target,
                                },
                            }
                        )

        # Fallback: lightweight regex extraction over structured evidence/metadata strings.
        for blob in _iter_strings({"evidence": ev, "metadata": md}, max_depth=3):
            for etype, evalue in _detect_entities_from_text(blob):
                sig = f"{target}|{etype}|{evalue.lower()}|{f.plugin}|{source_endpoint}"
                if sig in dedupe:
                    continue
                dedupe.add(sig)
                rows.append(
                    {
                        "entity_type": etype,
                        "entity_value": evalue,
                        "source_plugin": f.plugin,
                        "source_endpoint": source_endpoint,
                        "confidence_score": max(45.0, confidence - 18.0),
                        "metadata": {
                            "finding_category": f.category,
                            "finding_title": f.title,
                            "origin": "regex_fallback",
                            "source_target": target,
                        },
                    }
                )
    return rows


def _set_query(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    query_items = [item for item in query_items if item[0] != key]
    query_items.append((key, value))
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(query_items), parsed.fragment))


def _json_structure_tokens(value: Any, prefix: str = "") -> set[str]:
    tokens: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            key_s = str(key)
            path = f"{prefix}.{key_s}" if prefix else key_s
            tokens.add(path)
            tokens |= _json_structure_tokens(child, path)
    elif isinstance(value, list):
        for item in value[:5]:
            path = f"{prefix}[]" if prefix else "[]"
            tokens.add(path)
            tokens |= _json_structure_tokens(item, path)
    return tokens


def _semantic_structure_similarity(text_a: str, text_b: str) -> float:
    try:
        obj_a = json.loads(text_a)
        obj_b = json.loads(text_b)
    except Exception:
        tokens_a = set(re.split(r"[^a-z0-9]+", text_a.lower()))
        tokens_b = set(re.split(r"[^a-z0-9]+", text_b.lower()))
        tokens_a = {t for t in tokens_a if t}
        tokens_b = {t for t in tokens_b if t}
        if not tokens_a and not tokens_b:
            return 100.0
        return round((len(tokens_a & tokens_b) / max(1, len(tokens_a | tokens_b))) * 100.0, 2)
    ta = _json_structure_tokens(obj_a)
    tb = _json_structure_tokens(obj_b)
    if not ta and not tb:
        return 100.0
    return round((len(ta & tb) / max(1, len(ta | tb))) * 100.0, 2)


def _spawn_tasks_from_findings(findings: list[Finding], max_depth: int = 2) -> list[Task]:
    spawned: list[Task] = []
    dedupe: set[str] = set()
    for f in findings:
        meta = f.metadata if isinstance(f.metadata, dict) else {}
        raw = meta.get("spawn_tasks", [])
        if not isinstance(raw, list):
            continue
        for item in raw:
            if not isinstance(item, dict):
                continue
            plugin = str(item.get("plugin", "")).strip()
            target = str(item.get("target", f.target)).strip() or f.target
            payload = item.get("payload", {})
            if not plugin:
                continue
            payload_dict = payload if isinstance(payload, dict) else {}
            depth = int(payload_dict.get("_depth", 0) or 0)
            if depth > max_depth:
                continue
            sig = f"{plugin}|{target}|{json.dumps(payload_dict, sort_keys=True, ensure_ascii=True)}"
            if sig in dedupe:
                continue
            dedupe.add(sig)
            spawned.append(Task(plugin=plugin, target=target, payload=payload_dict))
    return spawned


async def _run_report_engine_if_high_critical(
    *,
    report_engine: ReportEngine,
    target: str,
    run_id: str,
    round_findings: list[Finding],
    logger: Any,
) -> list[Finding]:
    if not any(str(f.severity).strip().lower() in {"high", "critical"} for f in round_findings):
        return []
    try:
        return await report_engine.process_round(target=target, run_id=run_id, round_findings=round_findings)
    except Exception as err:
        logger.error(f"report_engine_round_failed target={target} err={err}")
        return []


def _should_alert_router_dispatch(finding: Finding) -> bool:
    if finding.plugin == "vulnerability_correlation_engine":
        return True
    if finding.plugin in {"business_logic_sniper", "race_condition_turbo"}:
        return True
    return str(finding.severity).strip().lower() in {"high", "critical"}


async def _route_alerts_from_batch(
    *,
    alert_router: AlertRouter,
    batch: list[Finding],
    run_id: str,
    logger: Any,
    source: str,
) -> None:
    if not alert_router.available or not batch:
        return
    for finding in batch:
        if not _should_alert_router_dispatch(finding):
            continue
        try:
            await alert_router.send_finding(finding, run_id=run_id, source=source)
        except Exception as err:
            logger.error(f"alert_router_dispatch_failed plugin={finding.plugin} target={finding.target} err={err}")


def _write_alert_dry_run_poc(*, out_dir: Path, run_id: str) -> Path:
    dry_dir = ensure_directory(out_dir / "alert_dry_run", mode=0o755)
    out_file = dry_dir / f"dry_run_poc_{run_id}.md"
    if out_file.exists():
        return out_file
    lines = [
        "# Alert Dry Run Evidence",
        "",
        "## Scenario",
        "Synthetic critical finding used to validate Discord/Slack routing and attachment uploads.",
        "",
        "## URL Afetada",
        "`https://dry-run.hunterops.local/api/v2/transactions/transfer?amount=-9999&currency=USD`",
        "",
        "## Parametro Vulneravel",
        "`amount`",
        "",
        "## Requisicao (CURL)",
        "```bash",
        "curl -i -X POST \"https://dry-run.hunterops.local/api/v2/transactions/transfer?amount=-9999&currency=USD\" "
        "-H \"Content-Type: application/json\" -d '{\"from_account_id\":\"1001\",\"to_account_id\":\"1002\",\"amount\":-9999,\"currency\":\"USD\"}'",
        "```",
        "",
        "## Prova de Vazamento (Impacto)",
        "Simulated response returns HTTP 200 with cross-account transfer confirmation despite invalid negative amount.",
        "",
        "## Payload Expansion",
    ]
    for idx in range(1, 90):
        lines.append(f"- sample_{idx:03d}: unauthorized_record=true transaction_ref=TXN-{idx:05d}")
    out_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_file


async def _run_alert_dry_run(
    *,
    alert_router: AlertRouter,
    out_dir: Path,
    run_id: str,
    logger: Any,
) -> int:
    if not alert_router.available:
        logger.error("alert_dry_run_unavailable reason=no_webhook_configured")
        return 7

    has_discord = bool(
        str(getattr(alert_router, "discord_research_webhook", "")).strip()
        or str(getattr(alert_router, "discord_critical_webhook", "")).strip()
    )
    has_slack = bool(
        str(getattr(alert_router, "slack_research_webhook", "")).strip()
        or str(getattr(alert_router, "slack_critical_webhook", "")).strip()
    )
    if not has_discord and not has_slack:
        logger.error("alert_dry_run_missing_channels discord=0 slack=0")
        return 7
    if not has_discord:
        logger.warning("alert_dry_run_warning discord_channels_missing=1")
    if not has_slack:
        logger.warning("alert_dry_run_warning slack_channels_missing=1")

    poc_path = _write_alert_dry_run_poc(out_dir=out_dir, run_id=run_id)
    identifier = str(os.getenv("H1_API_IDENTIFIER", "")).strip() or "reaperk0ji"

    critical_finding = Finding(
        plugin="business_logic_sniper",
        target="dry-run.hunterops.local",
        category="financial_tampering_indicator",
        severity="critical",
        title="Test Critical Finding - Financial Logic Tampering",
        evidence={
            "endpoint": "/api/v2/transactions/transfer?amount=-9999&currency=USD",
            "tested_parameter": "amount",
            "poc_path": str(poc_path),
            "request": {
                "method": "POST",
                "url": "https://dry-run.hunterops.local/api/v2/transactions/transfer?amount=-9999&currency=USD",
                "headers": {
                    "Content-Type": "application/json",
                    "X-H1-Client-Identifier": identifier,
                },
                "body": {
                    "from_account_id": "1001",
                    "to_account_id": "1002",
                    "amount": -9999,
                    "currency": "USD",
                },
            },
            "impact": "Dry-run signal: negative transfer accepted with HTTP 200 and cross-account context.",
        },
        metadata={
            "impact": 98.0,
            "confidence_score": 99.0,
            "dry_run": True,
            "discovery_source": "alert_dry_run",
        },
    )
    research_log = Finding(
        plugin="vulnerability_correlation_engine",
        target="dry-run.hunterops.local",
        category="research_log_heartbeat",
        severity="medium",
        title="Test Research Log - Pipeline Heartbeat",
        evidence={
            "endpoint": "/api/health/research-log",
            "tested_parameter": "trace_id",
            "request": {
                "method": "GET",
                "url": "https://dry-run.hunterops.local/api/health/research-log?trace_id=hb-001",
                "headers": {
                    "Accept": "application/json",
                    "X-H1-Client-Identifier": identifier,
                },
            },
            "evidence_snippet": "Dry-run heartbeat for low/medium research stream validation.",
        },
        metadata={
            "impact": 45.0,
            "confidence_score": 76.0,
            "dry_run": True,
            "discovery_source": "alert_dry_run",
        },
    )

    critical_sent = await alert_router.send_finding(critical_finding, run_id=run_id, source="alert_dry_run")
    research_sent = await alert_router.send_finding(research_log, run_id=run_id, source="alert_dry_run")
    await alert_router.send_critical_log(message="Alert dry-run completed: critical and research signals dispatched.", run_id=run_id)
    logger.info(
        "alert_dry_run_completed "
        f"critical_sent={critical_sent} "
        f"research_sent={research_sent} "
        f"poc_attachment={poc_path}"
    )
    return 0 if (critical_sent and research_sent) else 7


def _delta_score(delta: dict[str, Any]) -> float:
    new_endpoints = len(delta.get("new_endpoints", [])) if isinstance(delta.get("new_endpoints"), list) else 0
    changed_js = len(delta.get("changed_js", [])) if isinstance(delta.get("changed_js"), list) else 0
    new_parameters = len(delta.get("new_parameters", [])) if isinstance(delta.get("new_parameters"), list) else 0
    return round(min(100.0, (new_endpoints * 22.0) + (changed_js * 16.0) + (new_parameters * 12.0)), 2)


def _finding_confidence(finding: Finding) -> float:
    md = finding.metadata if isinstance(finding.metadata, dict) else {}
    return float(md.get("confidence_score", md.get("confidence", 0)) or 0)


def _is_logic_prover_confirmed(finding: Finding) -> bool:
    if finding.plugin != "logic_prover":
        return False
    if finding.category not in {"Potential_IDOR_Signal", "Broken_Object_Level_Authorization"}:
        return False
    return _finding_confidence(finding) > 50.0


def _finding_impact(finding: Finding) -> str:
    category = str(finding.category).lower()
    if "broken_object_level_authorization" in category or "idor" in category:
        return "Critical: Unauthorized PII/object access confirmed across authentication boundaries."
    if "auth" in category:
        return "High: Access-control inconsistency may allow unauthorized account/resource operations."
    return "Medium: Logic discrepancy with potential business impact requires triage."


def _estimated_payout_for_severity(severity: str) -> str:
    sev = str(severity or "").strip().lower()
    if sev == "critical":
        return "USD 1200-5000"
    if sev == "high":
        return "USD 400-1500"
    if sev == "medium":
        return "USD 100-500"
    if sev == "low":
        return "USD 25-150"
    return "N/A"


def _finding_evidence_snippet(finding: Finding) -> str:
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    parameter = str(evidence.get("tested_parameter", evidence.get("parameter", ""))).strip()
    leaked = evidence.get("leaked_entities", []) if isinstance(evidence.get("leaked_entities"), list) else []
    leaked_preview = []
    for item in leaked[:4]:
        if isinstance(item, dict):
            leaked_preview.append(str(item.get("entity_value", "")).strip())
    leaked_sample = ", ".join([x for x in leaked_preview if x]) or "n/a"
    response_a = evidence.get("response_auth_a", {}) if isinstance(evidence.get("response_auth_a"), dict) else {}
    response_b = evidence.get("response_auth_b", {}) if isinstance(evidence.get("response_auth_b"), dict) else {}
    return (
        f"param={parameter or 'id'} "
        f"statusA={int(response_a.get('status', 0) or 0)} "
        f"statusB={int(response_b.get('status', 0) or 0)} "
        f"leaks={len(leaked)} sample=[{leaked_sample}]"
    )


def _collect_status_codes(value: Any, out: set[int], depth: int = 0) -> None:
    if depth > 4:
        return
    if isinstance(value, dict):
        for key, child in value.items():
            lk = str(key).lower()
            if lk in {"status", "status_code"}:
                try:
                    status = int(child or 0)
                except Exception:
                    status = 0
                if status > 0:
                    out.add(status)
            _collect_status_codes(child, out, depth + 1)
    elif isinstance(value, list):
        for item in value[:80]:
            _collect_status_codes(item, out, depth + 1)


def _feedback_status_by_target(findings: list[Finding]) -> dict[str, set[int]]:
    tracked = {403, 429}
    out: dict[str, set[int]] = {}
    for finding in findings:
        statuses: set[int] = set()
        _collect_status_codes(finding.evidence if isinstance(finding.evidence, dict) else {}, statuses)
        _collect_status_codes(finding.metadata if isinstance(finding.metadata, dict) else {}, statuses)
        hits = {status for status in statuses if status in tracked}
        if not hits:
            continue
        out.setdefault(finding.target, set()).update(hits)
    return out


def _build_feedback_retry_tasks(
    *,
    current_wave: list[Task],
    feedback: dict[str, set[int]],
    scheduler: Any,
    run_id: str,
    max_depth: int,
) -> list[Task]:
    if not feedback:
        return []
    out: list[Task] = []
    dedupe: set[str] = set()
    for task in current_wave:
        statuses = feedback.get(task.target, set())
        if not statuses:
            continue
        payload = task.payload if isinstance(task.payload, dict) else {}
        retry_count = int(payload.get("_feedback_retry", 0) or 0)
        if retry_count >= int(getattr(scheduler, "feedback_max_retries", 2)):
            continue
        dominant_status = 429 if 429 in statuses else 403
        rotated_ua = scheduler.next_user_agent(task.target)
        rotated_proxy = scheduler.next_proxy(task.target)
        merged = payload.copy()
        merged["run_id"] = str(merged.get("run_id", run_id) or run_id)
        merged["_feedback_retry"] = retry_count + 1
        merged["_depth"] = min(int(merged.get("_depth", 0) or 0), max_depth)
        merged["trigger"] = f"feedback_retry_{dominant_status}"
        merged["feedback_status"] = dominant_status
        merged["request_delay_seconds"] = round(float(scheduler.target_delay_remaining(task.target)), 3)
        if rotated_ua:
            merged["user_agent"] = rotated_ua
        if rotated_proxy:
            merged["proxy"] = rotated_proxy
        base_prio = float(merged.get("priority_score", merged.get("priority", 0)) or 0)
        merged["priority_score"] = max(base_prio, 97.0 if dominant_status == 429 else 94.0)

        sig = f"{task.plugin}|{task.target}|{json.dumps(merged, sort_keys=True, ensure_ascii=True)}"
        if sig in dedupe:
            continue
        dedupe.add(sig)
        out.append(Task(plugin=task.plugin, target=task.target, payload=merged))
    return out


def _normalize_endpoint_key(raw: str) -> str:
    value = str(raw or "").strip()
    if not value:
        return "/"
    if value.startswith("http://") or value.startswith("https://"):
        parsed = urlparse(value)
        return parsed.path or "/"
    parsed = urlparse(value)
    path = parsed.path or value
    if not path.startswith("/"):
        path = f"/{path}"
    return path or "/"


def _auth_weight_from_finding(finding: Finding) -> float:
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    ra = evidence.get("response_auth_a", {}) if isinstance(evidence.get("response_auth_a"), dict) else {}
    rb = evidence.get("response_auth_b", {}) if isinstance(evidence.get("response_auth_b"), dict) else {}
    rc = evidence.get("response_unauthenticated", {}) if isinstance(evidence.get("response_unauthenticated"), dict) else {}
    status_a = int(ra.get("status", 0) or 0)
    status_b = int(rb.get("status", 0) or 0)
    status_c = int(rc.get("status", 0) or 0)
    if status_a in {200, 201} and status_b in {200, 201} and status_c in {401, 403}:
        return 2.0
    if status_a in {200, 201} and status_b in {200, 201} and status_c in {200, 201}:
        return 1.4
    return 1.0


class HighValuePriorityQueue:
    """Ranks recursive tasks by Delta-first and entity cross-pollination confidence."""

    def __init__(self, max_size: int = 4000) -> None:
        self.max_size = max(50, int(max_size))

    @staticmethod
    def confidence_formula(delta_struct: float, auth_weight: float, leaked_entities: int, probes: int) -> float:
        # C = ((Delta_struct * W_auth) + (E_leaked * 20)) / N_probes
        return round(((max(0.0, delta_struct) * max(1.0, auth_weight)) + (max(0, leaked_entities) * 20.0)) / max(1.0, float(probes)), 2)

    def _build_signal_map(self, findings: list[Finding]) -> dict[str, dict[str, float]]:
        endpoint_signals: dict[str, dict[str, float]] = {}
        for finding in findings:
            evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
            metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
            endpoint = _normalize_endpoint_key(_finding_source_endpoint(finding))

            struct_similarity = evidence.get("structure_similarity_pct", metadata.get("structure_similarity_pct"))
            if struct_similarity is None and isinstance(evidence.get("diff_map"), dict):
                struct_similarity = evidence["diff_map"].get("structure_similarity_pct")
            try:
                similarity = float(struct_similarity if struct_similarity is not None else 100.0)
            except Exception:
                similarity = 100.0
            delta_struct = max(0.0, 100.0 - similarity)

            leaked = 0
            if isinstance(evidence.get("leaked_entities"), list):
                leaked += len(evidence["leaked_entities"])
            if isinstance(evidence.get("sensitive_field_indicators"), list):
                leaked += len(evidence["sensitive_field_indicators"])
            if isinstance(evidence.get("diff_map"), dict):
                hits = evidence["diff_map"].get("sensitive_object_hits", [])
                if isinstance(hits, list):
                    leaked += len(hits)

            probes = int(metadata.get("probe_count", 1) or 1)
            auth_weight = _auth_weight_from_finding(finding)
            confidence = self.confidence_formula(delta_struct=delta_struct, auth_weight=auth_weight, leaked_entities=leaked, probes=probes)

            prev = endpoint_signals.get(endpoint, {"confidence": 0.0, "delta_struct": 0.0, "leaked_entities": 0.0, "probes": 1.0})
            if confidence >= float(prev.get("confidence", 0.0)):
                endpoint_signals[endpoint] = {
                    "confidence": confidence,
                    "delta_struct": delta_struct,
                    "leaked_entities": float(leaked),
                    "probes": float(probes),
                }
        return endpoint_signals

    @staticmethod
    def _priority_class(task: Task) -> int:
        payload = task.payload if isinstance(task.payload, dict) else {}
        trigger = str(payload.get("trigger", "")).strip().lower()
        if trigger in {"delta_change_monitor", "delta_detected"} or bool(payload.get("delta_detected", False)):
            return 0
        if task.plugin == "entity_cross_pollinator" or trigger in {"entity_cross_pollinator", "entity_pool_update"}:
            return 1
        if bool(payload.get("entity_substitution")) or bool(payload.get("recursive_object_probe", False)):
            return 1
        return 2

    def rank(self, tasks: list[Task], findings: list[Finding]) -> list[Task]:
        if not tasks:
            return []
        signal_map = self._build_signal_map(findings=findings)
        ranked: list[tuple[int, float, float, str, Task]] = []
        dedupe: set[str] = set()

        for task in tasks:
            payload = task.payload.copy() if isinstance(task.payload, dict) else {}
            endpoints = _task_endpoints(task)
            endpoint = _normalize_endpoint_key(endpoints[0] if endpoints else "/")
            signal = signal_map.get(endpoint, {})
            payload_priority = float(payload.get("priority_score", payload.get("priority", 0)) or 0.0)

            if signal:
                queue_confidence = float(signal.get("confidence", 0.0))
            else:
                leaked = int(payload.get("leaked_entities", 0) or 0)
                delta_struct = float(payload.get("delta_struct", 0.0) or 0.0)
                auth_weight = float(payload.get("auth_weight", 1.0) or 1.0)
                probes = int(payload.get("probe_count", 1) or 1)
                queue_confidence = self.confidence_formula(delta_struct=delta_struct, auth_weight=auth_weight, leaked_entities=leaked, probes=probes)

            priority_class = self._priority_class(task)
            if priority_class == 0 and queue_confidence < 100.0:
                queue_confidence = 100.0
            if priority_class == 1 and queue_confidence < 90.0:
                queue_confidence = 90.0

            payload["priority_class"] = priority_class
            payload["queue_confidence"] = queue_confidence
            payload["priority_score"] = max(payload_priority, queue_confidence)

            ranked_task = Task(plugin=task.plugin, target=task.target, payload=payload)
            signature = f"{ranked_task.plugin}|{ranked_task.target}|{json.dumps(ranked_task.payload, sort_keys=True, ensure_ascii=True)}"
            if signature in dedupe:
                continue
            dedupe.add(signature)
            ranked.append((priority_class, -queue_confidence, -max(payload_priority, queue_confidence), ranked_task.plugin, ranked_task))

        ranked.sort(key=lambda row: (row[0], row[1], row[2], row[3]))
        return [row[4] for row in ranked[: self.max_size]]


@dataclass
class ResearchState:
    run_id: str
    storage: PostgresStorage | None

    def was_scanned(self, plugin: str, target: str, endpoint: str) -> bool:
        if not self.storage:
            return False
        try:
            return self.storage.was_endpoint_scanned(self.run_id, plugin, target, endpoint)
        except Exception:
            return False

    def mark_scanned(self, plugin: str, target: str, endpoint: str) -> None:
        if not self.storage:
            return
        try:
            self.storage.mark_endpoint_scanned(self.run_id, plugin, target, endpoint)
        except Exception:
            return

    def filter_task(self, task: Task) -> Task | None:
        endpoints = _task_endpoints(task)
        remaining = [ep for ep in endpoints if not self.was_scanned(task.plugin, task.target, ep)]
        if not remaining:
            return None
        payload = task.payload.copy() if isinstance(task.payload, dict) else {}
        if len(remaining) != len(endpoints):
            payload["seed_paths"] = remaining
        return Task(plugin=task.plugin, target=task.target, payload=payload)


class ReactionLogic:
    """Turns discovery findings into follow-up tasks."""

    def __init__(self, max_seed_paths: int = 80) -> None:
        self.max_seed_paths = max_seed_paths

    @staticmethod
    def _priority(seed_paths: list[str]) -> int:
        merged = " ".join(seed_paths).lower()
        if any(k in merged for k in SENSITIVE_PRIORITY_KEYWORDS):
            return 100
        return 70

    def tasks_from_saved_findings(self, findings: list[Finding], run_id: str, pack: dict[str, Any] | None) -> list[Task]:
        derived: list[Task] = []
        by_target: dict[str, set[str]] = {}
        for f in findings:
            if f.category != "js_discovery":
                continue
            eps = set()
            if isinstance(f.evidence, dict):
                raw = f.evidence.get("endpoints", [])
                if isinstance(raw, list):
                    eps |= {str(x) for x in raw if isinstance(x, str)}
            if isinstance(f.metadata, dict):
                rawm = f.metadata.get("endpoints", [])
                if isinstance(rawm, list):
                    eps |= {str(x) for x in rawm if isinstance(x, str)}
            if not eps:
                continue
            normalized = set()
            for ep in eps:
                if ep.startswith("http"):
                    normalized.add(urlparse(ep).path or "/")
                else:
                    normalized.add(ep if ep.startswith("/") else f"/{ep}")
            by_target.setdefault(f.target, set()).update(normalized)

        for target, eps in by_target.items():
            seed_paths = sorted(list(eps))[: self.max_seed_paths]
            prio = self._priority(seed_paths)
            derived.append(
                Task(
                    plugin="parameter_intelligence",
                    target=target,
                    payload={
                        "seed_paths": seed_paths,
                        "trigger": "js_discovery",
                        "run_id": run_id,
                        "priority": prio,
                        "priority_score": prio,
                        "program_pack": pack or {},
                    },
                )
            )
            derived.append(
                Task(
                    plugin="differential_auth_prover",
                    target=target,
                    payload={
                        "seed_paths": seed_paths,
                        "trigger": "js_discovery",
                        "run_id": run_id,
                        "priority": prio,
                        "priority_score": prio,
                        "program_pack": pack or {},
                    },
                )
            )
        return derived


class DeltaMonitor:
    """Compares current results with previous run and prioritizes deep probes."""

    def __init__(self, storage: PostgresStorage | None) -> None:
        self.storage = storage

    @staticmethod
    def _extract_js_discovery(findings: list[Finding]) -> tuple[set[str], dict[str, str]]:
        endpoints: set[str] = set()
        js_hashes: dict[str, str] = {}
        for f in findings:
            if f.category != "js_discovery":
                continue
            if isinstance(f.evidence, dict):
                for e in f.evidence.get("endpoints", []) if isinstance(f.evidence.get("endpoints"), list) else []:
                    if isinstance(e, str):
                        endpoints.add(e if e.startswith("/") else urlparse(e).path or "/")
                artifacts = f.evidence.get("javascript_artifacts", [])
                if isinstance(artifacts, list):
                    for a in artifacts:
                        if not isinstance(a, dict):
                            continue
                        u = str(a.get("url", ""))
                        h = str(a.get("sha256", ""))
                        if u and h:
                            js_hashes[u] = h
        return endpoints, js_hashes

    @staticmethod
    def _extract_parameter_keys(findings: list[Finding]) -> set[str]:
        out: set[str] = set()
        for finding in findings:
            if finding.category != "parameter_intelligence":
                continue
            evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
            sample = evidence.get("parameter_map_sample", [])
            if isinstance(sample, list):
                for item in sample:
                    if not isinstance(item, dict):
                        continue
                    endpoint = _normalize_endpoint_key(str(item.get("endpoint", "")))
                    parameter = str(item.get("parameter", "")).strip()
                    if endpoint and parameter:
                        out.add(f"{endpoint}:{parameter}")
            tested = str(evidence.get("tested_parameter", "")).strip()
            if tested:
                endpoint = _normalize_endpoint_key(_finding_source_endpoint(finding))
                out.add(f"{endpoint}:{tested}")
        return out

    def compare(self, target: str, run_id: str, current_findings: list[Finding]) -> dict[str, Any]:
        if not self.storage:
            return {"new_endpoints": [], "changed_js": [], "new_parameters": []}
        try:
            prev_run = self.storage.get_previous_run_id(target=target, current_run_id=run_id)
            if not prev_run:
                return {"new_endpoints": [], "changed_js": [], "new_parameters": []}
            prev_rows = self.storage.fetch_run_findings(run_id=prev_run, target=target)
        except Exception:
            return {"new_endpoints": [], "changed_js": [], "new_parameters": []}

        curr_eps, curr_js = self._extract_js_discovery(current_findings)
        prev_findings = []
        for r in prev_rows:
            prev_findings.append(
                Finding(
                    plugin=str(r.get("plugin", "")),
                    target=str(r.get("target", target)),
                    category=str(r.get("category", "")),
                    severity=str(r.get("severity", "info")),
                    title=str(r.get("title", "")),
                    evidence=r.get("evidence", {}) if isinstance(r.get("evidence"), dict) else {},
                    metadata=r.get("metadata", {}) if isinstance(r.get("metadata"), dict) else {},
                )
            )
        prev_eps, prev_js = self._extract_js_discovery(prev_findings)
        curr_params = self._extract_parameter_keys(current_findings)
        prev_params = self._extract_parameter_keys(prev_findings)

        new_eps = sorted(list(curr_eps - prev_eps))
        changed_js = sorted([u for u, h in curr_js.items() if u in prev_js and prev_js[u] != h])
        new_parameters = sorted(list(curr_params - prev_params))
        return {"new_endpoints": new_eps, "changed_js": changed_js, "new_parameters": new_parameters}

    def build_priority_tasks(
        self,
        target: str,
        run_id: str,
        pack: dict[str, Any] | None,
        current_findings: list[Finding],
        available_plugins: set[str],
        precomputed_delta: dict[str, Any] | None = None,
    ) -> list[Task]:
        delta = precomputed_delta if isinstance(precomputed_delta, dict) else self.compare(target=target, run_id=run_id, current_findings=current_findings)
        if not delta.get("new_endpoints") and not delta.get("changed_js") and not delta.get("new_parameters"):
            return []
        deep_paths: set[str] = set(delta.get("new_endpoints", []))
        for jsu in delta.get("changed_js", []):
            deep_paths.add(urlparse(jsu).path or "/")
        for key in delta.get("new_parameters", []):
            if not isinstance(key, str) or ":" not in key:
                continue
            endpoint, _ = key.split(":", 1)
            deep_paths.add(_normalize_endpoint_key(endpoint))

        tasks: list[Task] = []
        if "parameter_intelligence" in available_plugins:
            tasks.append(
                Task(
                    plugin="parameter_intelligence",
                    target=target,
                    payload={
                        "seed_paths": sorted(list(deep_paths))[:120],
                        "priority_score": 100,
                        "trigger": "delta_change_monitor",
                        "program_pack": pack or {},
                        "run_id": run_id,
                    },
                )
            )
        if "behavioral_diff_engine" in available_plugins:
            tasks.append(
                Task(
                    plugin="behavioral_diff_engine",
                    target=target,
                    payload={
                        "paths": sorted(list(deep_paths))[:60],
                        "priority_score": 100,
                        "trigger": "delta_change_monitor",
                        "program_pack": pack or {},
                        "run_id": run_id,
                    },
                )
            )
        return tasks


class LogicChainingEngine:
    """Chains high-value logic leads into auth/account flow probes (safe, non-destructive)."""

    def __init__(self, auth_paths: list[str] | None = None) -> None:
        self.auth_paths = auth_paths or [
            "/api/password/recover",
            "/api/password/reset",
            "/api/account/update",
            "/api/profile/update",
        ]

    def build_tasks(
        self,
        findings: list[Finding],
        run_id: str,
        pack: dict[str, Any] | None,
        available_plugins: set[str],
    ) -> list[Task]:
        leaks_by_target: dict[str, set[str]] = {}
        for f in findings:
            if f.category not in {"idor_logic_signal", "idor_inconsistency_indicator", "idor_behavior_indicator"}:
                continue
            if not isinstance(f.evidence, dict):
                continue
            leaks = f.evidence.get("leaked_identifiers", [])
            if not isinstance(leaks, list):
                continue
            for lk in leaks:
                if isinstance(lk, str) and lk.strip():
                    leaks_by_target.setdefault(f.target, set()).add(lk.strip())

        tasks: list[Task] = []
        for target, leaks in leaks_by_target.items():
            if not leaks:
                continue
            payload_base = {
                "paths": self.auth_paths,
                "leaked_indicators": sorted(list(leaks))[:30],
                "trigger": "logic_chaining",
                "priority_score": 100,
                "program_pack": pack or {},
                "run_id": run_id,
            }
            if "behavioral_diff_engine" in available_plugins:
                tasks.append(Task(plugin="behavioral_diff_engine", target=target, payload=payload_base.copy()))
            if "context_aware_fuzzing_engine" in available_plugins:
                tasks.append(Task(plugin="context_aware_fuzzing_engine", target=target, payload=payload_base.copy()))
        return tasks


class DifferentialAuthProver:
    """Runs multi-session differential checks for high-risk object access patterns."""

    def __init__(self, cfg: dict[str, Any], runtime: dict[str, Any]) -> None:
        self.cfg = cfg
        self.timeout = int(runtime.get("timeout_seconds", 25))
        self.min_similarity = float(cfg.get("min_structure_similarity_pct", 90.0))
        self.max_candidates = int(cfg.get("max_candidates", 80))
        self.max_entities = int(cfg.get("max_entities", 120))
        self.auth_context_a = str(cfg.get("auth_context_a", "user")).strip() or "user"
        self.auth_context_b = str(cfg.get("auth_context_b", "user_b")).strip() or "user_b"
        self.sessions_file = Path(str(cfg.get("sessions_file", "data/sessions.yaml")))
        # Stealth-concurrency hard cap for non-disruptive operation.
        self.semaphore = asyncio.Semaphore(min(10, max(1, int(runtime.get("concurrency", 10)))))
        self.risk_types = {str(x).strip().lower() for x in cfg.get("high_risk_param_types", ["numeric_id", "identifier", "uuid", "token"])}
        self.risk_types.discard("")

    @staticmethod
    def _infer_param_type(param_name: str) -> str:
        name = param_name.lower()
        if "email" in name or "mail" in name:
            return "email"
        if any(k in name for k in ("token", "jwt", "auth", "api_key", "key", "secret")):
            return "token"
        if any(k in name for k in ("id", "uid", "account_id", "user_id", "order_id", "invoice_id", "profile_id")):
            return "numeric_id"
        return "string"

    @staticmethod
    def _normalize_endpoint(raw: str) -> str:
        value = str(raw or "").strip()
        if not value:
            return ""
        if value.startswith("http://") or value.startswith("https://"):
            p = urlparse(value)
            return p.path or "/"
        return value if value.startswith("/") else f"/{value}"

    def _candidate_rows(
        self,
        findings: list[Finding],
        storage: PostgresStorage | None,
        run_id: str,
    ) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        seen: set[str] = set()

        for f in findings:
            if f.category not in {"parameter_intelligence", "idor_logic_signal", "idor_inconsistency_indicator", "idor_behavior_indicator"}:
                continue
            ev = f.evidence if isinstance(f.evidence, dict) else {}
            samples = ev.get("parameter_map_sample", [])
            if isinstance(samples, list):
                for item in samples:
                    if not isinstance(item, dict):
                        continue
                    endpoint = self._normalize_endpoint(str(item.get("endpoint", "")))
                    param = str(item.get("parameter", "")).strip()
                    ptype = str(item.get("type", self._infer_param_type(param))).strip().lower()
                    if not endpoint or not param:
                        continue
                    if ptype not in self.risk_types:
                        continue
                    sig = f"{endpoint}|{param}"
                    if sig in seen:
                        continue
                    seen.add(sig)
                    rows.append({"endpoint": endpoint, "parameter": param, "param_type": ptype})

            if isinstance(ev.get("tested_parameter"), str):
                endpoint = self._normalize_endpoint(str(ev.get("base_url", ev.get("modified_url", ""))))
                param = str(ev.get("tested_parameter", "")).strip()
                if endpoint and param:
                    ptype = self._infer_param_type(param)
                    if ptype in self.risk_types:
                        sig = f"{endpoint}|{param}"
                        if sig not in seen:
                            seen.add(sig)
                            rows.append({"endpoint": endpoint, "parameter": param, "param_type": ptype})

        if not rows and storage:
            try:
                for item in storage.list_endpoint_parameters(run_id=run_id, limit=self.max_candidates * 8):
                    endpoint = self._normalize_endpoint(str(item.get("endpoint", "")))
                    param = str(item.get("param_name", "")).strip()
                    ptype = str(item.get("param_type", self._infer_param_type(param))).strip().lower()
                    if not endpoint or not param or ptype not in self.risk_types:
                        continue
                    sig = f"{endpoint}|{param}"
                    if sig in seen:
                        continue
                    seen.add(sig)
                    rows.append({"endpoint": endpoint, "parameter": param, "param_type": ptype})
                    if len(rows) >= self.max_candidates:
                        break
            except Exception:
                pass

        return rows[: self.max_candidates]

    @staticmethod
    def _entity_buckets(entities: list[dict[str, Any]]) -> dict[str, list[str]]:
        buckets: dict[str, list[str]] = {}
        for ent in entities:
            et = str(ent.get("entity_type", "")).strip().lower()
            ev = str(ent.get("entity_value", "")).strip()
            if not et or not ev:
                continue
            buckets.setdefault(et, [])
            if ev not in buckets[et]:
                buckets[et].append(ev)
        return buckets

    def _pick_value(self, param_type: str, buckets: dict[str, list[str]]) -> str:
        if param_type in buckets and buckets[param_type]:
            return buckets[param_type][0]
        if param_type in {"identifier", "numeric_id"}:
            for key in ("uuid", "numeric_id", "identifier"):
                if buckets.get(key):
                    return buckets[key][0]
            return "2"
        if param_type == "email":
            if buckets.get("email"):
                return buckets["email"][0]
            return "user@example.com"
        if param_type == "token":
            if buckets.get("token"):
                return buckets["token"][0]
            return "invalid-token"
        for key in ("uuid", "numeric_id", "email", "token", "identifier"):
            if buckets.get(key):
                return buckets[key][0]
        return "1"

    async def _probe_candidate(self, target: str, endpoint: str, parameter: str, param_type: str, value: str, headers_a: dict[str, str], headers_b: dict[str, str]) -> Finding | None:
        base_url = endpoint if endpoint.startswith("http://") or endpoint.startswith("https://") else f"https://{target}{endpoint}"
        probe_url = _set_query(base_url, parameter, value)
        async with self.semaphore:
            response_a = await request_http_async("GET", probe_url, headers=headers_a, timeout=self.timeout)
            response_b = await request_http_async("GET", probe_url, headers=headers_b, timeout=self.timeout)

        status_a = int(response_a.get("status", 0) or 0)
        status_b = int(response_b.get("status", 0) or 0)
        text_a = str(response_a.get("text", ""))
        text_b = str(response_b.get("text", ""))
        struct_similarity = _semantic_structure_similarity(text_a, text_b)
        if status_a != status_b or struct_similarity < self.min_similarity:
            return None
        if status_a not in {200, 201, 202, 204}:
            return None

        keys_a = json_keys(text_a)
        keys_b = json_keys(text_b)
        sensitive_markers = []
        lower_payload = f"{text_a}\n{text_b}".lower()
        for marker in ("email", "cpf", "phone", "address", "account", "wallet", "invoice"):
            if marker in lower_payload:
                sensitive_markers.append(marker)

        body_hash_a = hashlib.sha256(text_a.encode("utf-8", errors="ignore")).hexdigest()
        body_hash_b = hashlib.sha256(text_b.encode("utf-8", errors="ignore")).hexdigest()
        diff_map = {
            "status_a": status_a,
            "status_b": status_b,
            "status_equal": status_a == status_b,
            "length_a": int(response_a.get("length", 0) or 0),
            "length_b": int(response_b.get("length", 0) or 0),
            "length_delta": abs(int(response_a.get("length", 0) or 0) - int(response_b.get("length", 0) or 0)),
            "json_keys_a": keys_a,
            "json_keys_b": keys_b,
            "json_key_overlap": len(set(keys_a) & set(keys_b)),
            "structure_similarity_pct": struct_similarity,
            "body_hash_a": body_hash_a,
            "body_hash_b": body_hash_b,
            "body_equal": body_hash_a == body_hash_b,
        }

        confidence = 92.0 if sensitive_markers else 88.0
        return Finding(
            plugin="differential_auth_prover",
            target=target,
            category="critical_idor_vulnerability",
            severity="critical",
            title=f"Cross-context access consistency anomaly on {endpoint} ({parameter})",
            evidence={
                "request_auth_a": {"method": "GET", "url": probe_url, "headers": headers_a},
                "response_auth_a": {
                    "status": status_a,
                    "length": int(response_a.get("length", 0) or 0),
                    "headers": response_a.get("headers", {}),
                    "body": text_a,
                },
                "request_auth_b": {"method": "GET", "url": probe_url, "headers": headers_b},
                "response_auth_b": {
                    "status": status_b,
                    "length": int(response_b.get("length", 0) or 0),
                    "headers": response_b.get("headers", {}),
                    "body": text_b,
                },
                "diff_map": diff_map,
                "tested_parameter": parameter,
                "tested_value": value,
                "param_type": param_type,
                "sensitive_field_indicators": sorted(set(sensitive_markers)),
                "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "discovery_source": "differential_auth_prover",
            },
            metadata={
                "novelty": 93,
                "confidence": confidence,
                "confidence_score": confidence,
                "impact": 95,
                "discovery_source": "differential_auth_prover",
                "auth_context_a": self.auth_context_a,
                "auth_context_b": self.auth_context_b,
                "structure_similarity_pct": struct_similarity,
                "status_match": True,
            },
        )

    async def run(self, target: str, run_id: str, findings: list[Finding], storage: PostgresStorage | None) -> list[Finding]:
        sessions = load_sessions(self.sessions_file)
        session_a = sessions.get(self.auth_context_a, {})
        session_b = sessions.get(self.auth_context_b, {})
        headers_a = auth_header(session_a) if session_a else {}
        headers_b = auth_header(session_b) if session_b else {}
        if not headers_a or not headers_b:
            return []

        candidates = self._candidate_rows(findings=findings, storage=storage, run_id=run_id)
        if not candidates:
            return []

        entities = storage.list_recent_entities(target=target, limit=self.max_entities) if storage else []
        buckets = self._entity_buckets(entities)
        probes = []
        for cand in candidates[: self.max_candidates]:
            endpoint = str(cand.get("endpoint", ""))
            parameter = str(cand.get("parameter", ""))
            param_type = str(cand.get("param_type", self._infer_param_type(parameter)))
            if not endpoint or not parameter:
                continue
            val = self._pick_value(param_type=param_type, buckets=buckets)
            probes.append(
                self._probe_candidate(
                    target=target,
                    endpoint=endpoint,
                    parameter=parameter,
                    param_type=param_type,
                    value=val,
                    headers_a=headers_a,
                    headers_b=headers_b,
                )
            )
        if not probes:
            return []
        results = await asyncio.gather(*probes, return_exceptions=False)
        out: list[Finding] = []
        for item in results:
            if isinstance(item, Finding):
                out.append(item)
        return out


class ResearchScheduler:
    def __init__(self, plugins: dict[str, Any], context: dict[str, Any], state: ResearchState) -> None:
        self.plugins = plugins
        self.context = context
        self.state = state
        runtime = context["runtime"]
        self.rate = AsyncRateLimiter(float(runtime["rate_limit_per_sec"]))
        self._base_concurrency = max(1, int(runtime["concurrency"]))
        self._active_concurrency = self._base_concurrency
        self.semaphore = asyncio.Semaphore(self._active_concurrency)
        self.max_retries = int(runtime["max_retries"])
        self.backoff = float(runtime["backoff_base_seconds"])
        self.logger = context["logger"]
        self.target_rps: dict[str, float] = context.get("target_rps", {}) if isinstance(context.get("target_rps"), dict) else {}
        self._target_next_allowed: dict[str, float] = {}
        self._target_penalty_until: dict[str, float] = {}
        self._target_lock = asyncio.Lock()
        self.feedback_base_delay = float(runtime.get("feedback_base_delay_seconds", 1.2))
        self.feedback_max_delay = float(runtime.get("feedback_max_delay_seconds", 25.0))
        self.feedback_max_retries = int(runtime.get("feedback_max_retries", 2))
        self._feedback_counts: dict[str, int] = {}
        self._feedback_streak: dict[str, int] = {}
        self.feedback_streak_threshold = int(runtime.get("feedback_streak_threshold", 3))
        self.feedback_hard_pause_seconds = float(runtime.get("feedback_hard_pause_seconds", 60.0))
        user_agents = runtime.get("user_agents", [])
        if not isinstance(user_agents, list) or not user_agents:
            user_agents = [
                "Mozilla/5.0 (compatible; Pinguinho/1.0; +https://hunterops.local)",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/121.0",
            ]
        self.user_agents = [str(x).strip() for x in user_agents if str(x).strip()]
        self.proxies = [str(x).strip() for x in runtime.get("proxies", [])] if isinstance(runtime.get("proxies"), list) else []
        self._ua_idx: dict[str, int] = {}
        self._proxy_idx: dict[str, int] = {}

    async def _wait_target_budget(self, target: str) -> None:
        rps = float(self.target_rps.get(target, 0) or 0)
        interval = 0.0 if rps <= 0 else 1.0 / max(0.1, rps)
        async with self._target_lock:
            now = time.monotonic()
            next_allowed = float(self._target_next_allowed.get(target, now + interval))
            penalty_until = float(self._target_penalty_until.get(target, now))
            if penalty_until > next_allowed:
                next_allowed = penalty_until
            if next_allowed > now:
                await asyncio.sleep(next_allowed - now)
                now = time.monotonic()
            self._target_next_allowed[target] = now + interval

    def register_feedback(self, target: str, status_code: int) -> None:
        if int(status_code) not in {403, 429}:
            self.clear_feedback(target)
            return
        count = int(self._feedback_counts.get(target, 0) or 0) + 1
        self._feedback_counts[target] = count
        streak = int(self._feedback_streak.get(target, 0) or 0) + 1
        self._feedback_streak[target] = streak
        status_factor = 2.0 if int(status_code) == 429 else 1.3
        cooldown = min(self.feedback_max_delay, self.feedback_base_delay * status_factor * max(1.0, float(count)))
        until = time.monotonic() + cooldown
        prev = float(self._target_penalty_until.get(target, 0.0))
        penalty_until = max(prev, until)
        if streak > self.feedback_streak_threshold:
            penalty_until = max(penalty_until, time.monotonic() + self.feedback_hard_pause_seconds)
            new_concurrency = max(1, int(self._active_concurrency / 2))
            if new_concurrency < self._active_concurrency:
                self._active_concurrency = new_concurrency
                self.semaphore = asyncio.Semaphore(self._active_concurrency)
                self.logger.warning(
                    f"adaptive_concurrency_reduced target={target} active={self._active_concurrency} hard_pause={int(self.feedback_hard_pause_seconds)}s"
                )
        self._target_penalty_until[target] = penalty_until
        self.logger.warning(f"adaptive_backoff_applied target={target} status={status_code} cooldown={round(cooldown, 2)}")

    def clear_feedback(self, target: str) -> None:
        self._feedback_counts[target] = 0
        self._feedback_streak[target] = 0

    def target_delay_remaining(self, target: str) -> float:
        now = time.monotonic()
        return max(0.0, float(self._target_penalty_until.get(target, now)) - now)

    def next_user_agent(self, target: str) -> str:
        if not self.user_agents:
            return ""
        idx = int(self._ua_idx.get(target, 0) or 0)
        value = self.user_agents[idx % len(self.user_agents)]
        self._ua_idx[target] = (idx + 1) % len(self.user_agents)
        return value

    def next_proxy(self, target: str) -> str:
        if not self.proxies:
            return ""
        idx = int(self._proxy_idx.get(target, 0) or 0)
        value = self.proxies[idx % len(self.proxies)]
        self._proxy_idx[target] = (idx + 1) % len(self.proxies)
        return value

    async def run_task(self, task: Task) -> list[Finding]:
        filtered = self.state.filter_task(task)
        if filtered is None:
            return []
        if filtered.plugin not in self.plugins:
            self.logger.warning(f"plugin_not_loaded={filtered.plugin}")
            return []
        plugin = self.plugins[filtered.plugin]
        await self.rate.wait()
        await self._wait_target_budget(filtered.target)
        async with self.semaphore:
            async def invoke() -> list[Finding]:
                return await plugin.run(filtered, self.context)

            try:
                findings = await retry_async(invoke, retries=self.max_retries, base_delay=self.backoff)
                findings = plugin.normalize_findings(findings, filtered)
            except Exception as err:
                self.logger.error(f"pipeline_task_failed plugin={filtered.plugin} target={filtered.target} err={err}")
                return []
            for ep in _task_endpoints(filtered):
                self.state.mark_scanned(filtered.plugin, filtered.target, ep)
            return findings

    async def run_batch(self, tasks: list[Task]) -> list[Finding]:
        if not tasks:
            return []
        groups = await asyncio.gather(*(self.run_task(t) for t in tasks), return_exceptions=False)
        out: list[Finding] = []
        for g in groups:
            out.extend(g)
        return out


def persist_outputs(out_dir: Path, target_label: str, rows: list[dict[str, Any]]) -> None:
    export_json(out_dir / "findings.json", rows)
    export_csv(out_dir / "findings.csv", rows)
    export_markdown(out_dir / "findings.md", rows, target_label)
    export_html(out_dir / "findings.html", rows, target_label)
    export_dashboard(out_dir / "dashboard.html", rows)
    (out_dir / "findings.jsonl").write_text(to_jsonl(rows), encoding="utf-8")


def print_research_summary_table(rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    headers = ["Severity", "Plugin", "Endpoint", "Confidence", "Report_Path"]
    try:
        from rich.console import Console
        from rich.table import Table

        table = Table(title="HunterOps Research Summary")
        for h in headers:
            table.add_column(h)
        for row in rows:
            table.add_row(
                str(row.get("severity", "")),
                str(row.get("plugin", "")),
                str(row.get("endpoint", "")),
                str(row.get("confidence", "")),
                str(row.get("report_path", "")),
            )
        Console().print(table)
        return
    except Exception:
        pass
    try:
        from tabulate import tabulate

        lines = [
            [
                str(row.get("severity", "")),
                str(row.get("plugin", "")),
                str(row.get("endpoint", "")),
                str(row.get("confidence", "")),
                str(row.get("report_path", "")),
            ]
            for row in rows
        ]
        print(tabulate(lines, headers=headers, tablefmt="github"))
        return
    except Exception:
        pass

    # Fallback plain table.
    col_sizes = {
        "Severity": max(len("Severity"), max(len(str(r.get("severity", ""))) for r in rows)),
        "Plugin": max(len("Plugin"), max(len(str(r.get("plugin", ""))) for r in rows)),
        "Endpoint": max(len("Endpoint"), max(len(str(r.get("endpoint", ""))) for r in rows)),
        "Confidence": max(len("Confidence"), max(len(str(r.get("confidence", ""))) for r in rows)),
        "Report_Path": max(len("Report_Path"), max(len(str(r.get("report_path", ""))) for r in rows)),
    }
    sep = " | "
    header_line = sep.join([h.ljust(col_sizes[h]) for h in headers])
    rule = "-+-".join(["-" * col_sizes[h] for h in headers])
    print(header_line)
    print(rule)
    for row in rows:
        print(
            sep.join(
                [
                    str(row.get("severity", "")).ljust(col_sizes["Severity"]),
                    str(row.get("plugin", "")).ljust(col_sizes["Plugin"]),
                    str(row.get("endpoint", "")).ljust(col_sizes["Endpoint"]),
                    str(row.get("confidence", "")).ljust(col_sizes["Confidence"]),
                    str(row.get("report_path", "")).ljust(col_sizes["Report_Path"]),
                ]
            )
        )


def generate_auto_poc(out_dir: Path, findings: list[Finding], min_confidence: float = 80.0) -> None:
    poc_dir = out_dir / "auto_poc"
    poc_dir.mkdir(parents=True, exist_ok=True)
    index: list[dict[str, Any]] = []
    for i, f in enumerate(findings, start=1):
        meta = f.metadata if isinstance(f.metadata, dict) else {}
        conf = float(meta.get("confidence_score", meta.get("confidence", 0)) or 0)
        if conf < min_confidence:
            continue
        ev = f.evidence if isinstance(f.evidence, dict) else {}
        req = ev.get("request", {}) if isinstance(ev.get("request"), dict) else {}
        req_a = ev.get("request_auth_a", {}) if isinstance(ev.get("request_auth_a"), dict) else {}
        req_b = ev.get("request_auth_b", {}) if isinstance(ev.get("request_auth_b"), dict) else {}
        cat = f.category.lower()
        if "payment" in cat or "wallet" in cat or "invoice" in cat:
            impact = "Unauthorized Financial Transaction risk through broken business logic."
        elif "idor" in cat or "access" in cat:
            impact = "Massive Data Breach risk through unauthorized cross-account data access."
        elif "auth" in cat or "password" in cat or "session" in cat:
            impact = "Potential Account Takeover risk affecting user account integrity."
        else:
            impact = "Unauthorized Data Exposure risk with potential regulatory and trust impact."

        commands: list[str] = []
        md = [f"# PoC - {f.title}", "", f"- Target: {f.target}", f"- Category: {f.category}", f"- Confidence: {conf}", f"- Discovery Source: {meta.get('discovery_source', '')}", f"- Impact: {impact}", ""]
        if req_a and req_b:
            method_a = str(req_a.get("method", "GET")).upper()
            url_a = str(req_a.get("url", ""))
            headers_a = req_a.get("headers", {}) if isinstance(req_a.get("headers"), dict) else {}
            method_b = str(req_b.get("method", "GET")).upper()
            url_b = str(req_b.get("url", ""))
            headers_b = req_b.get("headers", {}) if isinstance(req_b.get("headers"), dict) else {}
            curl_a = f"curl -i -X {method_a} \"{url_a}\""
            curl_b = f"curl -i -X {method_b} \"{url_b}\""
            for hk, hv in headers_a.items():
                curl_a += f" -H \"{hk}: {hv}\""
            for hk, hv in headers_b.items():
                curl_b += f" -H \"{hk}: {hv}\""
            commands = [curl_a, curl_b]
            md.extend(
                [
                    "## Reproduction",
                    f"1. Execute request using Auth Context A: `{curl_a}`",
                    f"2. Replay the same request using Auth Context B: `{curl_b}`",
                    "3. Compare status/structure and confirm unauthorized cross-context consistency.",
                    "",
                ]
            )
        else:
            method = str(req.get("method", "GET")).upper()
            url = str(req.get("url", ev.get("modified_url", ev.get("base_url", ev.get("url", "")))))
            headers = req.get("headers", {}) if isinstance(req.get("headers"), dict) else {}
            curl = f"curl -i -X {method} \"{url}\""
            for hk, hv in headers.items():
                curl += f" -H \"{hk}: {hv}\""
            commands = [curl]
            md.extend(
                [
                    "## Reproduction",
                    f"1. Execute: `{curl}`",
                    "2. Observe response differences and sensitive indicators in evidence.",
                    "",
                ]
            )
        md_file = poc_dir / f"poc_{i:03d}.md"
        curl_file = poc_dir / f"poc_{i:03d}.sh"
        md_file.write_text("\n".join(md), encoding="utf-8")
        curl_file.write_text("\n".join(commands) + "\n", encoding="utf-8")
        index.append({"title": f.title, "target": f.target, "confidence": conf, "impact": impact, "markdown": str(md_file), "curl": str(curl_file), "commands": len(commands)})
    (poc_dir / "index.json").write_text(json.dumps({"count": len(index), "items": index}, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


async def run_async(args: argparse.Namespace) -> int:
    cfg = load_config(resolve_path(args.config))
    runtime = get_runtime(cfg)
    pool_cfg = cfg.get("http_pool", {}) if isinstance(cfg.get("http_pool"), dict) else {}
    configure_http_pool(
        max_connections=int(pool_cfg.get("max_connections", max(50, int(runtime.get("concurrency", 10)) * 12))),
        max_keepalive_connections=int(pool_cfg.get("max_keepalive_connections", max(20, int(runtime.get("concurrency", 10)) * 4))),
        keepalive_expiry=float(pool_cfg.get("keepalive_expiry", 10.0)),
        verify_ssl=bool(pool_cfg.get("verify_ssl", True)),
        http2=bool(pool_cfg.get("http2", False)),
        retries=int(pool_cfg.get("retries", 0)),
        linux_socket_tuning=bool(pool_cfg.get("linux_socket_tuning", True)),
    )
    ts = args.run_id.strip() or datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    out_dir = ensure_directory(resolve_path(args.out_dir), mode=0o755)
    logger = setup_logging(out_dir / f"research_{ts}.jsonl", verbose=args.verbose)
    discord = DiscordDispatch(cfg=cfg.get("modules", {}).get("discord_notifier", {}), logger=logger)
    alert_router = AlertRouter(cfg=cfg.get("modules", {}).get("alert_router", {}), logger=logger)
    attach_alert_router(logger, alert_router)

    async def _shutdown_clients() -> None:
        await discord.close()
        await alert_router.close()
        await close_async_http_client()

    if args.alert_dry_run:
        rc = await _run_alert_dry_run(
            alert_router=alert_router,
            out_dir=out_dir,
            run_id=ts,
            logger=logger,
        )
        await _shutdown_clients()
        return rc

    # Optional DB-backed state + persistence.
    storage: PostgresStorage | None = None
    pg_cfg = cfg.get("storage", {}).get("postgres", {})
    pg_enabled = bool(pg_cfg.get("enabled", False))
    dsn_env = str(pg_cfg.get("dsn_env", "HUNTEROPS_POSTGRES_DSN"))
    dsn = os.getenv(dsn_env, "")
    if pg_enabled and dsn:
        try:
            storage = PostgresStorage(dsn=dsn, enabled=True)
            storage.ensure_research_schema()
        except Exception as err:
            logger.error(f"research_storage_init_failed err={err}")
            storage = None

    h1_sync_engine = HackerOneSyncEngine(
        cfg=cfg.get("modules", {}).get("hackerone_sync_engine", {}),
        logger=logger,
        storage=storage,
        targets_file=args.targets_file,
    )
    if h1_sync_engine.enabled:
        try:
            preflight = h1_sync_engine.sync(run_id=ts, timeout=int(runtime.get("timeout_seconds", 25)))
            if preflight.get("enabled", False):
                targets_added = ((preflight.get("targets_file", {}) or {}).get("added_count", 0))
                logger.info(
                    "h1_preflight_sync "
                    f"api_called={preflight.get('api_called', False)} "
                    f"cache={preflight.get('used_cache', False)} "
                    f"domains={preflight.get('domains_total', 0)} "
                    f"added_targets={targets_added}"
                )
            else:
                logger.warning(f"h1_preflight_sync_skipped reason={preflight.get('reason', 'unknown')}")
                if h1_sync_engine.strict_sync:
                    await _shutdown_clients()
                    return 5
        except Exception as err:
            logger.error(f"h1_preflight_sync_failed err={err}")
            if h1_sync_engine.strict_sync:
                await _shutdown_clients()
                return 5

    targets = collect_targets(args)
    if not targets:
        logger.error("no_targets_provided")
        await _shutdown_clients()
        return 2

    h1_manager = HackerOneManager(cfg=cfg.get("modules", {}).get("hackerone_manager", {}), logger=logger)
    h1_scope_added: set[str] = set()
    if h1_manager.enabled:
        try:
            scope_state = h1_manager.watch_scope_updates(timeout=int(runtime.get("timeout_seconds", 25)))
            scope_hosts = sorted(list(h1_manager.current_scope_hosts()))
            if scope_hosts:
                targets = sorted(list(set(targets) | set(scope_hosts)))
            targets = h1_manager.filter_targets(targets)
            h1_scope_added = {str(x).strip().lower() for x in scope_state.get("added_hosts", []) if str(x).strip()}
            logger.info(f"h1_scope_sync enabled={scope_state.get('enabled', False)} targets={len(targets)} added={len(h1_scope_added)}")
        except Exception as err:
            logger.error(f"h1_scope_sync_failed err={err}")
            if h1_manager.strict_scope:
                await _shutdown_clients()
                return 5
    if not targets:
        logger.error("no_in_scope_targets_after_hackerone_sync")
        await _shutdown_clients()
        return 2

    if args.plugins.strip():
        plugin_names = [x.strip().lower() for x in args.plugins.split(",") if x.strip()]
    else:
        plugin_names = [
            "deep_js_intelligence",
            "parameter_intelligence",
            "business_logic_sniper",
            "race_condition_turbo",
            "differential_auth_prover",
            "vulnerability_correlation_engine",
            "logic_prover",
            "auth_matrix_engine",
            "entity_cross_pollinator",
            "report_synthesis",
            "evidence_packager",
        ]
    dep_report = evaluate_runtime_dependencies(cfg, plugin_names)
    for msg in dep_report["critical_warnings"]:
        logger.critical(msg)
    plugin_names = filter_enabled_plugins(plugin_names, dep_report["disabled_plugins"])
    if not plugin_names:
        logger.error("no_runnable_plugins_after_dependency_checks")
        await _shutdown_clients()
        return 6
    await discord.send_system_online(run_id=ts, targets_count=len(targets), plugins_count=len(plugin_names))
    plugins = load_plugins(plugin_names)
    target_rps_map: dict[str, float] = {}
    if h1_manager.enabled:
        for target in targets:
            target_rps_map[target] = h1_manager.target_rps(target)
    context = {"config": cfg, "runtime": runtime, "logger": logger, "target_rps": target_rps_map}
    ade_brain = ADEBrainPlugin()
    report_engine = ReportEngine(
        cfg=cfg.get("modules", {}).get("report_engine", {}),
        logger=logger,
        storage=storage,
    )

    state = ResearchState(run_id=ts, storage=storage)
    scheduler = ResearchScheduler(plugins=plugins, context=context, state=state)
    packs = load_program_packs(resolve_path(cfg.get("program_packs", {}).get("file", "config/program_packs.yaml")))
    reactions = ReactionLogic()
    delta_monitor = DeltaMonitor(storage=storage)
    logic_chaining = LogicChainingEngine()
    oob_engine = OOBEngine(cfg=cfg.get("modules", {}).get("oob_engine", {}), runtime=runtime, logger=logger)
    available_plugins = set(plugins.keys())
    recursion_max_depth = int(runtime.get("recursion_max_depth", 2))
    max_tasks_per_target = max(20, int(runtime.get("max_tasks_per_target", 1200)))
    queue_engine = HighValuePriorityQueue(max_size=int(runtime.get("task_queue_size", 4000)))
    wave_size = max(1, int(runtime.get("concurrency", 10)) * 2)

    all_findings: list[Finding] = []
    notified_logic_signals: set[str] = set()
    notified_report_paths: set[str] = set()
    for target in targets:
        if h1_manager.enabled and not h1_manager.in_scope(target):
            logger.warning(f"skip_out_of_scope_target target={target}")
            continue
        pack = resolve_pack(target, packs)
        initial_priority = 100 if str(target).strip().lower() in h1_scope_added else 70
        pending: list[Task] = [
            Task(
                plugin="deep_js_intelligence",
                target=target,
                payload={
                    "run_id": ts,
                    "program_pack": pack or {},
                    "_depth": 0,
                    "priority": initial_priority,
                    "priority_score": initial_priority,
                    "trigger": "h1_scope_update" if initial_priority == 100 else "initial_seed",
                },
            )
        ]
        pending = queue_engine.rank(pending, findings=[])
        target_history: list[Finding] = []
        rounds = 0
        processed_tasks = 0
        max_rounds = max(4, int(runtime.get("max_rounds_per_target", 6)))
        while pending and rounds < max_rounds and processed_tasks < max_tasks_per_target:
            rounds += 1
            budget_left = max_tasks_per_target - processed_tasks
            if budget_left <= 0:
                break
            wave_take = min(wave_size, budget_left)
            current_wave = pending[:wave_take]
            pending = pending[wave_take:]
            processed_tasks += len(current_wave)
            batch = await scheduler.run_batch(current_wave)
            if oob_engine.available and batch:
                try:
                    await oob_engine.inject_from_findings(
                        target=target,
                        run_id=ts,
                        findings=batch,
                        rate_limiter=scheduler.rate,
                        target_waiter=scheduler._wait_target_budget,
                    )
                    oob_hits = await oob_engine.poll_and_correlate()
                    if oob_hits:
                        batch.extend([x for x in oob_hits if x.target == target])
                except Exception as err:
                    logger.error(f"oob_engine_cycle_failed target={target} round={rounds} err={err}")
            batch = dedupe_findings(batch)
            try:
                ade_task = Task(
                    plugin="ade_brain",
                    target=target,
                    payload={
                        "run_id": ts,
                        "_depth": 0,
                        "round_findings": serialize_findings(batch),
                    },
                )
                ade_findings = await ade_brain.run(ade_task, context)
                ade_findings = ade_brain.normalize_findings(ade_findings, ade_task)
                if ade_findings:
                    batch.extend(ade_findings)
                    batch = dedupe_findings(batch)
            except Exception as err:
                logger.error(f"ade_brain_round_failed target={target} round={rounds} err={err}")
            if "vulnerability_correlation_engine" in plugins and batch:
                try:
                    corr_plugin = plugins["vulnerability_correlation_engine"]
                    corr_task = Task(
                        plugin="vulnerability_correlation_engine",
                        target=target,
                        payload={
                            "run_id": ts,
                            "findings": serialize_findings(batch),
                        },
                    )
                    corr_findings = await corr_plugin.run(corr_task, context)
                    corr_findings = corr_plugin.normalize_findings(corr_findings, corr_task)
                    if corr_findings:
                        batch.extend(corr_findings)
                        batch = dedupe_findings(batch)
                except Exception as err:
                    logger.error(f"vulnerability_correlation_round_failed target={target} round={rounds} err={err}")
            report_findings = await _run_report_engine_if_high_critical(
                report_engine=report_engine,
                target=target,
                run_id=ts,
                round_findings=batch,
                logger=logger,
            )
            if report_findings:
                batch.extend(report_findings)
                batch = dedupe_findings(batch)
            all_findings.extend(batch)
            await _route_alerts_from_batch(
                alert_router=alert_router,
                batch=batch,
                run_id=ts,
                logger=logger,
                source="scan_round",
            )
            target_history.extend(batch)
            if len(target_history) > 1200:
                target_history = target_history[-1200:]
            feedback = _feedback_status_by_target(batch)
            if feedback:
                for fb_target, statuses in feedback.items():
                    for status_code in statuses:
                        scheduler.register_feedback(fb_target, int(status_code))
            wave_targets = {str(t.target).strip() for t in current_wave if str(t.target).strip()}
            for wave_target in wave_targets:
                if wave_target not in feedback:
                    scheduler.clear_feedback(wave_target)
            feedback_retry_tasks = _build_feedback_retry_tasks(
                current_wave=current_wave,
                feedback=feedback,
                scheduler=scheduler,
                run_id=ts,
                max_depth=recursion_max_depth,
            )
            if discord.available and batch:
                for finding in batch:
                    if not _is_logic_prover_confirmed(finding):
                        continue
                    meta = finding.metadata if isinstance(finding.metadata, dict) else {}
                    sig = str(meta.get("structural_hash", "")).strip() or f"{finding.target}|{finding.category}|{finding.title}"
                    if sig in notified_logic_signals:
                        continue
                    notified_logic_signals.add(sig)
                    discord.route_finding_confirmed(
                        target=finding.target,
                        title=finding.title,
                        impact=_finding_impact(finding),
                        confidence=_finding_confidence(finding),
                        endpoint=_finding_source_endpoint(finding),
                        evidence_snippet=_finding_evidence_snippet(finding),
                        report_path=str(meta.get("report_path", "pending_generation")),
                        severity_level=str(finding.severity),
                        estimated_payout=_estimated_payout_for_severity(str(finding.severity)),
                    )
            entity_rows: list[dict[str, Any]] = []
            if storage and batch:
                try:
                    entity_rows = extract_entity_rows(batch, target=target)
                    if entity_rows:
                        storage.upsert_discovered_entities(run_id=ts, target=target, rows=entity_rows)
                except Exception as err:
                    logger.error(f"research_entity_pool_upsert_failed target={target} round={rounds} err={err}")
            if storage and batch:
                try:
                    storage.write_findings(run_id=ts, rows=serialize_findings(batch))
                except Exception as err:
                    logger.error(f"research_write_batch_failed target={target} round={rounds} err={err}")

            delta = delta_monitor.compare(target=target, run_id=ts, current_findings=batch)
            if discord.available and (
                delta.get("new_endpoints")
                or delta.get("changed_js")
                or delta.get("new_parameters")
            ):
                discord.route_recon_delta(
                    target=target,
                    delta_score=_delta_score(delta),
                    new_endpoints=[str(x) for x in delta.get("new_endpoints", []) if isinstance(x, str)],
                    changed_js=[str(x) for x in delta.get("changed_js", []) if isinstance(x, str)],
                    new_parameters=[str(x) for x in delta.get("new_parameters", []) if isinstance(x, str)],
                )

            next_tasks: list[Task] = []
            next_tasks.extend(reactions.tasks_from_saved_findings(batch, run_id=ts, pack=pack))
            next_tasks.extend(
                delta_monitor.build_priority_tasks(
                    target=target,
                    run_id=ts,
                    pack=pack,
                    current_findings=batch,
                    available_plugins=available_plugins,
                    precomputed_delta=delta,
                )
            )
            next_tasks.extend(logic_chaining.build_tasks(batch, run_id=ts, pack=pack, available_plugins=available_plugins))
            next_tasks.extend(feedback_retry_tasks)
            next_tasks.extend(_spawn_tasks_from_findings(batch, max_depth=recursion_max_depth))
            if "logic_prover" in available_plugins:
                logic_paths: set[str] = set()
                for finding in batch:
                    if finding.category in {
                        "js_discovery",
                        "parameter_intelligence",
                        "object_leakage_indicator",
                        "critical_idor_vulnerability",
                        "Potential_IDOR_Signal",
                        "Broken_Object_Level_Authorization",
                    }:
                        logic_paths.add(_normalize_endpoint_key(_finding_source_endpoint(finding)))
                if logic_paths:
                    next_tasks.append(
                        Task(
                            plugin="logic_prover",
                            target=target,
                            payload={
                                "run_id": ts,
                                "seed_paths": sorted(list(logic_paths))[:120],
                                "_depth": 0,
                                "trigger": "decision_brain",
                                "priority": 95,
                                "priority_score": 95,
                            },
                        )
                    )
            if "auth_matrix_engine" in available_plugins:
                matrix_paths: set[str] = set()
                for finding in batch:
                    if finding.category in {
                        "js_discovery",
                        "parameter_intelligence",
                        "object_leakage_indicator",
                        "Potential_IDOR_Signal",
                        "Broken_Object_Level_Authorization",
                        "broken_access_control_matrix_signal",
                    }:
                        matrix_paths.add(_normalize_endpoint_key(_finding_source_endpoint(finding)))
                if matrix_paths:
                    next_tasks.append(
                        Task(
                            plugin="auth_matrix_engine",
                            target=target,
                            payload={
                                "run_id": ts,
                                "seed_paths": sorted(list(matrix_paths))[:140],
                                "_depth": 0,
                                "trigger": "auth_matrix_expand",
                                "priority": 98,
                                "priority_score": 98,
                            },
                        )
                    )
            if entity_rows and "entity_cross_pollinator" in available_plugins:
                next_tasks.append(
                    Task(
                        plugin="entity_cross_pollinator",
                        target=target,
                        payload={
                            "run_id": ts,
                            "trigger": "entity_pool_update",
                            "_depth": 0,
                            "seed_paths": [f"/__entity_pool_round_{rounds}"],
                        },
                    )
                )
            # de-duplicate follow-up tasks
            seen: set[str] = set()
            deduped: list[Task] = []
            for t in next_tasks:
                sig = f"{t.plugin}|{t.target}|{json.dumps(t.payload, sort_keys=True, ensure_ascii=True) if isinstance(t.payload, dict) else ''}"
                if sig in seen:
                    continue
                seen.add(sig)
                deduped.append(t)
            pending = queue_engine.rank(pending + deduped, findings=target_history)
        if processed_tasks >= max_tasks_per_target:
            logger.warning(
                f"target_task_budget_reached target={target} processed_tasks={processed_tasks} limit={max_tasks_per_target}"
            )

    all_findings = dedupe_findings(all_findings)

    synthesized_findings: list[Finding] = []
    if "report_synthesis" in plugins:
        synth_plugin = plugins["report_synthesis"]
        serialized = serialize_findings(all_findings)
        if h1_manager.enabled:
            try:
                known_endpoints = h1_manager.fetch_known_report_endpoints(timeout=int(runtime.get("timeout_seconds", 25)))
                serialized = h1_manager.suppress_probable_duplicates(serialized, known_endpoints)
            except Exception as err:
                logger.error(f"h1_duplicate_prevention_failed err={err}")
        synth_jobs = []
        for target in targets:
            target_rows = [row for row in serialized if str(row.get("target", "")) == target]
            synth_jobs.append(
                synth_plugin.run(
                    Task(
                        plugin="report_synthesis",
                        target=target,
                        payload={
                            "run_id": ts,
                            "findings": target_rows,
                        },
                    ),
                    context,
                )
            )
        synth_groups = await asyncio.gather(*synth_jobs, return_exceptions=False)
        for grp in synth_groups:
            synthesized_findings.extend(grp)
        synthesized_findings = dedupe_findings(synthesized_findings)
        if synthesized_findings:
            all_findings.extend(synthesized_findings)
            await _route_alerts_from_batch(
                alert_router=alert_router,
                batch=synthesized_findings,
                run_id=ts,
                logger=logger,
                source="report_synthesis",
            )
            if storage:
                try:
                    storage.write_findings(run_id=ts, rows=serialize_findings(synthesized_findings))
                except Exception as err:
                    logger.error(f"research_write_synthesized_findings_failed err={err}")

    packaged_findings: list[Finding] = []
    if "evidence_packager" in plugins:
        packager_plugin = plugins["evidence_packager"]
        package_jobs = []
        serialized_all = serialize_findings(all_findings)
        for target in targets:
            target_rows = [row for row in serialized_all if str(row.get("target", "")) == target]
            package_jobs.append(
                packager_plugin.run(
                    Task(
                        plugin="evidence_packager",
                        target=target,
                        payload={
                            "run_id": ts,
                            "findings": target_rows,
                        },
                    ),
                    context,
                )
            )
        package_groups = await asyncio.gather(*package_jobs, return_exceptions=False)
        for group in package_groups:
            packaged_findings.extend(group)
        packaged_findings = dedupe_findings(packaged_findings)
        if packaged_findings:
            all_findings.extend(packaged_findings)
            await _route_alerts_from_batch(
                alert_router=alert_router,
                batch=packaged_findings,
                run_id=ts,
                logger=logger,
                source="evidence_packager",
            )
            if storage:
                try:
                    storage.write_findings(run_id=ts, rows=serialize_findings(packaged_findings))
                except Exception as err:
                    logger.error(f"research_write_packaged_findings_failed err={err}")
            if discord.available:
                for finding in packaged_findings:
                    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
                    source_category = str(evidence.get("category", "")).strip()
                    confidence = float(evidence.get("confidence_score", 0) or 0)
                    report_path = str(evidence.get("report_path", "")).strip()
                    if source_category not in {"Potential_IDOR_Signal", "Broken_Object_Level_Authorization"}:
                        continue
                    if confidence <= 50:
                        continue
                    if report_path and report_path in notified_report_paths:
                        continue
                    if report_path:
                        notified_report_paths.add(report_path)
                    discord.route_finding_confirmed(
                        target=finding.target,
                        title=str(finding.title),
                        impact=str(evidence.get("impact", _finding_impact(finding))),
                        confidence=confidence,
                        endpoint=str(evidence.get("endpoint", "/")),
                        evidence_snippet=f"bundle={source_category} confidence={confidence}",
                        report_path=report_path or "pending_generation",
                        severity_level=str(finding.severity),
                        estimated_payout=_estimated_payout_for_severity(str(finding.severity)),
                    )

    all_findings = dedupe_findings(all_findings)
    rows = serialize_findings(all_findings)
    persist_outputs(out_dir, f"{len(targets)}-targets", rows)
    generate_auto_poc(out_dir=out_dir, findings=all_findings, min_confidence=80.0)
    generate_research_artifacts(
        findings=all_findings,
        out_root=resolve_path("data/reports"),
        run_id=ts,
        min_confidence=85.0,
    )

    summary_rows: list[dict[str, Any]] = []
    for f in synthesized_findings + packaged_findings:
        meta = f.metadata if isinstance(f.metadata, dict) else {}
        ev = f.evidence if isinstance(f.evidence, dict) else {}
        report_path = str(meta.get("report_path", ev.get("report_path", "")))
        if not report_path:
            continue
        summary_rows.append(
            {
                "severity": f.severity,
                "plugin": str(meta.get("plugin_source", f.plugin)),
                "endpoint": str(meta.get("endpoint", ev.get("endpoint", ""))),
                "confidence": float(meta.get("confidence_score", meta.get("confidence", 0)) or 0),
                "report_path": report_path,
            }
        )
    if summary_rows:
        print_research_summary_table(summary_rows)

    logger.info(f"research_pipeline_completed run_id={ts} findings={len(rows)}")
    await _shutdown_clients()
    return 0


def main() -> int:
    args = parse_args()
    install_uvloop_if_available()
    try:
        return asyncio.run(run_async(args))
    except KeyboardInterrupt:
        return 130
    except Exception as err:
        print(f"[fatal] research_pipeline error: {err}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
