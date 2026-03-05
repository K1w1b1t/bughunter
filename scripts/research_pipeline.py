#!/usr/bin/env python3
"""Autonomous research pipeline for HunterOps (incremental, non-core orchestration)."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from hunterops.config import get_runtime, load_config
from hunterops.evidence_generator import generate_research_artifacts
from hunterops.hackerone_manager import HackerOneManager
from hunterops.http_client import json_keys, request_http_async
from hunterops.intelligence import dedupe_findings, serialize_findings, to_jsonl
from hunterops.logging_utils import setup_logging
from hunterops.oob_engine import OOBEngine
from hunterops.plugin_loader import load_plugins
from hunterops.program_packs import load_program_packs, resolve_pack
from hunterops.rate_limit import AsyncRateLimiter
from hunterops.reporting import export_csv, export_dashboard, export_html, export_json, export_markdown
from hunterops.retry import retry_async
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
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def collect_targets(args: argparse.Namespace) -> list[str]:
    if args.target:
        return [args.target.strip()]
    p = Path(args.targets_file)
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

    def compare(self, target: str, run_id: str, current_findings: list[Finding]) -> dict[str, Any]:
        if not self.storage:
            return {"new_endpoints": [], "changed_js": []}
        try:
            prev_run = self.storage.get_previous_run_id(target=target, current_run_id=run_id)
            if not prev_run:
                return {"new_endpoints": [], "changed_js": []}
            prev_rows = self.storage.fetch_run_findings(run_id=prev_run, target=target)
        except Exception:
            return {"new_endpoints": [], "changed_js": []}

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

        new_eps = sorted(list(curr_eps - prev_eps))
        changed_js = sorted([u for u, h in curr_js.items() if u in prev_js and prev_js[u] != h])
        return {"new_endpoints": new_eps, "changed_js": changed_js}

    def build_priority_tasks(
        self,
        target: str,
        run_id: str,
        pack: dict[str, Any] | None,
        current_findings: list[Finding],
        available_plugins: set[str],
    ) -> list[Task]:
        delta = self.compare(target=target, run_id=run_id, current_findings=current_findings)
        if not delta["new_endpoints"] and not delta["changed_js"]:
            return []
        deep_paths: set[str] = set(delta["new_endpoints"])
        for jsu in delta["changed_js"]:
            deep_paths.add(urlparse(jsu).path or "/")

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
        self.semaphore = asyncio.Semaphore(int(runtime["concurrency"]))
        self.max_retries = int(runtime["max_retries"])
        self.backoff = float(runtime["backoff_base_seconds"])
        self.logger = context["logger"]
        self.target_rps: dict[str, float] = context.get("target_rps", {}) if isinstance(context.get("target_rps"), dict) else {}
        self._target_next_allowed: dict[str, float] = {}
        self._target_lock = asyncio.Lock()

    async def _wait_target_budget(self, target: str) -> None:
        rps = float(self.target_rps.get(target, 0) or 0)
        if rps <= 0:
            return
        interval = 1.0 / max(0.1, rps)
        async with self._target_lock:
            now = time.monotonic()
            next_allowed = float(self._target_next_allowed.get(target, now))
            if next_allowed > now:
                await asyncio.sleep(next_allowed - now)
                now = time.monotonic()
            self._target_next_allowed[target] = now + interval

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
    cfg = load_config(Path(args.config))
    runtime = get_runtime(cfg)
    ts = args.run_id.strip() or datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    logger = setup_logging(out_dir / f"research_{ts}.jsonl", verbose=args.verbose)

    targets = collect_targets(args)
    if not targets:
        logger.error("no_targets_provided")
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
                return 5
    if not targets:
        logger.error("no_in_scope_targets_after_hackerone_sync")
        return 2

    if args.plugins.strip():
        plugin_names = [x.strip() for x in args.plugins.split(",") if x.strip()]
    else:
        plugin_names = [
            "deep_js_intelligence",
            "parameter_intelligence",
            "differential_auth_prover",
            "entity_cross_pollinator",
            "report_synthesis",
        ]
    plugins = load_plugins(plugin_names)
    target_rps_map: dict[str, float] = {}
    if h1_manager.enabled:
        for target in targets:
            target_rps_map[target] = h1_manager.target_rps(target)
    context = {"config": cfg, "runtime": runtime, "logger": logger, "target_rps": target_rps_map}

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

    state = ResearchState(run_id=ts, storage=storage)
    scheduler = ResearchScheduler(plugins=plugins, context=context, state=state)
    packs = load_program_packs(Path(cfg.get("program_packs", {}).get("file", "config/program_packs.yaml")))
    reactions = ReactionLogic()
    delta_monitor = DeltaMonitor(storage=storage)
    logic_chaining = LogicChainingEngine()
    oob_engine = OOBEngine(cfg=cfg.get("modules", {}).get("oob_engine", {}), runtime=runtime, logger=logger)
    available_plugins = set(plugins.keys())
    recursion_max_depth = int(runtime.get("recursion_max_depth", 2))

    all_findings: list[Finding] = []
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
        rounds = 0
        max_rounds = 4
        while pending and rounds < max_rounds:
            rounds += 1
            batch = await scheduler.run_batch(pending)
            if oob_engine.available and batch:
                try:
                    await oob_engine.inject_from_findings(target=target, run_id=ts, findings=batch)
                    oob_hits = await oob_engine.poll_and_correlate()
                    if oob_hits:
                        batch.extend([x for x in oob_hits if x.target == target])
                except Exception as err:
                    logger.error(f"oob_engine_cycle_failed target={target} round={rounds} err={err}")
            batch = dedupe_findings(batch)
            all_findings.extend(batch)
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

            next_tasks: list[Task] = []
            next_tasks.extend(reactions.tasks_from_saved_findings(batch, run_id=ts, pack=pack))
            next_tasks.extend(delta_monitor.build_priority_tasks(target=target, run_id=ts, pack=pack, current_findings=batch, available_plugins=available_plugins))
            next_tasks.extend(logic_chaining.build_tasks(batch, run_id=ts, pack=pack, available_plugins=available_plugins))
            next_tasks.extend(_spawn_tasks_from_findings(batch, max_depth=recursion_max_depth))
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
            pending = deduped

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
            if storage:
                try:
                    storage.write_findings(run_id=ts, rows=serialize_findings(synthesized_findings))
                except Exception as err:
                    logger.error(f"research_write_synthesized_findings_failed err={err}")

    all_findings = dedupe_findings(all_findings)
    rows = serialize_findings(all_findings)
    persist_outputs(out_dir, f"{len(targets)}-targets", rows)
    generate_auto_poc(out_dir=out_dir, findings=all_findings, min_confidence=80.0)
    generate_research_artifacts(
        findings=all_findings,
        out_root=Path("data/reports"),
        run_id=ts,
        min_confidence=85.0,
    )

    summary_rows: list[dict[str, Any]] = []
    for f in synthesized_findings:
        meta = f.metadata if isinstance(f.metadata, dict) else {}
        ev = f.evidence if isinstance(f.evidence, dict) else {}
        summary_rows.append(
            {
                "severity": f.severity,
                "plugin": str(meta.get("plugin_source", f.plugin)),
                "endpoint": str(meta.get("endpoint", ev.get("endpoint", ""))),
                "confidence": float(meta.get("confidence_score", meta.get("confidence", 0)) or 0),
                "report_path": str(meta.get("report_path", ev.get("report_path", ""))),
            }
        )
    if summary_rows:
        print_research_summary_table(summary_rows)

    logger.info(f"research_pipeline_completed run_id={ts} findings={len(rows)}")
    return 0


def main() -> int:
    args = parse_args()
    try:
        return asyncio.run(run_async(args))
    except KeyboardInterrupt:
        return 130
    except Exception as err:
        print(f"[fatal] research_pipeline error: {err}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
