from __future__ import annotations

import asyncio
import os
import re
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from hunterops.http_client import request_http_async
from hunterops.plugin_base import Plugin
from hunterops.session_profiles import auth_header, load_sessions
from hunterops.storage import PostgresStorage
from hunterops.types import Finding, Task

ID_PARAM_HINTS = ("id", "uid", "user_id", "account_id", "order_id", "invoice_id", "profile_id", "project_id")
EMAIL_PARAM_HINTS = ("email", "mail")
TOKEN_PARAM_HINTS = ("token", "jwt", "auth", "api_key", "key", "secret")
SENSITIVE_ENDPOINT_KEYWORDS = ("admin", "internal", "v1/debug", "config", "staging", "export", "graphiql")
EMAIL_RE = re.compile(r"""[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}""")
UUID_RE = re.compile(r"""\b[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\b""")
NUMERIC_ID_RE = re.compile(r"""\b[1-9][0-9]{2,18}\b""")


def _normalize_endpoint(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw.startswith("http://") or raw.startswith("https://"):
        return urlparse(raw).path or "/"
    if raw.startswith("/"):
        return raw
    return f"/{raw}"


def _infer_param_type(param_name: str) -> str:
    name = param_name.lower()
    if any(h in name for h in EMAIL_PARAM_HINTS):
        return "email"
    if any(h in name for h in TOKEN_PARAM_HINTS):
        return "token"
    if any(h in name for h in ID_PARAM_HINTS):
        return "numeric_id"
    return "string"


def _inject_query(endpoint: str, param_name: str, value: str) -> str:
    raw = endpoint.strip()
    if not raw:
        return ""
    is_abs = raw.startswith("http://") or raw.startswith("https://")
    normalized = raw if is_abs else (raw if raw.startswith("/") else f"/{raw}")
    parsed = urlparse(normalized if is_abs else f"https://placeholder.local{normalized}")
    q = parse_qsl(parsed.query, keep_blank_values=True)
    q = [item for item in q if item[0] != param_name]
    q.append((param_name, value))
    query = urlencode(q)
    if is_abs:
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, query, parsed.fragment))
    return f"{parsed.path or '/'}?{query}"


def _fallback_params(object_type: str) -> list[str]:
    if object_type in {"numeric_id", "object_reference", "identifier"}:
        return ["id", "user_id", "account_id", "order_id"]
    if object_type == "email":
        return ["email", "user_email"]
    if object_type == "token":
        return ["token", "auth_token"]
    return ["id"]


def _normalize_param_type(raw: str) -> str:
    pt = str(raw or "").strip().lower()
    if pt in {"numeric_id", "identifier", "object_reference", "uuid"}:
        return "numeric_id"
    if pt == "email":
        return "email"
    if pt in {"token", "jwt"}:
        return "token"
    return "string"


def _priority_for_endpoint(endpoint: str) -> int:
    text = endpoint.lower()
    if any(k in text for k in SENSITIVE_ENDPOINT_KEYWORDS):
        return 100
    return 85


def _extract_endpoints(rows: list[dict[str, Any]]) -> set[str]:
    out: set[str] = set()
    for row in rows:
        category = str(row.get("category", "")).lower()
        if category not in {"js_discovery", "surface_map", "parameter_intelligence"}:
            continue
        evidence = row.get("evidence", {}) if isinstance(row.get("evidence"), dict) else {}
        endpoints = evidence.get("endpoints", [])
        if isinstance(endpoints, list):
            for item in endpoints:
                if isinstance(item, str):
                    ep = _normalize_endpoint(item)
                    if ep:
                        out.add(ep)
        mapped = evidence.get("mapped_sample", [])
        if isinstance(mapped, list):
            for item in mapped:
                if isinstance(item, dict):
                    ep = _normalize_endpoint(str(item.get("endpoint", "")))
                    if ep:
                        out.add(ep)
        param_sample = evidence.get("parameter_map_sample", [])
        if isinstance(param_sample, list):
            for item in param_sample:
                if isinstance(item, dict):
                    ep = _normalize_endpoint(str(item.get("endpoint", "")))
                    if ep:
                        out.add(ep)
    return out


def _extract_entities_from_text(text: str, cap: int = 30) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for value in EMAIL_RE.findall(text):
        out.append(("email", value.strip()))
    for value in UUID_RE.findall(text):
        out.append(("object_reference", value.strip()))
    for value in NUMERIC_ID_RE.findall(text):
        out.append(("numeric_id", value.strip()))
    dedupe: set[str] = set()
    compact: list[tuple[str, str]] = []
    for etype, value in out:
        sig = f"{etype}|{value.lower()}"
        if sig in dedupe:
            continue
        dedupe.add(sig)
        compact.append((etype, value))
        if len(compact) >= cap:
            break
    return compact


def _path(value: str) -> Path:
    return Path(value)


class PluginImpl(Plugin):
    name = "entity_cross_pollinator"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        payload = task.payload if isinstance(task.payload, dict) else {}
        run_id = str(payload.get("run_id", "")).strip()
        if not run_id:
            return []

        current_depth = int(payload.get("_depth", 0) or 0)
        max_depth = int(cfg.get("cross_pollination_depth", 5))
        if current_depth >= max_depth:
            return []

        max_objects = int(cfg.get("max_entities", 150))
        max_endpoints = int(cfg.get("max_endpoints", 220))
        max_generated_tasks = int(cfg.get("max_generated_tasks", 260))
        fanout_per_endpoint = int(cfg.get("fanout_per_endpoint", 4))
        max_probe_requests = int(cfg.get("max_probe_requests", 90))
        concurrency = max(2, int(context["runtime"].get("concurrency", 10)))
        timeout = int(context["runtime"].get("timeout_seconds", 25))
        target_plugins = cfg.get("target_plugins", ["parameter_intelligence", "differential_auth_prover"])
        if not isinstance(target_plugins, list) or not target_plugins:
            target_plugins = ["parameter_intelligence", "differential_auth_prover"]

        pg_cfg = context["config"].get("storage", {}).get("postgres", {})
        dsn_env = str(pg_cfg.get("dsn_env", "HUNTEROPS_POSTGRES_DSN")).strip()
        dsn = os.getenv(dsn_env, "").strip()
        if not dsn or not bool(pg_cfg.get("enabled", False)):
            return []

        try:
            storage = PostgresStorage(dsn=dsn, enabled=True)
            storage.ensure_research_schema()
            current_rows = storage.fetch_run_findings(run_id=run_id, target=task.target)
            previous_run = storage.get_previous_run_id(target=task.target, current_run_id=run_id)
            previous_rows = storage.fetch_run_findings(run_id=previous_run, target=task.target) if previous_run else []
            current_endpoints = _extract_endpoints(current_rows) | set(storage.list_known_endpoints(target=task.target, run_id=run_id, limit=max_endpoints))
            previous_endpoints = _extract_endpoints(previous_rows)
            new_endpoints = sorted(list(current_endpoints - previous_endpoints))[:max_endpoints]
            endpoint_rows = storage.list_endpoint_parameters(run_id=run_id, limit=max_endpoints * 12)
            object_rows = storage.list_objects(run_id=run_id, target=task.target, limit=max_objects)
            if not object_rows:
                # Backward-compatible fallback when objects table is still cold.
                entities = storage.list_recent_entities(target=task.target, limit=max_objects)
                object_rows = [
                    {
                        "object_type": "email" if str(e.get("entity_type", "")).lower() == "email" else ("object_reference" if str(e.get("entity_type", "")).lower() == "uuid" else str(e.get("entity_type", "")).lower()),
                        "object_key": str(e.get("entity_value", "")),
                        "source_endpoint": str(e.get("source_endpoint", "/")),
                        "confidence_score": float(e.get("confidence_score", 65) or 65),
                        "discovery_source": str(e.get("source_plugin", "")),
                        "metadata": e.get("metadata", {}) if isinstance(e.get("metadata"), dict) else {},
                    }
                    for e in entities
                    if str(e.get("entity_value", "")).strip()
                ]
        except Exception:
            return []

        if not current_endpoints or not object_rows:
            return []

        endpoint_to_params: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for row in endpoint_rows:
            endpoint = _normalize_endpoint(str(row.get("endpoint", "")))
            param_name = str(row.get("param_name", "")).strip()
            if not endpoint or not param_name:
                continue
            param_type = _normalize_param_type(str(row.get("param_type", _infer_param_type(param_name))))
            entry = (param_name, param_type)
            if entry not in endpoint_to_params[endpoint]:
                endpoint_to_params[endpoint].append(entry)

        # Task generation: new endpoints first.
        spawn_tasks: list[dict[str, Any]] = []
        dedupe: set[str] = set()
        for endpoint in new_endpoints[:max_endpoints]:
            sig = f"parameter_intelligence|{endpoint}|new"
            if sig in dedupe:
                continue
            dedupe.add(sig)
            spawn_tasks.append(
                {
                    "plugin": "parameter_intelligence",
                    "target": task.target,
                    "payload": {
                        "seed_paths": [endpoint],
                        "trigger": "new_endpoint_discovered",
                        "priority": 100,
                        "priority_score": 100,
                        "run_id": run_id,
                        "_depth": current_depth + 1,
                    },
                }
            )
            if len(spawn_tasks) >= max_generated_tasks:
                break

        # Cross-pollination tasks with foreign entities.
        candidates: list[dict[str, Any]] = []
        spray_types = {"numeric_id", "email"}
        for endpoint in sorted(current_endpoints):
            params = endpoint_to_params.get(endpoint, [])
            if params:
                params = [entry for entry in params if entry[1] in spray_types][: max(1, fanout_per_endpoint * 2)]
            if not params:
                # Bootstrap parameters from object type when map is still sparse.
                object_type = str(object_rows[0].get("object_type", "")).strip().lower()
                params = [(name, _normalize_param_type(_infer_param_type(name))) for name in _fallback_params(object_type)]
            emitted = 0
            for param_name, inferred in params:
                compatible_objects = [
                    row
                    for row in object_rows
                    if (
                        (inferred == "email" and str(row.get("object_type", "")).lower() == "email")
                        or (inferred == "token" and str(row.get("object_type", "")).lower() in {"token", "jwt"})
                        or (inferred == "numeric_id" and str(row.get("object_type", "")).lower() in {"numeric_id", "object_reference", "identifier"})
                        or inferred == "string"
                    )
                ]
                if not compatible_objects:
                    compatible_objects = object_rows
                for obj in compatible_objects[:fanout_per_endpoint]:
                    entity_value = str(obj.get("object_key", "")).strip()
                    if not entity_value:
                        continue
                    candidate_path = _inject_query(endpoint, param_name, entity_value)
                    if not candidate_path:
                        continue
                    candidates.append(
                        {
                            "endpoint": endpoint,
                            "candidate_path": candidate_path,
                            "parameter": param_name,
                            "entity_type": str(obj.get("object_type", "identifier")),
                            "entity_value": entity_value,
                            "source_endpoint": str(obj.get("source_endpoint", endpoint)),
                            "confidence_score": float(obj.get("confidence_score", 70) or 70),
                        }
                    )
                    for plugin_name in target_plugins:
                        sig = f"{plugin_name}|{candidate_path}|{entity_value}"
                        if sig in dedupe:
                            continue
                        dedupe.add(sig)
                        spawn_tasks.append(
                            {
                                "plugin": str(plugin_name),
                                "target": task.target,
                                "payload": {
                                    "seed_paths": [candidate_path],
                                    "trigger": "entity_cross_pollinator",
                                    "priority": _priority_for_endpoint(endpoint),
                                    "priority_score": _priority_for_endpoint(endpoint),
                                    "run_id": run_id,
                                    "recursive_object_probe": True,
                                    "entity_substitution": {
                                        "entity_type": str(obj.get("object_type", "identifier")),
                                        "entity_value": entity_value,
                                        "parameter": param_name,
                                        "endpoint": endpoint,
                                    },
                                    "_depth": current_depth + 1,
                                },
                            }
                        )
                        if len(spawn_tasks) >= max_generated_tasks:
                            break
                    emitted += 1
                    if emitted >= fanout_per_endpoint or len(spawn_tasks) >= max_generated_tasks:
                        break
                if emitted >= fanout_per_endpoint or len(spawn_tasks) >= max_generated_tasks:
                    break
            if len(spawn_tasks) >= max_generated_tasks:
                break

        # Leakage monitoring: user B probes foreign entities and compares with unauthenticated context.
        sessions_file = str(cfg.get("sessions_file", context["config"].get("modules", {}).get("differential_auth_prover", {}).get("sessions_file", "data/sessions.yaml")))
        other_name = str(cfg.get("auth_context_b", context["config"].get("modules", {}).get("differential_auth_prover", {}).get("session_other", "user_b")))
        sessions = load_sessions(_path(sessions_file))
        other_hdr = auth_header(sessions.get(other_name, {})) if sessions.get(other_name) else {}
        leakage_findings: list[Finding] = []
        edge_rows: list[dict[str, Any]] = []

        if other_hdr and candidates:
            sem = asyncio.Semaphore(concurrency)
            base_url = f"https://{task.target}"

            async def probe_candidate(candidate: dict[str, Any]) -> Finding | None:
                candidate_path = str(candidate.get("candidate_path", ""))
                endpoint = str(candidate.get("endpoint", ""))
                parameter = str(candidate.get("parameter", "id"))
                entity_value = str(candidate.get("entity_value", ""))
                if not candidate_path or not entity_value:
                    return None
                full_url = f"{base_url}{candidate_path}" if candidate_path.startswith("/") else candidate_path
                async with sem:
                    resp_other, resp_unauth = await asyncio.gather(
                        request_http_async("GET", full_url, headers=other_hdr, timeout=timeout),
                        request_http_async("GET", full_url, headers={}, timeout=timeout),
                    )
                status_other = int(resp_other.get("status", 0) or 0)
                status_unauth = int(resp_unauth.get("status", 0) or 0)
                text_other = str(resp_other.get("text", ""))
                text_unauth = str(resp_unauth.get("text", ""))
                if status_other not in {200, 201}:
                    return None
                unauthorized_gap = status_unauth in {0, 401, 403, 404}
                value_visible = entity_value.lower() in text_other.lower()
                length_gap = int(resp_other.get("length", 0) or 0) > int(resp_unauth.get("length", 0) or 0) * 1.5
                if not (value_visible and (unauthorized_gap or length_gap)):
                    return None

                leaked_entities = _extract_entities_from_text(text_other, cap=20)
                confidence = 84.0 if unauthorized_gap else 76.0
                confidence += 6.0 if value_visible else 0.0
                confidence = min(96.0, confidence)

                edge_rows.extend(
                    [
                        {
                            "src_type": "auth_context",
                            "src_key": other_name,
                            "dst_type": "endpoint",
                            "dst_key": endpoint,
                            "edge_type": "foreign_entity_probe",
                            "confidence_score": confidence,
                            "metadata": {"plugin": self.name, "parameter": parameter},
                        },
                        {
                            "src_type": "endpoint",
                            "src_key": endpoint,
                            "dst_type": "object",
                            "dst_key": entity_value,
                            "edge_type": "object_leakage_detected",
                            "confidence_score": confidence,
                            "metadata": {"plugin": self.name, "parameter": parameter},
                        },
                    ]
                )

                for etype, evalue in leaked_entities:
                    spawn_key = _inject_query(endpoint, "id" if etype != "email" else "email", evalue)
                    for plugin_name in ("parameter_intelligence", "differential_auth_prover"):
                        sig = f"{plugin_name}|{spawn_key}|{evalue}"
                        if sig in dedupe:
                            continue
                        dedupe.add(sig)
                        spawn_tasks.append(
                            {
                                "plugin": plugin_name,
                                "target": task.target,
                                "payload": {
                                    "seed_paths": [spawn_key],
                                    "trigger": "object_leakage_followup",
                                    "priority": 100,
                                    "priority_score": 100,
                                    "run_id": run_id,
                                    "_depth": current_depth + 1,
                                },
                            }
                        )
                        if len(spawn_tasks) >= max_generated_tasks:
                            break
                    if len(spawn_tasks) >= max_generated_tasks:
                        break

                return Finding(
                    plugin=self.name,
                    target=task.target,
                    category="object_leakage_indicator",
                    severity="high",
                    title=f"Foreign entity exposure via {parameter} at {endpoint}",
                    evidence={
                        "endpoint": endpoint,
                        "candidate_path": candidate_path,
                        "parameter": parameter,
                        "entity_value": entity_value,
                        "entity_type": str(candidate.get("entity_type", "identifier")),
                        "request_auth_b": {"method": "GET", "url": full_url, "headers": other_hdr},
                        "response_auth_b": {"status": status_other, "length": int(resp_other.get("length", 0) or 0)},
                        "request_unauthenticated": {"method": "GET", "url": full_url, "headers": {}},
                        "response_unauthenticated": {"status": status_unauth, "length": int(resp_unauth.get("length", 0) or 0)},
                        "leaked_entities": [{"entity_type": etype, "entity_value": evalue} for etype, evalue in leaked_entities],
                        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                        "discovery_source": self.name,
                    },
                    metadata={
                        "novelty": 95,
                        "confidence": confidence,
                        "confidence_score": confidence,
                        "impact": 88,
                        "priority_score": 100,
                        "discovery_source": self.name,
                    },
                )

            probe_jobs = [probe_candidate(candidate) for candidate in candidates[:max_probe_requests]]
            results = await asyncio.gather(*probe_jobs, return_exceptions=False)
            for item in results:
                if isinstance(item, Finding):
                    leakage_findings.append(item)

        # Persist graph relationships for cross-pollination intelligence.
        try:
            if edge_rows:
                storage.upsert_attack_graph_edges(
                    run_id=run_id,
                    target=task.target,
                    edges=edge_rows,
                    discovery_source=self.name,
                    confidence_score=80.0,
                )
        except Exception:
            pass

        if not spawn_tasks and not leakage_findings:
            return []

        summary = Finding(
            plugin=self.name,
            target=task.target,
            category="entity_cross_pollination_queue",
            severity="info",
            title=f"Entity cross-pollination generated {len(spawn_tasks)} follow-up tasks",
            evidence={
                "target": task.target,
                "run_id": run_id,
                "object_count": len(object_rows),
                "known_endpoint_count": len(current_endpoints),
                "new_endpoint_count": len(new_endpoints),
                "candidate_count": len(candidates),
                "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "discovery_source": self.name,
            },
            metadata={
                "novelty": 90,
                "confidence": 82,
                "confidence_score": 82,
                "impact": 72,
                "discovery_source": self.name,
                "cross_pollination_depth": current_depth + 1,
                "spawn_tasks": spawn_tasks[:max_generated_tasks],
            },
        )
        return [summary] + leakage_findings
