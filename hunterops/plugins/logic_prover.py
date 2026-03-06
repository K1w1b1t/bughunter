from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from hunterops.http_client import request_http_async
from hunterops.plugin_base import Plugin
from hunterops.session_profiles import auth_header, load_sessions
from hunterops.storage import PostgresStorage
from hunterops.types import Finding, Task

EMAIL_RE = re.compile(r"""[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}""")
UUID_RE = re.compile(r"""\b[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\b""")
NUMERIC_ID_RE = re.compile(r"""\b[1-9][0-9]{2,18}\b""")
SLUG_RE = re.compile(r"""\b[a-z0-9]+(?:-[a-z0-9]+){1,6}\b""")

ID_HINTS = ("id", "uid", "user_id", "account_id", "order_id", "invoice_id", "profile_id", "project_id")
DYNAMIC_FIELD_HINTS = ("timestamp", "updated", "created", "nonce", "csrf", "token", "session", "trace")


def _path(value: str) -> Path:
    return Path(value)


def _normalize_endpoint(raw: str) -> str:
    value = str(raw or "").strip()
    if not value:
        return ""
    if value.startswith("http://") or value.startswith("https://"):
        return urlparse(value).path or "/"
    return value if value.startswith("/") else f"/{value}"


def _set_query(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    query_items = [item for item in query_items if item[0] != key]
    query_items.append((key, value))
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(query_items), parsed.fragment))


def _safe_json(text: str) -> dict[str, Any]:
    if not text:
        return {}
    try:
        doc = json.loads(text)
    except Exception:
        return {}
    return doc if isinstance(doc, dict) else {}


def _structure_tokens(value: Any, prefix: str = "") -> set[str]:
    out: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            key_s = str(key)
            path = f"{prefix}.{key_s}" if prefix else key_s
            out.add(path)
            out |= _structure_tokens(child, path)
    elif isinstance(value, list):
        path = f"{prefix}[]" if prefix else "[]"
        out.add(path)
        for item in value[:5]:
            out |= _structure_tokens(item, path)
    return out


def _strip_dynamic(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, child in value.items():
            lower = str(key).lower()
            if any(marker in lower for marker in DYNAMIC_FIELD_HINTS):
                continue
            out[str(key)] = _strip_dynamic(child)
        return out
    if isinstance(value, list):
        return [_strip_dynamic(item) for item in value[:100]]
    return value


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    return len(a & b) / max(1, len(a | b))


def _extract_entities(text: str, limit: int = 60) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for item in EMAIL_RE.findall(text):
        found.append(("email", item.strip()))
    for item in UUID_RE.findall(text):
        found.append(("uuid", item.strip()))
    for item in NUMERIC_ID_RE.findall(text):
        found.append(("numeric_id", item.strip()))
    for item in SLUG_RE.findall(text):
        if len(item) >= 6:
            found.append(("slug", item.strip()))
    dedupe: set[str] = set()
    out: list[tuple[str, str]] = []
    for etype, value in found:
        sig = f"{etype}|{value.lower()}"
        if sig in dedupe:
            continue
        dedupe.add(sig)
        out.append((etype, value))
        if len(out) >= limit:
            break
    return out


def _candidate_rows(
    *,
    task: Task,
    storage: PostgresStorage,
    run_id: str,
    max_candidates: int,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    seed_paths = task.payload.get("seed_paths", []) if isinstance(task.payload, dict) else []
    for item in seed_paths if isinstance(seed_paths, list) else []:
        ep = _normalize_endpoint(str(item))
        if not ep:
            continue
        for param in ID_HINTS[:4]:
            sig = f"{ep}|{param}"
            if sig in seen:
                continue
            seen.add(sig)
            rows.append({"endpoint": ep, "parameter": param})
            if len(rows) >= max_candidates:
                return rows

    for item in storage.list_endpoint_parameters(run_id=run_id, limit=max_candidates * 8):
        ep = _normalize_endpoint(str(item.get("endpoint", "")))
        param = str(item.get("param_name", "")).strip()
        if not ep or not param:
            continue
        if param.lower() not in ID_HINTS and "id" not in param.lower():
            continue
        sig = f"{ep}|{param}"
        if sig in seen:
            continue
        seen.add(sig)
        rows.append({"endpoint": ep, "parameter": param})
        if len(rows) >= max_candidates:
            return rows
    return rows


def _pick_entity_value(storage: PostgresStorage, target: str, run_id: str, fallback: str = "2") -> str:
    object_rows = storage.list_objects(run_id=run_id, target=target, limit=400) if hasattr(storage, "list_objects") else []
    for row in object_rows:
        value = str(row.get("object_key", "")).strip()
        if value:
            return value
    entities = storage.list_recent_entities(target=target, limit=200)
    for row in entities:
        value = str(row.get("entity_value", "")).strip()
        if value:
            return value
    return fallback


def _auth_weight(status_a: int, status_b: int, status_c: int) -> float:
    if status_a in {200, 201} and status_b in {200, 201} and status_c in {401, 403}:
        return 2.0
    if status_a in {200, 201} and status_b in {200, 201} and status_c in {200, 201}:
        return 1.2
    return 1.0


class PluginImpl(Plugin):
    name = "logic_prover"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        run_id = str((task.payload if isinstance(task.payload, dict) else {}).get("run_id", "")).strip()
        if not run_id:
            return []

        pg_cfg = context["config"].get("storage", {}).get("postgres", {})
        dsn_env = str(pg_cfg.get("dsn_env", "HUNTEROPS_POSTGRES_DSN"))
        dsn = os.getenv(dsn_env, "")
        if not bool(pg_cfg.get("enabled", False)) or not dsn:
            return []

        sessions_file = str(cfg.get("sessions_file", "data/sessions.yaml"))
        auth_context_a = str(cfg.get("auth_context_a", "user"))
        auth_context_b = str(cfg.get("auth_context_b", "user_b"))
        max_candidates = int(cfg.get("max_candidates", 80))
        max_depth = int(cfg.get("max_depth", 3))
        current_depth = int((task.payload if isinstance(task.payload, dict) else {}).get("_depth", 0) or 0)
        min_similarity = float(cfg.get("min_structure_similarity_pct", 90.0))
        timeout = int(context["runtime"].get("timeout_seconds", 25))
        concurrency = max(2, int(context["runtime"].get("concurrency", 10)))
        semaphore = asyncio.Semaphore(concurrency)

        sessions = load_sessions(_path(sessions_file))
        headers_a = auth_header(sessions.get(auth_context_a, {})) if sessions.get(auth_context_a) else {}
        headers_b = auth_header(sessions.get(auth_context_b, {})) if sessions.get(auth_context_b) else {}
        headers_c: dict[str, str] = {}
        if not headers_a or not headers_b:
            return []

        try:
            storage = PostgresStorage(dsn=dsn, enabled=True)
            storage.ensure_research_schema()
            candidates = _candidate_rows(task=task, storage=storage, run_id=run_id, max_candidates=max_candidates)
        except Exception:
            return []
        if not candidates:
            return []

        default_entity = _pick_entity_value(storage=storage, target=task.target, run_id=run_id, fallback="2")
        findings: list[Finding] = []
        object_rows: list[dict[str, Any]] = []
        entity_rows: list[dict[str, Any]] = []
        edge_rows: list[dict[str, Any]] = []

        async def probe(candidate: dict[str, str]) -> Finding | None:
            endpoint = str(candidate.get("endpoint", ""))
            parameter = str(candidate.get("parameter", "id"))
            if not endpoint or not parameter:
                return None
            base_url = f"https://{task.target}{endpoint}"
            probe_url = _set_query(base_url, parameter, default_entity)
            async with semaphore:
                resp_a, resp_b, resp_c = await asyncio.gather(
                    request_http_async("GET", probe_url, headers=headers_a, timeout=timeout),
                    request_http_async("GET", probe_url, headers=headers_b, timeout=timeout),
                    request_http_async("GET", probe_url, headers=headers_c, timeout=timeout),
                )

            status_a = int(resp_a.get("status", 0) or 0)
            status_b = int(resp_b.get("status", 0) or 0)
            status_c = int(resp_c.get("status", 0) or 0)
            if status_a not in {200, 201} or status_b not in {200, 201}:
                return None

            text_a = str(resp_a.get("text", ""))
            text_b = str(resp_b.get("text", ""))
            text_c = str(resp_c.get("text", ""))
            json_a = _strip_dynamic(_safe_json(text_a))
            json_b = _strip_dynamic(_safe_json(text_b))
            struct_a = _structure_tokens(json_a if json_a else text_a)
            struct_b = _structure_tokens(json_b if json_b else text_b)
            structure_similarity = round(_jaccard(struct_a, struct_b) * 100.0, 2)
            if structure_similarity < min_similarity:
                return None

            body_hash_a = hashlib.sha256(text_a.encode("utf-8", errors="ignore")).hexdigest()
            body_hash_b = hashlib.sha256(text_b.encode("utf-8", errors="ignore")).hexdigest()
            value_changed = body_hash_a != body_hash_b
            if not value_changed:
                return None

            leaked_entities = _extract_entities(text_b, limit=35)
            leaked_count = len(leaked_entities)
            auth_w = _auth_weight(status_a, status_b, status_c)
            delta_struct = max(1.0, 100.0 - structure_similarity)
            confidence = min(98.0, round(((delta_struct * auth_w) + (leaked_count * 20.0)) / max(1.0, 1.0), 2))
            category = "Broken_Object_Level_Authorization" if status_c in {401, 403} else "Potential_IDOR_Signal"

            edge_rows.append(
                {
                    "src_type": "endpoint",
                    "src_key": endpoint,
                    "dst_type": "state",
                    "dst_key": "logic_discrepancy_confirmed",
                    "edge_type": "differential_state_mismatch",
                    "confidence_score": confidence,
                    "metadata": {"parameter": parameter, "plugin": self.name},
                }
            )
            storage.mark_verified_vulnerability_chain(
                run_id=run_id,
                target=task.target,
                endpoint=endpoint,
                relation="verified_vulnerability_chain",
                confidence_score=confidence,
                metadata={"parameter": parameter, "plugin": self.name, "category": category},
                evidence_ref="",
            )

            if leaked_entities:
                for etype, value in leaked_entities:
                    mapped_type = "object_reference" if etype == "uuid" else etype
                    entity_rows.append(
                        {
                            "entity_type": "uuid" if mapped_type == "object_reference" else mapped_type,
                            "entity_value": value,
                            "source_plugin": self.name,
                            "source_endpoint": endpoint,
                            "confidence_score": max(68.0, confidence - 10.0),
                            "metadata": {"origin": "logic_prover_leak", "parameter": parameter},
                        }
                    )
                    object_rows.append(
                        {
                            "object_type": mapped_type,
                            "object_key": value,
                            "source_endpoint": endpoint,
                            "confidence_score": max(68.0, confidence - 10.0),
                            "discovery_source": self.name,
                            "metadata": {"origin": "logic_prover_leak", "parameter": parameter},
                        }
                    )
                    edge_rows.append(
                        {
                            "src_type": "endpoint",
                            "src_key": endpoint,
                            "dst_type": "object",
                            "dst_key": value,
                            "edge_type": "verified_object_leak_chain",
                            "confidence_score": max(68.0, confidence - 6.0),
                            "metadata": {"object_type": mapped_type, "parameter": parameter, "plugin": self.name},
                        }
                    )

            spawn_tasks: list[dict[str, Any]] = []
            if leaked_entities and current_depth < max_depth:
                for etype, value in leaked_entities[:20]:
                    q_key = "id" if etype in {"uuid", "numeric_id"} else ("email" if etype == "email" else "slug")
                    seeded = _set_query(endpoint if endpoint.startswith("http") else f"https://{task.target}{endpoint}", q_key, value)
                    seeded_path = (urlparse(seeded).path or endpoint)
                    if urlparse(seeded).query:
                        seeded_path = f"{seeded_path}?{urlparse(seeded).query}"
                    spawn_tasks.append(
                        {
                            "plugin": "entity_cross_pollinator",
                            "target": task.target,
                            "payload": {
                                "run_id": run_id,
                                "seed_paths": [seeded_path],
                                "_depth": current_depth + 1,
                                "trigger": "logic_prover_recursive_mapping",
                                "priority": 100,
                                "priority_score": 100,
                            },
                        }
                    )

            return Finding(
                plugin=self.name,
                target=task.target,
                category=category,
                severity="critical" if confidence >= 90 else "high",
                title=f"Logic discrepancy confirmed at {endpoint} via {parameter}",
                evidence={
                    "endpoint": endpoint,
                    "parameter": parameter,
                    "request_auth_a": {"method": "GET", "url": probe_url, "headers": headers_a},
                    "request_auth_b": {"method": "GET", "url": probe_url, "headers": headers_b},
                    "request_unauthenticated": {"method": "GET", "url": probe_url, "headers": headers_c},
                    "response_auth_a": {"status": status_a, "length": int(resp_a.get("length", 0) or 0), "headers": resp_a.get("headers", {}), "body": text_a},
                    "response_auth_b": {"status": status_b, "length": int(resp_b.get("length", 0) or 0), "headers": resp_b.get("headers", {}), "body": text_b},
                    "response_unauthenticated": {"status": status_c, "length": int(resp_c.get("length", 0) or 0), "headers": resp_c.get("headers", {}), "body": text_c},
                    "structure_similarity_pct": structure_similarity,
                    "leaked_entities": [{"entity_type": t, "entity_value": v} for t, v in leaked_entities],
                    "discovery_source": self.name,
                    "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                },
                metadata={
                    "novelty": 94,
                    "confidence": confidence,
                    "confidence_score": confidence,
                    "impact": 95 if category == "Broken_Object_Level_Authorization" else 86,
                    "discovery_source": self.name,
                    "auth_context_a": auth_context_a,
                    "auth_context_b": auth_context_b,
                    "spawn_tasks": spawn_tasks[:120],
                    "verified_vulnerability_chain": True,
                    "probe_count": 1,
                },
            )

        raw = await asyncio.gather(*(probe(item) for item in candidates), return_exceptions=False)
        for entry in raw:
            if isinstance(entry, Finding):
                findings.append(entry)

        if findings:
            try:
                if entity_rows:
                    storage.upsert_discovered_entities(run_id=run_id, target=task.target, rows=entity_rows)
                if object_rows:
                    storage.upsert_objects(run_id=run_id, target=task.target, rows=object_rows)
                if edge_rows:
                    storage.upsert_attack_graph_edges(
                        run_id=run_id,
                        target=task.target,
                        edges=edge_rows,
                        discovery_source=self.name,
                        confidence_score=82.0,
                    )
            except Exception:
                pass
        return findings
