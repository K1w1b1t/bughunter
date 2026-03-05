from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from hunterops.http_client import request_http_async
from hunterops.plugin_base import Plugin
from hunterops.session_profiles import auth_header, load_sessions
from hunterops.storage import PostgresStorage
from hunterops.types import Finding, Task

SENSITIVE_KEYWORDS = ("admin", "internal", "v1/debug", "config", "staging", "export", "graphiql")
ID_PARAM_HINTS = ("id", "uid", "user_id", "account_id", "order_id", "invoice_id", "profile_id", "project_id")
IGNORE_DYNAMIC_FIELDS = {
    "timestamp",
    "updated_at",
    "created_at",
    "csrf",
    "csrf_token",
    "session",
    "session_id",
    "nonce",
    "iat",
    "exp",
    "token",
    "request_id",
    "trace_id",
}
IGNORE_DYNAMIC_RE = re.compile(r"(time|timestamp|csrf|nonce|session|token|trace|request_id|updated|created|expiry|expires)$", re.IGNORECASE)


def _normalize_endpoint(raw: str) -> str:
    value = str(raw or "").strip()
    if not value:
        return ""
    if value.startswith("http://") or value.startswith("https://"):
        return urlparse(value).path or "/"
    if value.startswith("/"):
        return value
    return f"/{value}"


def _inject_query(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    q = [item for item in q if item[0] != param]
    q.append((param, value))
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(q), p.fragment))


def _remove_dynamic_fields(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, child in value.items():
            key_s = str(key)
            key_l = key_s.lower()
            if key_l in IGNORE_DYNAMIC_FIELDS or IGNORE_DYNAMIC_RE.search(key_l):
                continue
            out[key_s] = _remove_dynamic_fields(child)
        return out
    if isinstance(value, list):
        return [_remove_dynamic_fields(x) for x in value[:100]]
    return value


def _load_json(text: str) -> dict[str, Any]:
    if not text:
        return {}
    try:
        obj = json.loads(text)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _structure_paths(value: Any, prefix: str = "") -> set[str]:
    out: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            key_s = str(key)
            path = f"{prefix}.{key_s}" if prefix else key_s
            out.add(path)
            out |= _structure_paths(child, path)
    elif isinstance(value, list):
        path = f"{prefix}[]" if prefix else "[]"
        out.add(path)
        for item in value[:5]:
            out |= _structure_paths(item, path)
    return out


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    return len(a & b) / max(1, len(a | b))


def _content_ratio(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()


def _extract_endpoints_from_rows(rows: list[dict[str, Any]]) -> set[str]:
    out: set[str] = set()
    for row in rows:
        category = str(row.get("category", "")).lower()
        if category not in {"js_discovery", "parameter_intelligence"}:
            continue
        evidence = row.get("evidence", {}) if isinstance(row.get("evidence"), dict) else {}
        arr = evidence.get("endpoints", [])
        if isinstance(arr, list):
            for item in arr:
                if isinstance(item, str):
                    ep = _normalize_endpoint(item)
                    if ep:
                        out.add(ep)
        mapping = evidence.get("parameter_map_sample", [])
        if isinstance(mapping, list):
            for m in mapping:
                if not isinstance(m, dict):
                    continue
                ep = _normalize_endpoint(str(m.get("endpoint", "")))
                if ep:
                    out.add(ep)
    return out


def _sensitive_endpoint_priority(endpoint: str) -> int:
    text = endpoint.lower()
    if any(k in text for k in SENSITIVE_KEYWORDS):
        return 100
    return 70


class PluginImpl(Plugin):
    name = "differential_auth_prover"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        payload = task.payload if isinstance(task.payload, dict) else {}
        run_id = str(payload.get("run_id", "")).strip()
        if not run_id:
            return []

        timeout = int(context["runtime"].get("timeout_seconds", 25))
        max_probes = int(cfg.get("max_probes", 90))
        min_structure = float(cfg.get("min_structure_similarity_pct", 90))
        min_content = float(cfg.get("min_content_similarity_pct", 85))
        sess_file = str(cfg.get("sessions_file", "data/sessions.yaml"))
        owner_name = str(cfg.get("session_owner", "user"))
        other_name = str(cfg.get("session_other", "user_b"))
        base_url = f"https://{task.target}"

        sessions = load_sessions(_path(sess_file))
        owner_hdr = auth_header(sessions.get(owner_name, {})) if sessions.get(owner_name) else {}
        other_hdr = auth_header(sessions.get(other_name, {})) if sessions.get(other_name) else {}
        unauth_hdr: dict[str, str] = {}
        if not owner_hdr or not other_hdr:
            return []

        pg_cfg = context["config"].get("storage", {}).get("postgres", {})
        dsn_env = str(pg_cfg.get("dsn_env", "HUNTEROPS_POSTGRES_DSN"))
        dsn = os.getenv(dsn_env, "")
        if not bool(pg_cfg.get("enabled", False)) or not dsn:
            return []

        try:
            storage = PostgresStorage(dsn=dsn, enabled=True)
            storage.ensure_research_schema()
        except Exception:
            return []

        endpoints: set[str] = set()
        seed_paths = payload.get("seed_paths", [])
        if isinstance(seed_paths, list):
            for item in seed_paths:
                if isinstance(item, str):
                    ep = _normalize_endpoint(item)
                    if ep:
                        endpoints.add(ep)

        try:
            run_rows = storage.fetch_run_findings(run_id=run_id, target=task.target)
            endpoints |= _extract_endpoints_from_rows(run_rows)
            endpoints |= set(storage.list_known_endpoints(target=task.target, run_id=run_id, limit=300))
            param_rows = storage.list_endpoint_parameters(run_id=run_id, limit=2400)
            entities = storage.list_recent_entities(target=task.target, limit=400)
        except Exception:
            return []

        if not endpoints:
            return []

        entity_values: list[str] = []
        for e in entities:
            ev = str(e.get("entity_value", "")).strip()
            if ev and ev not in entity_values:
                entity_values.append(ev)
        if not entity_values:
            entity_values = ["1", "2"]

        params_by_endpoint: dict[str, list[str]] = {}
        for row in param_rows:
            ep = _normalize_endpoint(str(row.get("endpoint", "")))
            pn = str(row.get("param_name", "")).strip()
            if not ep or not pn:
                continue
            params_by_endpoint.setdefault(ep, [])
            if pn not in params_by_endpoint[ep]:
                params_by_endpoint[ep].append(pn)

        probes: list[tuple[str, str, str]] = []
        for ep in sorted(endpoints):
            params = params_by_endpoint.get(ep, [])
            if not params:
                params = ["id", "user_id", "account_id"]
            for p in params:
                if len(probes) >= max_probes:
                    break
                if p.lower() not in ID_PARAM_HINTS and "id" not in p.lower():
                    continue
                for ev in entity_values[:4]:
                    probes.append((ep, p, ev))
                    if len(probes) >= max_probes:
                        break
            if len(probes) >= max_probes:
                break

        findings: list[Finding] = []
        for ep, param, entity_id in probes:
            probe_url = _inject_query(f"{base_url}{ep}", param, entity_id)
            r_owner, r_other, r_unauth = await _triple_get(
                url=probe_url,
                owner_headers=owner_hdr,
                other_headers=other_hdr,
                unauth_headers=unauth_hdr,
                timeout=timeout,
            )
            status_owner = int(r_owner.get("status", 0) or 0)
            status_other = int(r_other.get("status", 0) or 0)
            status_unauth = int(r_unauth.get("status", 0) or 0)
            if status_owner != 200 or status_other != 200:
                continue

            owner_json = _remove_dynamic_fields(_load_json(str(r_owner.get("text", ""))))
            other_json = _remove_dynamic_fields(_load_json(str(r_other.get("text", ""))))
            unauth_json = _remove_dynamic_fields(_load_json(str(r_unauth.get("text", ""))))
            owner_norm = json.dumps(owner_json, sort_keys=True, ensure_ascii=True)
            other_norm = json.dumps(other_json, sort_keys=True, ensure_ascii=True)
            unauth_norm = json.dumps(unauth_json, sort_keys=True, ensure_ascii=True)

            struct_owner = _structure_paths(owner_json)
            struct_other = _structure_paths(other_json)
            struct_unauth = _structure_paths(unauth_json)

            structure_sim = round(_jaccard(struct_owner, struct_other) * 100.0, 2)
            content_sim = round(_content_ratio(owner_norm, other_norm) * 100.0, 2)
            unauth_structure = round(_jaccard(struct_owner, struct_unauth) * 100.0, 2)
            unauth_content = round(_content_ratio(owner_norm, unauth_norm) * 100.0, 2)
            if structure_sim < min_structure or content_sim < min_content:
                continue

            likely_unauth_blocked = status_unauth in {0, 401, 403}
            confidence = 92.0 if likely_unauth_blocked else 87.0
            severity = "critical" if confidence >= 90 else "high"
            title = f"Potential IDOR via differential auth replay at {ep} using {param}"

            findings.append(
                Finding(
                    plugin=self.name,
                    target=task.target,
                    category="critical_idor_vulnerability" if severity == "critical" else "idor_behavior_indicator",
                    severity=severity,
                    title=title,
                    evidence={
                        "request_auth_a": {"method": "GET", "url": probe_url, "headers": owner_hdr},
                        "response_auth_a": {
                            "status": status_owner,
                            "length": int(r_owner.get("length", 0) or 0),
                            "headers": r_owner.get("headers", {}),
                            "body": str(r_owner.get("text", "")),
                        },
                        "request_auth_b": {"method": "GET", "url": probe_url, "headers": other_hdr},
                        "response_auth_b": {
                            "status": status_other,
                            "length": int(r_other.get("length", 0) or 0),
                            "headers": r_other.get("headers", {}),
                            "body": str(r_other.get("text", "")),
                        },
                        "request_unauthenticated": {"method": "GET", "url": probe_url, "headers": unauth_hdr},
                        "response_unauthenticated": {
                            "status": status_unauth,
                            "length": int(r_unauth.get("length", 0) or 0),
                            "headers": r_unauth.get("headers", {}),
                            "body": str(r_unauth.get("text", "")),
                        },
                        "diff_map": {
                            "entity_id": entity_id,
                            "parameter": param,
                            "status_owner": status_owner,
                            "status_other": status_other,
                            "status_unauthenticated": status_unauth,
                            "structure_similarity_pct": structure_sim,
                            "content_similarity_pct": content_sim,
                            "unauth_structure_similarity_pct": unauth_structure,
                            "unauth_content_similarity_pct": unauth_content,
                            "owner_hash": hashlib.sha256(owner_norm.encode("utf-8")).hexdigest(),
                            "other_hash": hashlib.sha256(other_norm.encode("utf-8")).hexdigest(),
                            "unauth_hash": hashlib.sha256(unauth_norm.encode("utf-8")).hexdigest(),
                            "ignore_dynamic_fields": sorted(list(IGNORE_DYNAMIC_FIELDS)),
                        },
                        "tested_parameter": param,
                        "entity_id": entity_id,
                        "endpoint": ep,
                        "discovery_source": self.name,
                        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                    },
                    metadata={
                        "novelty": float(payload.get("priority", _sensitive_endpoint_priority(ep))),
                        "confidence": confidence,
                        "confidence_score": confidence,
                        "impact": 92 if severity == "critical" else 84,
                        "priority_score": _sensitive_endpoint_priority(ep),
                        "discovery_source": self.name,
                        "spawn_tasks": [
                            {
                                "plugin": "report_synthesis",
                                "target": task.target,
                                "payload": {
                                    "run_id": run_id,
                                    "priority": 100,
                                    "_depth": int(payload.get("_depth", 0) or 0) + 1,
                                    "seed_paths": [ep],
                                    "trigger": "differential_auth_prover",
                                },
                            }
                        ],
                    },
                )
            )
        return findings


def _path(value: str) -> Any:
    from pathlib import Path

    return Path(value)


async def _triple_get(
    url: str,
    owner_headers: dict[str, str],
    other_headers: dict[str, str],
    unauth_headers: dict[str, str],
    timeout: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    return await _gather_3(
        request_http_async("GET", url, headers=owner_headers, timeout=timeout),
        request_http_async("GET", url, headers=other_headers, timeout=timeout),
        request_http_async("GET", url, headers=unauth_headers, timeout=timeout),
    )


async def _gather_3(a: Any, b: Any, c: Any) -> tuple[Any, Any, Any]:
    import asyncio

    x, y, z = await asyncio.gather(a, b, c, return_exceptions=False)
    return x, y, z
