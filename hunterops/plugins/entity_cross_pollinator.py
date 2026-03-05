from __future__ import annotations

import os
from collections import defaultdict
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from hunterops.plugin_base import Plugin
from hunterops.storage import PostgresStorage
from hunterops.types import Finding, Task

ID_PARAM_HINTS = ("id", "uid", "user_id", "account_id", "order_id", "invoice_id", "profile_id")
EMAIL_PARAM_HINTS = ("email", "mail")
TOKEN_PARAM_HINTS = ("token", "jwt", "auth", "api_key", "key", "secret")
SENSITIVE_ENDPOINT_KEYWORDS = ("admin", "internal", "v1/debug", "config", "staging", "export", "graphiql")


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


def _fallback_params(entity_type: str) -> list[str]:
    if entity_type in {"numeric_id", "uuid", "identifier"}:
        return ["id", "user_id", "account_id"]
    if entity_type == "email":
        return ["email", "user_email"]
    if entity_type == "token":
        return ["token", "auth_token"]
    return ["id"]


def _priority_for_endpoint(endpoint: str) -> int:
    text = endpoint.lower()
    if any(k in text for k in SENSITIVE_ENDPOINT_KEYWORDS):
        return 100
    return 75


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

        max_entities = int(cfg.get("max_entities", 120))
        max_endpoints = int(cfg.get("max_endpoints", 160))
        max_generated_tasks = int(cfg.get("max_generated_tasks", 220))
        fanout_per_endpoint = int(cfg.get("fanout_per_endpoint", 4))
        target_plugins = cfg.get("target_plugins", ["parameter_intelligence", "differential_auth_prover"])
        if not isinstance(target_plugins, list) or not target_plugins:
            target_plugins = ["parameter_intelligence"]

        pg_cfg = context["config"].get("storage", {}).get("postgres", {})
        dsn_env = str(pg_cfg.get("dsn_env", "HUNTEROPS_POSTGRES_DSN")).strip()
        dsn = os.getenv(dsn_env, "").strip()
        if not dsn or not bool(pg_cfg.get("enabled", False)):
            return []

        try:
            storage = PostgresStorage(dsn=dsn, enabled=True)
            storage.ensure_research_schema()
            entities = storage.list_recent_entities(target=task.target, limit=max_entities)
            endpoints = storage.list_known_endpoints(target=task.target, run_id=run_id, limit=max_endpoints)
            endpoint_rows = storage.list_endpoint_parameters(run_id=run_id, limit=max_endpoints * 8)
        except Exception:
            return []

        if not entities or not endpoints:
            return []

        entity_buckets: dict[str, list[dict[str, object]]] = defaultdict(list)
        for ent in entities:
            e_type = str(ent.get("entity_type", "")).strip().lower()
            e_value = str(ent.get("entity_value", "")).strip()
            if not e_type or not e_value:
                continue
            entity_buckets[e_type].append(ent)

        endpoint_to_params: dict[str, list[str]] = defaultdict(list)
        for row in endpoint_rows:
            endpoint = str(row.get("endpoint", "")).strip()
            param_name = str(row.get("param_name", "")).strip()
            if not endpoint or not param_name:
                continue
            endpoint_to_params[endpoint].append(param_name)

        dedupe: set[str] = set()
        spawn_tasks: list[dict[str, object]] = []
        sample_paths: list[str] = []

        for endpoint in endpoints:
            params = endpoint_to_params.get(endpoint, [])[: max(1, fanout_per_endpoint)]
            if not params:
                # If this endpoint has no mapped parameters yet, bootstrap from entity types.
                for kind in ("numeric_id", "uuid", "identifier", "email", "token"):
                    if kind in entity_buckets:
                        params.extend(_fallback_params(kind))
                params = params[: max(1, fanout_per_endpoint)]
            emitted = 0
            for param_name in params:
                if len(spawn_tasks) >= max_generated_tasks:
                    break
                preferred_type = _infer_param_type(param_name)
                bucket = entity_buckets.get(preferred_type) or entity_buckets.get("uuid") or entity_buckets.get("numeric_id") or entity_buckets.get("identifier") or entity_buckets.get("email") or entity_buckets.get("token")
                if not bucket:
                    continue
                chosen = bucket[0]
                ent_type = str(chosen.get("entity_type", "identifier"))
                ent_value = str(chosen.get("entity_value", "1"))
                candidate_path = _inject_query(endpoint=endpoint, param_name=param_name, value=ent_value)
                if not candidate_path:
                    continue
                for plugin_name in target_plugins:
                    if len(spawn_tasks) >= max_generated_tasks:
                        break
                    sig = f"{plugin_name}|{task.target}|{candidate_path}|{param_name}|{ent_value}"
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
                                "recursive_object_probe": bool(preferred_type in {"numeric_id", "identifier"}),
                                "entity_substitution": {
                                    "entity_type": ent_type,
                                    "entity_value": ent_value,
                                    "parameter": param_name,
                                    "endpoint": endpoint,
                                    "source_plugin": str(chosen.get("source_plugin", "")),
                                },
                                "run_id": run_id,
                                "_depth": current_depth + 1,
                            },
                        }
                    )
                    if len(sample_paths) < 25:
                        sample_paths.append(candidate_path)
                emitted += 1
                if emitted >= fanout_per_endpoint:
                    break
            if len(spawn_tasks) >= max_generated_tasks:
                break

        if not spawn_tasks:
            return []

        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="entity_cross_pollination_queue",
                severity="info",
                title=f"Entity cross-pollination generated {len(spawn_tasks)} follow-up tasks",
                evidence={
                    "target": task.target,
                    "run_id": run_id,
                    "entity_count": len(entities),
                    "endpoint_count": len(endpoints),
                    "sample_candidate_paths": sample_paths,
                    "timestamp": payload.get("timestamp", ""),
                    "discovery_source": self.name,
                },
                metadata={
                    "novelty": 88,
                    "confidence": 79,
                    "confidence_score": 79,
                    "impact": 66,
                    "discovery_source": self.name,
                    "cross_pollination_depth": current_depth + 1,
                    "spawn_tasks": spawn_tasks,
                },
            )
        ]
