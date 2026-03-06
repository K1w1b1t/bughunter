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

try:
    import httpx
except Exception:  # pragma: no cover
    httpx = None  # type: ignore[assignment]

from hunterops.http_client import request_http_async
from hunterops.plugin_base import Plugin
from hunterops.runtime_paths import ensure_directory, resolve_path
from hunterops.session_profiles import auth_header, load_sessions
from hunterops.storage import PostgresStorage
from hunterops.types import Finding, Task

ID_HINTS = ("id", "uid", "user_id", "account_id", "order_id", "invoice_id", "profile_id", "project_id")
EMAIL_HINTS = ("email", "mail")
TOKEN_HINTS = ("token", "jwt", "auth", "secret", "api_key", "key")
SENSITIVE_FIELD_HINTS = ("email", "phone", "address", "cpf", "tax", "wallet", "account", "invoice", "card", "credit_card_last4")
DYNAMIC_FIELD_HINTS = ("timestamp", "updated", "created", "nonce", "csrf", "trace", "request_id", "session", "token", "iat", "exp")

SEMANTIC_PARAM_RULES: list[tuple[tuple[str, ...], dict[str, list[str]]]] = [
    (("debug", "diag", "trace"), {"debug": ["true", "1"], "verbose": ["1"], "show_secrets": ["1"]}),
    (("admin", "internal", "manage"), {"admin": ["1"], "internal": ["true"], "role": ["admin"]}),
    (("export", "download", "report"), {"include_sensitive": ["1"], "full": ["true"], "format": ["json"]}),
    (("profile", "account", "user"), {"user_id": ["1", "2"], "account_id": ["1001", "1002"]}),
    (("billing", "payment", "invoice"), {"invoice_id": ["1001", "1002"], "wallet_id": ["1", "2"]}),
]


def _normalize_endpoint(raw: str) -> str:
    value = str(raw or "").strip()
    if not value:
        return ""
    if value.startswith("http://") or value.startswith("https://"):
        return urlparse(value).path or "/"
    parsed = urlparse(value)
    path = parsed.path or value
    if not path.startswith("/"):
        path = f"/{path}"
    return path or "/"


def _set_query(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    query_items = [item for item in query_items if item[0] != key]
    query_items.append((key, value))
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(query_items), parsed.fragment))


def _infer_param_type(name: str) -> str:
    n = str(name or "").lower()
    if any(h in n for h in EMAIL_HINTS):
        return "email"
    if any(h in n for h in TOKEN_HINTS):
        return "token"
    if any(h in n for h in ID_HINTS) or "uuid" in n or "identifier" in n:
        return "identifier"
    return "string"


def _safe_json(text: str) -> dict[str, Any]:
    if not text:
        return {}
    try:
        obj = json.loads(text)
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _strip_dynamic(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, child in value.items():
            lk = str(key).lower()
            if any(marker in lk for marker in DYNAMIC_FIELD_HINTS):
                continue
            out[str(key)] = _strip_dynamic(child)
        return out
    if isinstance(value, list):
        return [_strip_dynamic(item) for item in value[:120]]
    return value


def _structure_tokens(value: Any, prefix: str = "") -> set[str]:
    out: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            key_s = str(key)
            path = f"{prefix}.{key_s}" if prefix else key_s
            out.add(path)
            out |= _structure_tokens(child, path)
    elif isinstance(value, list):
        marker = f"{prefix}[]" if prefix else "[]"
        out.add(marker)
        for item in value[:6]:
            out |= _structure_tokens(item, marker)
    return out


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    return len(a & b) / max(1, len(a | b))


def _mask(value: str) -> str:
    raw = str(value or "")
    if len(raw) <= 8:
        return "*" * len(raw)
    return f"{raw[:4]}...{raw[-4:]}"


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in headers.items():
        lk = str(key).lower()
        if lk in {"authorization", "cookie"} or "token" in lk or "secret" in lk or "api-key" in lk:
            out[str(key)] = _mask(str(value))
        else:
            out[str(key)] = str(value)
    return out


def _semantic_param_guesses(endpoint: str) -> dict[str, list[str]]:
    ep = str(endpoint or "").lower()
    out: dict[str, list[str]] = {}
    for markers, mapping in SEMANTIC_PARAM_RULES:
        if any(marker in ep for marker in markers):
            for key, values in mapping.items():
                out.setdefault(key, [])
                for value in values:
                    if value not in out[key]:
                        out[key].append(value)
    return out


async def _request_with_proxy(
    method: str,
    url: str,
    headers: dict[str, str],
    timeout: int,
    proxy: str = "",
) -> dict[str, Any]:
    px = str(proxy or "").strip()
    if not px or httpx is None:
        return await request_http_async(method, url, headers=headers, timeout=timeout)
    try:
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, proxy=px) as client:
                response = await client.request(method.upper(), url, headers=headers)
        except TypeError:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, proxies=px) as client:  # type: ignore[call-arg]
                response = await client.request(method.upper(), url, headers=headers)
        return {
            "ok": bool(response.is_success),
            "status": int(response.status_code),
            "headers": dict(response.headers.items()),
            "text": response.text,
            "length": len(response.content),
        }
    except Exception as err:
        return {"ok": False, "status": 0, "headers": {}, "text": str(err), "length": 0}


def _impact_analysis(endpoint: str, leaked_fields: list[str], parameter: str) -> str:
    if leaked_fields:
        return f"PII Leakage detected: {sorted(set(leaked_fields))}. Cross-session object exposure via '{parameter}' on {endpoint}."
    return f"Broken object-level authorization signal detected via '{parameter}' on {endpoint}."


def _build_poc_bundle(
    *,
    out_dir: Path,
    run_id: str,
    target: str,
    endpoint: str,
    parameter: str,
    value: str,
    req_a: dict[str, Any],
    req_b: dict[str, Any],
    req_c: dict[str, Any],
) -> tuple[str, str]:
    run_dir = ensure_directory(out_dir / f"run_{run_id}", mode=0o755)
    stem_raw = f"{target}_{endpoint}_{parameter}_{value}".replace("/", "_").replace("?", "_").replace("&", "_")
    stem = re.sub(r"[^a-zA-Z0-9_.-]+", "_", stem_raw).strip("_")[:120] or "verified_signal"
    py_path = run_dir / f"{stem}.py"
    sh_path = run_dir / f"{stem}.sh"

    red_a = _redact_headers(req_a.get("headers", {}) if isinstance(req_a.get("headers"), dict) else {})
    red_b = _redact_headers(req_b.get("headers", {}) if isinstance(req_b.get("headers"), dict) else {})
    red_c = _redact_headers(req_c.get("headers", {}) if isinstance(req_c.get("headers"), dict) else {})
    url = str(req_a.get("url", ""))

    curl_a = f"curl -i -X GET \"{url}\""
    curl_b = f"curl -i -X GET \"{url}\""
    curl_c = f"curl -i -X GET \"{url}\""
    for key, val in red_a.items():
        curl_a += f" -H \"{key}: {val}\""
    for key, val in red_b.items():
        curl_b += f" -H \"{key}: {val}\""
    for key, val in red_c.items():
        curl_c += f" -H \"{key}: {val}\""

    script = "\n".join(
        [
            "import requests",
            "",
            f"URL = {json.dumps(url, ensure_ascii=True)}",
            f"HEADERS_A = {json.dumps(red_a, ensure_ascii=True)}",
            f"HEADERS_B = {json.dumps(red_b, ensure_ascii=True)}",
            f"HEADERS_C = {json.dumps(red_c, ensure_ascii=True)}",
            "",
            "def run(name, headers):",
            "    r = requests.get(URL, headers=headers, timeout=20)",
            "    print(f\"[{name}] status={r.status_code} len={len(r.text)}\")",
            "    print(r.text[:400])",
            "",
            "if __name__ == '__main__':",
            "    run('Owner', HEADERS_A)",
            "    run('OtherUser', HEADERS_B)",
            "    run('Unauthenticated', HEADERS_C)",
            "",
        ]
    )
    py_path.write_text(script, encoding="utf-8")
    sh_path.write_text("\n".join([curl_a, curl_b, curl_c]) + "\n", encoding="utf-8")
    return str(py_path), curl_b


class PluginImpl(Plugin):
    name = "auth_matrix_engine"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        payload = task.payload if isinstance(task.payload, dict) else {}
        run_id = str(payload.get("run_id", "")).strip()
        if not run_id:
            return []

        pg_cfg = context["config"].get("storage", {}).get("postgres", {})
        dsn_env = str(pg_cfg.get("dsn_env", "HUNTEROPS_POSTGRES_DSN")).strip()
        dsn = str(os.getenv(dsn_env, "")).strip()
        if not bool(pg_cfg.get("enabled", False)) or not dsn:
            return []

        timeout = int(context["runtime"].get("timeout_seconds", 25))
        concurrency = max(2, int(context["runtime"].get("concurrency", 10)))
        max_endpoints = int(cfg.get("max_endpoints", 220))
        max_probes = int(cfg.get("max_probes", 140))
        min_structure = float(cfg.get("min_structure_similarity_pct", 90.0))
        min_confidence = float(cfg.get("min_confidence", 50.0))
        verified_threshold = float(cfg.get("verified_threshold", 85.0))
        max_depth = int(context["runtime"].get("recursion_max_depth", 5))
        current_depth = int(payload.get("_depth", 0) or 0)
        request_delay = max(0.0, float(payload.get("request_delay_seconds", 0) or 0.0))
        user_agent = str(payload.get("user_agent", "")).strip()
        proxy = str(payload.get("proxy", "")).strip()
        base_url = f"https://{task.target}"

        sessions_file = Path(str(cfg.get("sessions_file", "data/sessions.yaml")))
        auth_context_a = str(cfg.get("auth_context_a", "user")).strip() or "user"
        auth_context_b = str(cfg.get("auth_context_b", "user_b")).strip() or "user_b"
        sessions = load_sessions(sessions_file)
        headers_a = auth_header(sessions.get(auth_context_a, {})) if sessions.get(auth_context_a) else {}
        headers_b = auth_header(sessions.get(auth_context_b, {})) if sessions.get(auth_context_b) else {}
        headers_c: dict[str, str] = {}
        if user_agent:
            headers_a.setdefault("User-Agent", user_agent)
            headers_b.setdefault("User-Agent", user_agent)
            headers_c.setdefault("User-Agent", user_agent)
        if not headers_a or not headers_b:
            return []

        try:
            storage = PostgresStorage(dsn=dsn, enabled=True)
            storage.ensure_research_schema()
            endpoints = set(storage.list_known_endpoints(target=task.target, run_id=run_id, limit=max_endpoints))
            param_rows = storage.list_endpoint_parameters(run_id=run_id, limit=max_endpoints * 20)
            object_rows = storage.list_objects(run_id=run_id, target=task.target, limit=max_endpoints * 12)
            entity_rows = storage.list_recent_entities(target=task.target, limit=max_endpoints * 12)
        except Exception:
            return []

        for seed in payload.get("seed_paths", []) if isinstance(payload.get("seed_paths"), list) else []:
            if isinstance(seed, str):
                ep = _normalize_endpoint(seed)
                if ep:
                    endpoints.add(ep)
        if not endpoints:
            return []

        params_by_endpoint: dict[str, list[tuple[str, str]]] = {}
        for row in param_rows:
            endpoint = _normalize_endpoint(str(row.get("endpoint", "")))
            param = str(row.get("param_name", "")).strip()
            if not endpoint or not param:
                continue
            ptype = str(row.get("param_type", _infer_param_type(param))).strip().lower()
            if ptype in {"numeric_id", "identifier", "object_reference", "uuid"}:
                ptype = "identifier"
            elif ptype not in {"email", "token"}:
                ptype = _infer_param_type(param)
            params_by_endpoint.setdefault(endpoint, [])
            entry = (param, ptype)
            if entry not in params_by_endpoint[endpoint]:
                params_by_endpoint[endpoint].append(entry)

        buckets: dict[str, list[str]] = {"identifier": [], "email": [], "token": []}
        dedupe_values: set[str] = set()
        for row in object_rows:
            key = str(row.get("object_key", "")).strip()
            otype = str(row.get("object_type", "")).strip().lower()
            if not key:
                continue
            if key.lower() in dedupe_values:
                continue
            dedupe_values.add(key.lower())
            if otype in {"numeric_id", "object_reference", "identifier", "uuid"}:
                buckets["identifier"].append(key)
            elif otype == "email":
                buckets["email"].append(key)
            elif otype in {"token", "jwt"}:
                buckets["token"].append(key)
        for row in entity_rows:
            key = str(row.get("entity_value", "")).strip()
            etype = str(row.get("entity_type", "")).strip().lower()
            if not key or key.lower() in dedupe_values:
                continue
            dedupe_values.add(key.lower())
            if etype in {"numeric_id", "uuid", "identifier", "object_reference"}:
                buckets["identifier"].append(key)
            elif etype == "email":
                buckets["email"].append(key)
            elif etype in {"token", "jwt"}:
                buckets["token"].append(key)
        if not buckets["identifier"]:
            buckets["identifier"] = ["1", "2", "1001"]
        if not buckets["email"]:
            buckets["email"] = ["user@example.com", "owner@example.com"]

        probes: list[dict[str, str]] = []
        dedupe_probe: set[str] = set()
        for endpoint in sorted(endpoints)[:max_endpoints]:
            semantic = _semantic_param_guesses(endpoint)
            params = params_by_endpoint.get(endpoint, [])
            for key in semantic.keys():
                inferred = _infer_param_type(key)
                item = (key, inferred)
                if item not in params:
                    params.append(item)
            if not params:
                params = [("id", "identifier")]

            for param_name, param_type in params[:8]:
                values: list[str] = []
                if param_name in semantic and semantic[param_name]:
                    values.extend(semantic[param_name][:3])
                if param_type == "identifier":
                    values.extend(buckets["identifier"][:8])
                elif param_type == "email":
                    values.extend(buckets["email"][:6])
                elif param_type == "token":
                    values.extend(buckets["token"][:4])
                if not values:
                    values = ["1"] if param_type == "identifier" else ["true"]

                for value in values:
                    signature = f"{endpoint}|{param_name}|{value}"
                    if signature in dedupe_probe:
                        continue
                    dedupe_probe.add(signature)
                    probes.append(
                        {
                            "endpoint": endpoint,
                            "parameter": param_name,
                            "param_type": param_type,
                            "value": value,
                        }
                    )
                    if len(probes) >= max_probes:
                        break
                if len(probes) >= max_probes:
                    break
            if len(probes) >= max_probes:
                break

        if not probes:
            return []

        verified_dir = ensure_directory(resolve_path(str(cfg.get("verified_dir", "data/evidence/verified"))), mode=0o755)
        sem = asyncio.Semaphore(concurrency)
        findings: list[Finding] = []

        async def run_probe(probe: dict[str, str]) -> Finding | None:
            endpoint = str(probe.get("endpoint", ""))
            parameter = str(probe.get("parameter", "id"))
            value = str(probe.get("value", "1"))
            if not endpoint:
                return None
            url = _set_query(f"{base_url}{endpoint}", parameter, value)

            async with sem:
                if request_delay > 0:
                    await asyncio.sleep(request_delay)
                r_a, r_b, r_c = await asyncio.gather(
                    _request_with_proxy("GET", url, headers_a, timeout, proxy=proxy),
                    _request_with_proxy("GET", url, headers_b, timeout, proxy=proxy),
                    _request_with_proxy("GET", url, headers_c, timeout, proxy=proxy),
                )

            s_a = int(r_a.get("status", 0) or 0)
            s_b = int(r_b.get("status", 0) or 0)
            s_c = int(r_c.get("status", 0) or 0)
            if s_a not in {200, 201} or s_b not in {200, 201}:
                return None

            text_a = str(r_a.get("text", ""))
            text_b = str(r_b.get("text", ""))
            text_c = str(r_c.get("text", ""))
            json_a = _strip_dynamic(_safe_json(text_a))
            json_b = _strip_dynamic(_safe_json(text_b))
            json_c = _strip_dynamic(_safe_json(text_c))

            struct_a = _structure_tokens(json_a if json_a else text_a)
            struct_b = _structure_tokens(json_b if json_b else text_b)
            struct_similarity = round(_jaccard(struct_a, struct_b) * 100.0, 2)
            if struct_similarity < min_structure:
                return None

            hash_a = hashlib.sha256(text_a.encode("utf-8", errors="ignore")).hexdigest()
            hash_b = hashlib.sha256(text_b.encode("utf-8", errors="ignore")).hexdigest()
            data_changed = hash_a != hash_b
            if not data_changed:
                return None

            leaked_fields = sorted([key for key in json_b.keys() if any(marker in key.lower() for marker in SENSITIVE_FIELD_HINTS)]) if json_b else []
            leaked_entities = []
            if str(value).strip().lower() in text_b.lower():
                leaked_entities.append(value)
            auth_w = 2.0 if s_c in {401, 403} else (1.2 if s_c in {200, 201} else 1.0)
            delta_struct = max(1.0, 100.0 - struct_similarity)
            e_leaked = len(leaked_fields) + len(leaked_entities)
            confidence = round(min(98.0, ((delta_struct * auth_w) + (e_leaked * 20.0)) / 1.0), 2)
            if confidence < min_confidence:
                return None

            impact = _impact_analysis(endpoint, leaked_fields, parameter)
            severity = "critical" if confidence >= verified_threshold else "high"
            category = "broken_access_control_matrix_signal"

            req_a = {"method": "GET", "url": url, "headers": headers_a}
            req_b = {"method": "GET", "url": url, "headers": headers_b}
            req_c = {"method": "GET", "url": url, "headers": headers_c}
            response_meta_a = {"status": s_a, "length": int(r_a.get("length", 0) or 0), "headers": r_a.get("headers", {}), "body": text_a}
            response_meta_b = {"status": s_b, "length": int(r_b.get("length", 0) or 0), "headers": r_b.get("headers", {}), "body": text_b}
            response_meta_c = {"status": s_c, "length": int(r_c.get("length", 0) or 0), "headers": r_c.get("headers", {}), "body": text_c}

            poc_path = ""
            curl_command = ""
            if confidence >= verified_threshold:
                try:
                    poc_path, curl_command = _build_poc_bundle(
                        out_dir=verified_dir,
                        run_id=run_id,
                        target=task.target,
                        endpoint=endpoint,
                        parameter=parameter,
                        value=value,
                        req_a=req_a,
                        req_b=req_b,
                        req_c=req_c,
                    )
                    if hasattr(storage, "upsert_verified_finding"):
                        storage.upsert_verified_finding(
                            run_id=run_id,
                            target=task.target,
                            plugin=self.name,
                            category=category,
                            severity=severity,
                            title=f"Authorization matrix discrepancy at {endpoint}",
                            confidence_score=confidence,
                            impact_analysis=impact,
                            endpoint=endpoint,
                            parameter_name=parameter,
                            poc_path=poc_path,
                            curl_command=curl_command,
                            metadata={"discovery_source": self.name, "auth_context_a": auth_context_a, "auth_context_b": auth_context_b},
                            evidence={
                                "request_auth_a": {"method": "GET", "url": url, "headers": _redact_headers(headers_a)},
                                "request_auth_b": {"method": "GET", "url": url, "headers": _redact_headers(headers_b)},
                                "request_unauthenticated": {"method": "GET", "url": url, "headers": _redact_headers(headers_c)},
                                "response_auth_a": {"status": s_a, "length": int(r_a.get("length", 0) or 0)},
                                "response_auth_b": {"status": s_b, "length": int(r_b.get("length", 0) or 0)},
                                "response_unauthenticated": {"status": s_c, "length": int(r_c.get("length", 0) or 0)},
                            },
                        )
                except Exception:
                    poc_path = ""
                    curl_command = ""

            spawn_tasks: list[dict[str, Any]] = []
            if confidence >= 80 and current_depth < max_depth:
                spawn_tasks.append(
                    {
                        "plugin": "entity_cross_pollinator",
                        "target": task.target,
                        "payload": {
                            "run_id": run_id,
                            "seed_paths": [f"{endpoint}?{parameter}={value}"],
                            "trigger": "auth_matrix_engine",
                            "priority_score": 100,
                            "_depth": current_depth + 1,
                        },
                    }
                )

            return Finding(
                plugin=self.name,
                target=task.target,
                category=category,
                severity=severity,
                title=f"Authorization matrix discrepancy at {endpoint} via {parameter}",
                evidence={
                    "endpoint": endpoint,
                    "tested_parameter": parameter,
                    "tested_value": value,
                    "request_auth_a": req_a,
                    "request_auth_b": req_b,
                    "request_unauthenticated": req_c,
                    "response_auth_a": response_meta_a,
                    "response_auth_b": response_meta_b,
                    "response_unauthenticated": response_meta_c,
                    "structure_similarity_pct": struct_similarity,
                    "leaked_sensitive_fields": leaked_fields,
                    "impact_analysis": impact,
                    "poc_path": poc_path,
                    "curl_command": curl_command,
                    "discovery_source": self.name,
                    "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                },
                metadata={
                    "novelty": 94,
                    "confidence": confidence,
                    "confidence_score": confidence,
                    "impact": 93 if leaked_fields else 85,
                    "discovery_source": self.name,
                    "auth_context_a": auth_context_a,
                    "auth_context_b": auth_context_b,
                    "semantic_parameter_guessing": bool(_semantic_param_guesses(endpoint)),
                    "spawn_tasks": spawn_tasks,
                    "proxy_used": bool(proxy),
                },
            )

        jobs = [run_probe(probe) for probe in probes]
        results = await asyncio.gather(*jobs, return_exceptions=False)
        for item in results:
            if isinstance(item, Finding):
                findings.append(item)
        return findings
