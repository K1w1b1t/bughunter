from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from hunterops.http_client import request_http_async
from hunterops.intelligence import http_diff_score
from hunterops.plugin_base import Plugin
from hunterops.runtime_paths import resolve_path
from hunterops.session_profiles import auth_header, load_sessions
from hunterops.storage import PostgresStorage
from hunterops.types import Finding, Task

FINANCIAL_PARAM_HINTS = ("price", "amount", "total", "quantity", "cost")
COUPON_PARAM_HINTS = ("coupon", "promo", "discount")
CURRENCY_PARAM_HINTS = ("currency", "curr")
HIGH_VALUE_ENDPOINT_HINTS = ("withdraw", "redeem", "transfer", "wallet", "payment", "checkout")
STATE_STEP_HINTS = ("cart", "checkout", "payment")
STATE_BYPASS_TARGETS = ("/success", "/api/success", "/complete", "/confirmation", "/paid")
NEGATIVE_VALUES = ("-1", "-9999")
ZERO_PRICE_VALUES = ("0", "0.01")
COUPON_STACK_VALUES = ("WELCOME10", "VIP20", "STACK50")
SUCCESS_HINT_RE = re.compile(r"(success|approved|confirmed|paid|completed|redeemed)", re.IGNORECASE)
ERROR_HINT_RE = re.compile(r"(invalid|error|denied|forbidden|blocked|insufficient)", re.IGNORECASE)
INVOICE_ID_RE = re.compile(r"\b(?:inv|invoice)[_-]?[0-9]{2,12}\b", re.IGNORECASE)
TRANSACTION_ID_RE = re.compile(r"\b(?:txn|tx|transaction)[_-]?[0-9]{2,12}\b", re.IGNORECASE)
WALLET_ID_RE = re.compile(r"\bwallet[_-]?[0-9]{2,12}\b", re.IGNORECASE)


def _set_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query = [item for item in query if item[0] != key]
    query.append((key, value))
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(query), parsed.fragment))


def _set_multi_param(url: str, key: str, values: tuple[str, ...]) -> str:
    parsed = urlparse(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query = [item for item in query if item[0] != key]
    for item in values:
        query.append((key, item))
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(query), parsed.fragment))


def _query_params(url: str) -> list[str]:
    return [str(k).strip().lower() for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True) if str(k).strip()]


def _looks_successful(text: str) -> bool:
    body = str(text or "")
    if ERROR_HINT_RE.search(body):
        return False
    return bool(SUCCESS_HINT_RE.search(body))


def _json_keys(text: str) -> list[str]:
    try:
        payload = json.loads(text)
    except Exception:
        return []
    if isinstance(payload, dict):
        return sorted(list(payload.keys()))
    return []


def _extract_financial_entities(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for hit in INVOICE_ID_RE.findall(str(text or "")):
        rows.append({"entity_type": "invoice_id", "entity_value": hit})
    for hit in TRANSACTION_ID_RE.findall(str(text or "")):
        rows.append({"entity_type": "transaction_id", "entity_value": hit})
    for hit in WALLET_ID_RE.findall(str(text or "")):
        rows.append({"entity_type": "wallet_id", "entity_value": hit})
    dedupe: set[str] = set()
    unique: list[dict[str, Any]] = []
    for row in rows:
        sig = f"{row['entity_type']}|{str(row['entity_value']).lower()}"
        if sig in dedupe:
            continue
        dedupe.add(sig)
        unique.append(row)
    return unique


class PluginImpl(Plugin):
    name = "business_logic_sniper"

    async def run(self, task: Task, context: dict[str, Any]) -> list[Finding]:
        try:
            return await self._run(task, context)
        except Exception as err:
            logger = context.get("logger")
            if logger is not None:
                try:
                    logger.exception(f"business_logic_sniper_unhandled target={task.target} err={err}")
                except Exception:
                    pass
            return []

    async def _run(self, task: Task, context: dict[str, Any]) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        timeout = int(context["runtime"].get("timeout_seconds", 25))
        scheme = str(cfg.get("base_scheme", "https")).strip().lower() or "https"
        payload = task.payload if isinstance(task.payload, dict) else {}
        run_id = str(payload.get("run_id", "")).strip()
        base = f"{scheme}://{task.target}"
        seed_paths = payload.get("seed_paths", cfg.get("seed_paths", ["/api/cart?price=100&quantity=1", "/api/checkout?amount=100"]))
        candidate_urls: list[str] = []
        if isinstance(seed_paths, list):
            for item in seed_paths:
                if not isinstance(item, str) or not item.strip():
                    continue
                if item.startswith("http://") or item.startswith("https://"):
                    candidate_urls.append(item.strip())
                else:
                    path = item if item.startswith("/") else f"/{item}"
                    candidate_urls.append(f"{base}{path}")

        pg_cfg = context["config"].get("storage", {}).get("postgres", {})
        dsn_env = str(pg_cfg.get("dsn_env", "HUNTEROPS_POSTGRES_DSN"))
        dsn = os.getenv(dsn_env, "").strip()
        storage: PostgresStorage | None = None
        if bool(pg_cfg.get("enabled", False)) and dsn and run_id:
            try:
                storage = PostgresStorage(dsn=dsn, enabled=True)
                storage.ensure_research_schema()
                for endpoint in storage.list_known_endpoints(target=task.target, run_id=run_id, limit=400):
                    if any(marker in endpoint.lower() for marker in FINANCIAL_PARAM_HINTS + COUPON_PARAM_HINTS + HIGH_VALUE_ENDPOINT_HINTS + STATE_STEP_HINTS):
                        candidate_urls.append(f"{base}{endpoint}")
            except Exception:
                storage = None

        unique_urls = sorted(list({url for url in candidate_urls if url.startswith("http://") or url.startswith("https://")}))
        findings: list[Finding] = []
        financial_entities: list[dict[str, Any]] = []

        sessions_file = str(cfg.get("sessions_file", "data/sessions.yaml"))
        sessions = load_sessions(Path(resolve_path(sessions_file)))
        headers_a = auth_header(sessions.get(str(cfg.get("auth_context_a", "user")), {})) if sessions else {}
        headers_b = auth_header(sessions.get(str(cfg.get("auth_context_b", "user_b")), {})) if sessions else {}

        for url in unique_urls[:120]:
            params = _query_params(url)
            base_resp = await request_http_async("GET", url, headers={}, timeout=timeout)
            base_text = str(base_resp.get("text", ""))
            base_status = int(base_resp.get("status", 0) or 0)

            financial_params = [p for p in params if any(marker in p for marker in FINANCIAL_PARAM_HINTS)]
            coupon_params = [p for p in params if any(marker in p for marker in COUPON_PARAM_HINTS)]
            currency_params = [p for p in params if any(marker in p for marker in CURRENCY_PARAM_HINTS)]

            for param in financial_params:
                for value in NEGATIVE_VALUES + ZERO_PRICE_VALUES:
                    mutated = _set_param(url, param, value)
                    variant = await request_http_async("GET", mutated, headers={}, timeout=timeout)
                    variant_status = int(variant.get("status", 0) or 0)
                    variant_text = str(variant.get("text", ""))
                    diff = http_diff_score(
                        {"status": base_status, "length": int(base_resp.get("length", 0) or 0), "json_keys": _json_keys(base_text)},
                        {"status": variant_status, "length": int(variant.get("length", 0) or 0), "json_keys": _json_keys(variant_text)},
                    )
                    accepted_mutation = variant_status in {200, 201} and (diff["anomaly_score"] >= 30 or _looks_successful(variant_text))
                    if not accepted_mutation:
                        continue
                    severity = "critical" if value in NEGATIVE_VALUES else "high"
                    spawn_tasks = []
                    if any(marker in url.lower() for marker in HIGH_VALUE_ENDPOINT_HINTS):
                        spawn_tasks.append(
                            {
                                "plugin": "race_condition_turbo",
                                "target": task.target,
                                "payload": {
                                    "run_id": run_id,
                                    "seed_paths": [urlparse(mutated).path + ("?" + urlparse(mutated).query if urlparse(mutated).query else "")],
                                    "priority_score": 100,
                                    "trigger": "business_logic_sniper",
                                },
                            }
                        )
                    findings.append(
                        Finding(
                            plugin=self.name,
                            target=task.target,
                            category="financial_tampering_indicator",
                            severity=severity,
                            title=f"Financial tampering accepted for parameter {param} at {urlparse(url).path}",
                            evidence={
                                "base_url": url,
                                "mutated_url": mutated,
                                "parameter": param,
                                "tested_value": value,
                                "base_status": base_status,
                                "mutated_status": variant_status,
                                "response_diff": diff,
                            },
                            metadata={
                                "novelty": 88,
                                "confidence": 84,
                                "confidence_score": 84,
                                "impact": 92,
                                "financial_flow": True,
                                "discovery_source": self.name,
                                "spawn_tasks": spawn_tasks,
                            },
                        )
                    )
                    for row in _extract_financial_entities(variant_text):
                        row["source_endpoint"] = urlparse(url).path or "/"
                        row["source_plugin"] = self.name
                        row["confidence_score"] = 80
                        row["metadata"] = {"financial_flow": True, "category": "financial_tampering_indicator"}
                        financial_entities.append(row)

            for param in coupon_params:
                stacked = _set_multi_param(url, param, COUPON_STACK_VALUES)
                stacked_resp = await request_http_async("GET", stacked, headers={}, timeout=timeout)
                stacked_text = str(stacked_resp.get("text", ""))
                if int(stacked_resp.get("status", 0) or 0) in {200, 201} and _looks_successful(stacked_text):
                    findings.append(
                        Finding(
                            plugin=self.name,
                            target=task.target,
                            category="coupon_abuse_indicator",
                            severity="high",
                            title=f"Coupon stacking accepted at {urlparse(url).path}",
                            evidence={
                                "base_url": url,
                                "stacked_url": stacked,
                                "parameter": param,
                                "codes": list(COUPON_STACK_VALUES),
                                "stacked_status": int(stacked_resp.get("status", 0) or 0),
                            },
                            metadata={
                                "novelty": 85,
                                "confidence": 82,
                                "confidence_score": 82,
                                "impact": 88,
                                "financial_flow": True,
                                "discovery_source": self.name,
                            },
                        )
                    )

                if headers_a and headers_b:
                    shared_coupon = _set_param(url, param, COUPON_STACK_VALUES[0])
                    owner = await request_http_async("GET", shared_coupon, headers=headers_a, timeout=timeout)
                    other = await request_http_async("GET", shared_coupon, headers=headers_b, timeout=timeout)
                    if int(owner.get("status", 0) or 0) in {200, 201} and int(other.get("status", 0) or 0) in {200, 201} and _looks_successful(str(other.get("text", ""))):
                        findings.append(
                            Finding(
                                plugin=self.name,
                                target=task.target,
                                category="coupon_cross_account_reuse",
                                severity="critical",
                                title=f"Coupon appears reusable across accounts at {urlparse(url).path}",
                                evidence={
                                    "url": shared_coupon,
                                    "parameter": param,
                                    "owner_status": int(owner.get("status", 0) or 0),
                                    "other_status": int(other.get("status", 0) or 0),
                                },
                                metadata={
                                    "novelty": 90,
                                    "confidence": 86,
                                    "confidence_score": 86,
                                    "impact": 95,
                                    "financial_flow": True,
                                    "discovery_source": self.name,
                                },
                            )
                        )

            if currency_params and financial_params:
                amount_param = financial_params[0]
                currency_param = currency_params[0]
                switched = _set_param(_set_param(url, amount_param, "100"), currency_param, "INR")
                switched_resp = await request_http_async("GET", switched, headers={}, timeout=timeout)
                if int(switched_resp.get("status", 0) or 0) in {200, 201} and _looks_successful(str(switched_resp.get("text", ""))):
                    findings.append(
                        Finding(
                            plugin=self.name,
                            target=task.target,
                            category="currency_manipulation_indicator",
                            severity="high",
                            title=f"Currency manipulation accepted at {urlparse(url).path}",
                            evidence={
                                "base_url": url,
                                "mutated_url": switched,
                                "amount_parameter": amount_param,
                                "currency_parameter": currency_param,
                                "mutated_status": int(switched_resp.get("status", 0) or 0),
                            },
                            metadata={
                                "novelty": 83,
                                "confidence": 79,
                                "confidence_score": 79,
                                "impact": 86,
                                "financial_flow": True,
                                "discovery_source": self.name,
                            },
                        )
                    )

            path = urlparse(url).path.lower()
            if any(marker in path for marker in STATE_STEP_HINTS):
                for bypass_path in STATE_BYPASS_TARGETS:
                    bypass_url = f"{base}{bypass_path}"
                    bypass_resp = await request_http_async("GET", bypass_url, headers={}, timeout=timeout)
                    bypass_text = str(bypass_resp.get("text", ""))
                    if int(bypass_resp.get("status", 0) or 0) in {200, 201} and _looks_successful(bypass_text):
                        findings.append(
                            Finding(
                                plugin=self.name,
                                target=task.target,
                                category="state_machine_violation_indicator",
                                severity="critical",
                                title=f"State-machine bypass detected from {urlparse(url).path} to {bypass_path}",
                                evidence={
                                    "origin_url": url,
                                    "bypass_url": bypass_url,
                                    "bypass_status": int(bypass_resp.get("status", 0) or 0),
                                },
                                metadata={
                                    "novelty": 91,
                                    "confidence": 88,
                                    "confidence_score": 88,
                                    "impact": 96,
                                    "financial_flow": True,
                                    "discovery_source": self.name,
                                },
                            )
                        )

        if storage is not None and run_id and financial_entities:
            try:
                storage.upsert_discovered_entities(run_id=run_id, target=task.target, rows=financial_entities)
            except Exception:
                pass
        return findings
