from __future__ import annotations

import asyncio
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from hunterops.async_io import write_text
from hunterops.plugin_base import Plugin
from hunterops.runtime_paths import ensure_directory, resolve_path, secure_secret_file
from hunterops.storage import PostgresStorage
from hunterops.types import Finding, Task

TOKEN_RE = re.compile(r"""(?i)\b(bearer\s+)([a-z0-9\-._~+/]+=*)""")
COOKIE_RE = re.compile(r"""(?i)\b(session(?:id)?|auth(?:orization)?|token)\s*=\s*([^;,\s]+)""")
JSON_SECRET_RE = re.compile(r'(?i)"(access_token|refresh_token|id_token|api[_-]?key|secret|authorization)"\s*:\s*"([^"]+)"')


def _mask(value: str) -> str:
    raw = str(value or "")
    if len(raw) <= 8:
        return "*" * len(raw)
    return f"{raw[:4]}...{raw[-4:]}"


def _redact_headers(headers: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in headers.items():
        k = str(key)
        v = str(value)
        lk = k.lower()
        if lk in {"authorization", "cookie"} or "token" in lk or "secret" in lk or "api-key" in lk:
            out[k] = _mask(v)
        else:
            out[k] = v
    return out


def _redact_text(value: str, max_chars: int = 8000) -> str:
    text = str(value or "")
    if not text:
        return ""
    text = TOKEN_RE.sub(lambda m: f"{m.group(1)}{_mask(m.group(2))}", text)
    text = COOKIE_RE.sub(lambda m: f"{m.group(1)}={_mask(m.group(2))}", text)
    text = JSON_SECRET_RE.sub(lambda m: f"\"{m.group(1)}\": \"{_mask(m.group(2))}\"", text)
    if len(text) > max_chars:
        return f"{text[:max_chars]}\n...[truncated {len(text) - max_chars} chars]..."
    return text


def _impact(category: str, leaked: int) -> str:
    cl = str(category).lower()
    if "idor" in cl or "broken_object_level_authorization" in cl or "potential_idor_signal" in cl:
        return "Critical: Unauthorized access to PII/Financial data discovered via object relationship mismatch."
    if leaked > 0:
        return "High: Cross-context data disclosure may expose customer records and internal object references."
    return "Medium: Logic boundary inconsistency detected and requires manual validation."


def _endpoint_from_evidence(evidence: dict[str, Any]) -> str:
    endpoint = str(evidence.get("endpoint", "")).strip()
    if endpoint:
        return endpoint
    for key in ("request_auth_a", "request_auth_b", "request_unauthenticated", "request"):
        req = evidence.get(key, {})
        if isinstance(req, dict):
            url = str(req.get("url", "")).strip()
            if url:
                if url.startswith("http://") or url.startswith("https://"):
                    p = urlparse(url)
                    path = p.path or "/"
                    return f"{path}?{p.query}" if p.query else path
                return url
    return "/"


def _count_leaked_entities(evidence: dict[str, Any]) -> int:
    leaked = evidence.get("leaked_entities", [])
    if isinstance(leaked, list):
        return len(leaked)
    diff = evidence.get("diff_map", {})
    if isinstance(diff, dict):
        hits = diff.get("sensitive_object_hits", [])
        if isinstance(hits, list):
            return len(hits)
    return 0


async def _load_rows_from_storage(
    *,
    dsn: str,
    run_id: str,
    target: str,
) -> list[dict[str, Any]]:
    storage = PostgresStorage(dsn=dsn, enabled=True)
    return await asyncio.to_thread(storage.fetch_run_findings, run_id, target)


class PluginImpl(Plugin):
    name = "evidence_packager"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        payload = task.payload if isinstance(task.payload, dict) else {}
        run_id = str(payload.get("run_id", "")).strip()
        if not run_id:
            return []

        threshold = float(cfg.get("confidence_threshold", 80.0))
        max_body_chars = int(cfg.get("max_body_chars", 7000))
        out_root = ensure_directory(resolve_path(str(cfg.get("out_dir", "data/evidence/bundles"))), mode=0o755)
        run_dir = ensure_directory(out_root / f"run_{run_id}", mode=0o755)

        rows: list[dict[str, Any]] = []
        raw_payload_rows = payload.get("findings", [])
        if isinstance(raw_payload_rows, list):
            rows = [x for x in raw_payload_rows if isinstance(x, dict)]

        if not rows:
            pg_cfg = context["config"].get("storage", {}).get("postgres", {})
            dsn_env = str(pg_cfg.get("dsn_env", "HUNTEROPS_POSTGRES_DSN"))
            dsn = os.getenv(dsn_env, "")
            if bool(pg_cfg.get("enabled", False)) and dsn:
                try:
                    rows = await _load_rows_from_storage(dsn=dsn, run_id=run_id, target=task.target)
                except Exception:
                    rows = []
        if not rows:
            return []

        generated: list[Finding] = []
        for row in rows:
            category = str(row.get("category", ""))
            meta = row.get("metadata", {}) if isinstance(row.get("metadata"), dict) else {}
            confidence = float(meta.get("confidence_score", meta.get("confidence", 0)) or 0)
            if confidence < threshold:
                continue
            evidence = row.get("evidence", {}) if isinstance(row.get("evidence"), dict) else {}
            endpoint = _endpoint_from_evidence(evidence)
            leaked_count = _count_leaked_entities(evidence)
            impact = _impact(category, leaked_count)
            title = str(row.get("title", "Logic discrepancy"))
            severity = str(row.get("severity", "high")).lower()
            ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S_%f")
            file_name = f"report_{ts}.md"
            report_path = run_dir / file_name

            req_a = evidence.get("request_auth_a", evidence.get("request", {}))
            req_b = evidence.get("request_auth_b", {})
            req_c = evidence.get("request_unauthenticated", {})
            req_a = req_a if isinstance(req_a, dict) else {}
            req_b = req_b if isinstance(req_b, dict) else {}
            req_c = req_c if isinstance(req_c, dict) else {}
            redacted_a = _redact_headers(req_a.get("headers", {}) if isinstance(req_a.get("headers"), dict) else {})
            redacted_b = _redact_headers(req_b.get("headers", {}) if isinstance(req_b.get("headers"), dict) else {})
            redacted_c = _redact_headers(req_c.get("headers", {}) if isinstance(req_c.get("headers"), dict) else {})
            resp_a = evidence.get("response_auth_a", {}) if isinstance(evidence.get("response_auth_a"), dict) else {}
            resp_b = evidence.get("response_auth_b", {}) if isinstance(evidence.get("response_auth_b"), dict) else {}
            resp_c = evidence.get("response_unauthenticated", {}) if isinstance(evidence.get("response_unauthenticated"), dict) else {}
            body_a = _redact_text(str(resp_a.get("body", "")), max_chars=max_body_chars)
            body_b = _redact_text(str(resp_b.get("body", "")), max_chars=max_body_chars)
            body_c = _redact_text(str(resp_c.get("body", "")), max_chars=max_body_chars)

            parameter = str(evidence.get("tested_parameter", evidence.get("parameter", "")))
            lines = [
                f"# {title}",
                "",
                "## Vulnerability Type & Business Impact",
                f"- Type: `{category}`",
                f"- Severity: `{severity}`",
                f"- Impact: {impact}",
                "",
                "## Affected Endpoint & Parameters",
                f"- Endpoint: `{endpoint}`",
                f"- Parameter: `{parameter}`",
                "",
                "## Technical Evidence",
                "### Request A (Auth Context A)",
                f"- Method: `{str(req_a.get('method', 'GET')).upper()}`",
                f"- URL: `{str(req_a.get('url', ''))}`",
                f"- Headers: `{json.dumps(redacted_a, ensure_ascii=True)}`",
                "",
                "### Request B (Auth Context B)",
                f"- Method: `{str(req_b.get('method', 'GET')).upper()}`",
                f"- URL: `{str(req_b.get('url', ''))}`",
                f"- Headers: `{json.dumps(redacted_b, ensure_ascii=True)}`",
                "",
                "### Request C (Unauthenticated)",
                f"- Method: `{str(req_c.get('method', 'GET')).upper()}`",
                f"- URL: `{str(req_c.get('url', ''))}`",
                f"- Headers: `{json.dumps(redacted_c, ensure_ascii=True)}`",
                "",
                "### Response Summary",
                f"- Auth A status/length: `{resp_a.get('status', 0)}` / `{resp_a.get('length', 0)}`",
                f"- Auth B status/length: `{resp_b.get('status', 0)}` / `{resp_b.get('length', 0)}`",
                f"- Unauth status/length: `{resp_c.get('status', 0)}` / `{resp_c.get('length', 0)}`",
                "",
                "## Raw Request/Response Logs (Redacted)",
                "### Request A",
                "```http",
                f"{str(req_a.get('method', 'GET')).upper()} {str(req_a.get('url', ''))}",
                f"Headers: {json.dumps(redacted_a, ensure_ascii=True)}",
                "```",
                "",
                "### Response A",
                "```http",
                f"Status: {resp_a.get('status', 0)}",
                f"Headers: {json.dumps(resp_a.get('headers', {}), ensure_ascii=True)}",
                body_a,
                "```",
                "",
                "### Request B",
                "```http",
                f"{str(req_b.get('method', 'GET')).upper()} {str(req_b.get('url', ''))}",
                f"Headers: {json.dumps(redacted_b, ensure_ascii=True)}",
                "```",
                "",
                "### Response B",
                "```http",
                f"Status: {resp_b.get('status', 0)}",
                f"Headers: {json.dumps(resp_b.get('headers', {}), ensure_ascii=True)}",
                body_b,
                "```",
                "",
                "### Request C (Unauthenticated)",
                "```http",
                f"{str(req_c.get('method', 'GET')).upper()} {str(req_c.get('url', ''))}",
                f"Headers: {json.dumps(redacted_c, ensure_ascii=True)}",
                "```",
                "",
                "### Response C (Unauthenticated)",
                "```http",
                f"Status: {resp_c.get('status', 0)}",
                f"Headers: {json.dumps(resp_c.get('headers', {}), ensure_ascii=True)}",
                body_c,
                "```",
                "",
                "## Steps to Reproduce",
                "1. Authenticate with context A and request the endpoint using the parameter shown above.",
                "2. Replay the same request with context B (another account).",
                "3. Replay without authentication.",
                "4. Compare status, structure, and leaked entity markers.",
                "",
                "## Confidence",
                f"- Confidence Score: `{confidence}`",
                f"- Leaked Entities Detected: `{leaked_count}`",
                f"- Discovery Source: `{meta.get('discovery_source', row.get('plugin', self.name))}`",
                "",
            ]
            await write_text(report_path, "\n".join(lines))
            secure_secret_file(report_path)
            generated.append(
                Finding(
                    plugin=self.name,
                    target=task.target,
                    category="evidence_bundle",
                    severity="info",
                    title=f"Evidence bundle generated for {title}",
                    evidence={
                        "report_path": str(report_path),
                        "endpoint": endpoint,
                        "category": category,
                        "impact": impact,
                        "confidence_score": confidence,
                    },
                    metadata={
                        "novelty": 78,
                        "confidence": confidence,
                        "confidence_score": confidence,
                        "impact": float(meta.get("impact", 70) or 70),
                        "discovery_source": self.name,
                        "report_path": str(report_path),
                    },
                )
            )
        return generated
