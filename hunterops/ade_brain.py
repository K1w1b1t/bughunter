from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from hunterops.http_client import request_http_async
from hunterops.plugin_base import Plugin
from hunterops.runtime_paths import ensure_directory, resolve_path
from hunterops.types import Finding, Task

CRITICAL_ENDPOINT_HINTS = ("admin", "v1", "api/v2", "debug", "config", "user")
CHAIN_PARAM_NAMES = {"uuid", "user_id", "account_id"}
NUMERIC_PARAM_HINTS = ("id", "uid", "account", "user", "order", "invoice", "profile")
BOUNDARY_VALUES = ("0", "-1", "999999", "null")
IDOR_CATEGORIES = {
    "idor_logic_signal",
    "critical_idor_vulnerability",
    "idor_behavior_indicator",
    "Potential_IDOR_Signal",
    "Broken_Object_Level_Authorization",
}


def _normalize_endpoint(raw: str) -> str:
    value = str(raw or "").strip()
    if not value:
        return "/"
    if value.startswith("http://") or value.startswith("https://"):
        parsed = urlparse(value)
        out = parsed.path or "/"
        return out if out.startswith("/") else f"/{out}"
    parsed = urlparse(value)
    out = parsed.path or value
    return out if out.startswith("/") else f"/{out}"


def _set_query(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    items = parse_qsl(parsed.query, keep_blank_values=True)
    items = [item for item in items if item[0] != key]
    items.append((key, value))
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(items), parsed.fragment))


def _json_shape(text: str) -> set[str]:
    try:
        obj = json.loads(text)
    except Exception:
        return set()

    def _walk(value: Any, prefix: str = "") -> set[str]:
        out: set[str] = set()
        if isinstance(value, dict):
            for key, child in value.items():
                key_s = str(key)
                path = f"{prefix}.{key_s}" if prefix else key_s
                out.add(path)
                out |= _walk(child, path)
        elif isinstance(value, list):
            path = f"{prefix}[]" if prefix else "[]"
            out.add(path)
            for item in value[:8]:
                out |= _walk(item, path)
        return out

    return _walk(obj)


def _shape_similarity(a: str, b: str) -> float:
    ta = _json_shape(a)
    tb = _json_shape(b)
    if not ta and not tb:
        return 100.0
    return round((len(ta & tb) / max(1, len(ta | tb))) * 100.0, 2)


def _significant_length_diff(a: int, b: int) -> bool:
    aa = int(a or 0)
    bb = int(b or 0)
    delta = abs(aa - bb)
    if delta >= 120:
        return True
    base = min(aa, bb)
    if base <= 0:
        return delta >= 60
    return (delta / max(1, base)) >= 0.3


def _extract_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw = payload.get("round_findings", [])
    if not isinstance(raw, list):
        return []
    return [row for row in raw if isinstance(row, dict)]


def _extract_endpoints_from_row(row: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    evidence = row.get("evidence", {}) if isinstance(row.get("evidence"), dict) else {}
    metadata = row.get("metadata", {}) if isinstance(row.get("metadata"), dict) else {}
    candidates = []
    for key in ("endpoints", "known_endpoints"):
        vals = evidence.get(key, [])
        if isinstance(vals, list):
            candidates.extend([x for x in vals if isinstance(x, str)])
        vals_m = metadata.get(key, [])
        if isinstance(vals_m, list):
            candidates.extend([x for x in vals_m if isinstance(x, str)])
    for item in candidates:
        out.add(_normalize_endpoint(item))
    return out


@dataclass
class _ParamCtx:
    endpoint: str
    parameter: str
    param_type: str


def _extract_param_contexts(rows: list[dict[str, Any]]) -> list[_ParamCtx]:
    out: list[_ParamCtx] = []
    dedupe: set[str] = set()
    for row in rows:
        evidence = row.get("evidence", {}) if isinstance(row.get("evidence"), dict) else {}
        category = str(row.get("category", "")).strip()
        plugin = str(row.get("plugin", "")).strip()
        if plugin == "parameter_intelligence" and category == "parameter_intelligence":
            sample = evidence.get("parameter_map_sample", [])
            if isinstance(sample, list):
                for item in sample:
                    if not isinstance(item, dict):
                        continue
                    endpoint = _normalize_endpoint(str(item.get("endpoint", "")))
                    parameter = str(item.get("parameter", "")).strip()
                    ptype = str(item.get("type", "string")).strip().lower()
                    if not endpoint or not parameter:
                        continue
                    sig = f"{endpoint}|{parameter.lower()}|{ptype}"
                    if sig in dedupe:
                        continue
                    dedupe.add(sig)
                    out.append(_ParamCtx(endpoint=endpoint, parameter=parameter, param_type=ptype))

        if plugin == "parameter_intelligence" and category == "idor_logic_signal":
            endpoint = _normalize_endpoint(str(evidence.get("endpoint", evidence.get("base_url", ""))))
            parameter = str(evidence.get("tested_parameter", "")).strip()
            if endpoint and parameter:
                sig = f"{endpoint}|{parameter.lower()}|numeric_id"
                if sig not in dedupe:
                    dedupe.add(sig)
                    out.append(_ParamCtx(endpoint=endpoint, parameter=parameter, param_type="numeric_id"))
    return out


def _default_impact_text(url: str, parameter: str) -> str:
    return (
        "A resposta retornou dados inconsistentes entre contextos/autores, "
        f"sugerindo vazamento de objeto via parametro '{parameter}' em {url}."
    )


class PluginImpl(Plugin):
    name = "ade_brain"

    def _evidence_dir(self, context: dict[str, Any]) -> Path:
        cfg = context.get("config", {}).get("modules", {}).get(self.name, {})
        raw = str(cfg.get("evidence_dir", "data/evidence/ade")).strip()
        out = ensure_directory(resolve_path(raw, prefer_existing=False), mode=0o755)
        return out

    @staticmethod
    def _build_curl(url: str, headers: dict[str, Any] | None = None) -> str:
        header_lines: list[str] = []
        if isinstance(headers, dict):
            for key, value in list(headers.items())[:12]:
                k = str(key).strip()
                v = str(value).strip()
                if not k or not v:
                    continue
                header_lines.append(f"-H '{k}: {v}'")
        header_part = " ".join(header_lines)
        return f"curl -i -sS -X GET '{url}' {header_part}".strip()

    def _write_idor_evidence(
        self,
        *,
        context: dict[str, Any],
        target: str,
        run_id: str,
        url: str,
        parameter: str,
        curl_cmd: str,
        impact: str,
        source_title: str,
        source_plugin: str,
    ) -> str:
        out_dir = self._evidence_dir(context)
        seed = f"{run_id}|{target}|{url}|{parameter}|{time.time()}"
        evidence_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:10]
        path = out_dir / f"evidence_{evidence_id}.md"
        lines = [
            f"# HunterOps ADE Evidence {evidence_id}",
            "",
            f"- Generated: {datetime.now(UTC).isoformat().replace('+00:00', 'Z')}",
            f"- Run ID: `{run_id}`",
            f"- Target: `{target}`",
            f"- Source Plugin: `{source_plugin}`",
            f"- Source Finding: {source_title}",
            "",
            "## URL Afetada",
            f"`{url}`",
            "",
            "## Parametro Vulneravel",
            f"`{parameter or 'id'}`",
            "",
            "## Requisicao (CURL)",
            "```bash",
            curl_cmd,
            "```",
            "",
            "## Prova de Vazamento (Impacto)",
            impact,
            "",
        ]
        path.write_text("\n".join(lines), encoding="utf-8")
        return str(path)

    @staticmethod
    def _idor_evidence_details(row: dict[str, Any]) -> dict[str, Any] | None:
        category = str(row.get("category", "")).strip()
        if category not in IDOR_CATEGORIES:
            return None
        evidence = row.get("evidence", {}) if isinstance(row.get("evidence"), dict) else {}
        response_a = evidence.get("response_auth_a", {}) if isinstance(evidence.get("response_auth_a"), dict) else {}
        response_b = evidence.get("response_auth_b", {}) if isinstance(evidence.get("response_auth_b"), dict) else {}
        base_resp = evidence.get("base_response", {}) if isinstance(evidence.get("base_response"), dict) else {}
        mod_resp = evidence.get("modified_response", {}) if isinstance(evidence.get("modified_response"), dict) else {}
        status_a = int(response_a.get("status", base_resp.get("status", 0)) or 0)
        status_b = int(response_b.get("status", mod_resp.get("status", 0)) or 0)
        len_a = int(response_a.get("length", base_resp.get("length", 0)) or 0)
        len_b = int(response_b.get("length", mod_resp.get("length", 0)) or 0)

        diff_map = evidence.get("diff_map", {}) if isinstance(evidence.get("diff_map"), dict) else {}
        leaked_ids = evidence.get("leaked_identifiers", []) if isinstance(evidence.get("leaked_identifiers"), list) else []
        leaked_entities = evidence.get("leaked_entities", []) if isinstance(evidence.get("leaked_entities"), list) else []
        sensitive_hits = diff_map.get("sensitive_object_hits", []) if isinstance(diff_map.get("sensitive_object_hits"), list) else []
        content_similarity = float(diff_map.get("content_similarity_pct", 100) or 100)

        cross_data = bool(leaked_ids or leaked_entities or sensitive_hits or content_similarity < 95.0)
        size_delta = _significant_length_diff(len_a, len_b)
        if status_a == 200 and status_b == 200 and (cross_data or size_delta):
            request_b = evidence.get("request_auth_b", {}) if isinstance(evidence.get("request_auth_b"), dict) else {}
            request = evidence.get("request", {}) if isinstance(evidence.get("request"), dict) else {}
            url = str(
                request_b.get("url")
                or request.get("url")
                or evidence.get("modified_url")
                or evidence.get("url")
                or evidence.get("base_url")
                or ""
            ).strip()
            parameter = str(
                evidence.get("tested_parameter")
                or evidence.get("parameter")
                or diff_map.get("parameter")
                or ""
            ).strip()
            headers = request_b.get("headers") if isinstance(request_b.get("headers"), dict) else request.get("headers", {})
            impact = _default_impact_text(url, parameter or "id")
            if leaked_ids:
                impact += f" Indicadores expostos: {', '.join([str(x) for x in leaked_ids[:5]])}."
            if sensitive_hits:
                impact += f" Objetos sensiveis detectados: {', '.join([str(x) for x in sensitive_hits[:5]])}."
            return {
                "url": url,
                "parameter": parameter,
                "headers": headers if isinstance(headers, dict) else {},
                "impact": impact,
            }
        return None

    @staticmethod
    def _critical_endpoints(rows: list[dict[str, Any]]) -> set[str]:
        out: set[str] = set()
        for row in rows:
            if str(row.get("plugin", "")) != "deep_js_intelligence":
                continue
            if str(row.get("category", "")) != "js_discovery":
                continue
            for endpoint in _extract_endpoints_from_row(row):
                lowered = endpoint.lower()
                if any(token in lowered for token in CRITICAL_ENDPOINT_HINTS):
                    out.add(endpoint)
        return out

    @staticmethod
    def _is_numeric_candidate(parameter: str, param_type: str) -> bool:
        p = str(parameter).strip().lower()
        t = str(param_type).strip().lower()
        if t in {"numeric_id", "number", "identifier"}:
            return True
        return any(hint in p for hint in NUMERIC_PARAM_HINTS)

    async def _probe_boundaries(
        self,
        *,
        target: str,
        ctx: _ParamCtx,
        timeout: int,
    ) -> list[Finding]:
        endpoint = _normalize_endpoint(ctx.endpoint)
        base_url = f"https://{target}{endpoint}"
        baseline_url = _set_query(base_url, ctx.parameter, "1")
        baseline = await request_http_async("GET", baseline_url, timeout=timeout)
        baseline_text = str(baseline.get("text", ""))
        baseline_status = int(baseline.get("status", 0) or 0)
        baseline_length = int(baseline.get("length", 0) or 0)

        findings: list[Finding] = []
        for boundary_value in BOUNDARY_VALUES:
            probe_url = _set_query(base_url, ctx.parameter, boundary_value)
            probe = await request_http_async("GET", probe_url, timeout=timeout)
            status = int(probe.get("status", 0) or 0)
            length = int(probe.get("length", 0) or 0)
            text = str(probe.get("text", ""))
            shape_similarity = _shape_similarity(baseline_text, text)
            length_anomaly = _significant_length_diff(baseline_length, length)
            status_anomaly = status in {200, 201} and baseline_status in {0, 401, 403, 404}
            structure_anomaly = shape_similarity < 70.0
            if not (length_anomaly or status_anomaly or structure_anomaly):
                continue

            confidence = 72.0
            if status_anomaly:
                confidence += 15.0
            if length_anomaly:
                confidence += 8.0
            if structure_anomaly:
                confidence += 8.0
            confidence = min(96.0, confidence)

            findings.append(
                Finding(
                    plugin=self.name,
                    target=target,
                    category="state_machine_boundary_anomaly",
                    severity="high" if status_anomaly else "medium",
                    title=f"Boundary anomaly on {endpoint} parameter {ctx.parameter}={boundary_value}",
                    evidence={
                        "endpoint": endpoint,
                        "parameter": ctx.parameter,
                        "baseline_url": baseline_url,
                        "probe_url": probe_url,
                        "baseline_response": {"status": baseline_status, "length": baseline_length},
                        "probe_response": {"status": status, "length": length},
                        "shape_similarity_pct": shape_similarity,
                        "length_delta": abs(baseline_length - length),
                        "status_anomaly": status_anomaly,
                        "structure_anomaly": structure_anomaly,
                    },
                    metadata={
                        "novelty": 86,
                        "confidence": confidence,
                        "confidence_score": confidence,
                        "impact": 78.0 if status_anomaly else 65.0,
                        "priority_score": 98.0 if status_anomaly else 88.0,
                        "discovery_source": self.name,
                    },
                )
            )
        return findings

    async def run(self, task: Task, context: dict[str, Any]) -> list[Finding]:
        payload = task.payload if isinstance(task.payload, dict) else {}
        run_id = str(payload.get("run_id", "")).strip()
        rows = _extract_findings(payload)
        if not rows:
            return []

        runtime = context.get("runtime", {}) if isinstance(context.get("runtime"), dict) else {}
        timeout = int(runtime.get("timeout_seconds", 25))
        cfg = context.get("config", {}).get("modules", {}).get(self.name, {})
        max_spawn_tasks = max(1, int(cfg.get("max_spawn_tasks", 220)))
        max_boundary_candidates = max(1, int(cfg.get("max_boundary_candidates", 30)))

        spawn_tasks: list[dict[str, Any]] = []
        dedupe_tasks: set[str] = set()
        findings: list[Finding] = []
        evidence_reports: list[str] = []

        def _append_task(plugin: str, seed_path: str, trigger: str, priority: float = 100.0) -> None:
            endpoint = _normalize_endpoint(seed_path)
            payload_inner = {
                "run_id": run_id,
                "seed_paths": [endpoint],
                "trigger": trigger,
                "priority": float(priority),
                "priority_score": float(priority),
                "priority_level": "CRITICAL",
                "_depth": int(payload.get("_depth", 0) or 0) + 1,
            }
            signature = f"{plugin}|{task.target}|{json.dumps(payload_inner, sort_keys=True, ensure_ascii=True)}"
            if signature in dedupe_tasks:
                return
            dedupe_tasks.add(signature)
            spawn_tasks.append(
                {
                    "plugin": plugin,
                    "target": task.target,
                    "payload": payload_inner,
                }
            )

        # 1) Priority heuristic from Deep JS discoveries.
        critical_endpoints = sorted(list(self._critical_endpoints(rows)))
        for endpoint in critical_endpoints:
            _append_task("parameter_intelligence", endpoint, "ade_critical_endpoint", priority=100.0)

        # 2) Recursive chaining decisions + 3) boundary probing for numeric parameters.
        param_contexts = _extract_param_contexts(rows)
        boundary_candidates: list[_ParamCtx] = []
        for item in param_contexts:
            param_lower = item.parameter.strip().lower()
            if param_lower in CHAIN_PARAM_NAMES or item.param_type == "uuid":
                _append_task("differential_auth_prover", item.endpoint, "ade_recursive_auth_chain", priority=100.0)
            if self._is_numeric_candidate(item.parameter, item.param_type):
                boundary_candidates.append(item)

        for item in boundary_candidates[:max_boundary_candidates]:
            probe_findings = await self._probe_boundaries(target=task.target, ctx=item, timeout=timeout)
            findings.extend(probe_findings)
            if probe_findings:
                _append_task("differential_auth_prover", item.endpoint, "ade_boundary_anomaly_chain", priority=99.0)

        # 4) Evidence/auto-poc markdown for IDOR-like anomalies.
        for row in rows:
            details = self._idor_evidence_details(row)
            if not details:
                continue
            url = str(details.get("url", "")).strip()
            if not url:
                continue
            parameter = str(details.get("parameter", "")).strip() or "id"
            headers = details.get("headers", {}) if isinstance(details.get("headers"), dict) else {}
            curl_cmd = self._build_curl(url, headers=headers)
            impact = str(details.get("impact", _default_impact_text(url, parameter)))
            report_path = self._write_idor_evidence(
                context=context,
                target=task.target,
                run_id=run_id,
                url=url,
                parameter=parameter,
                curl_cmd=curl_cmd,
                impact=impact,
                source_title=str(row.get("title", "")),
                source_plugin=str(row.get("plugin", "")),
            )
            evidence_reports.append(report_path)

        spawn_tasks = spawn_tasks[:max_spawn_tasks]
        if findings or spawn_tasks or evidence_reports:
            findings.append(
                Finding(
                    plugin=self.name,
                    target=task.target,
                    category="ade_decision_cycle",
                    severity="info",
                    title=f"ADE decided {len(spawn_tasks)} next tasks and generated {len(evidence_reports)} evidence reports",
                    evidence={
                        "critical_endpoints": critical_endpoints[:120],
                        "boundary_candidates": [f"{x.endpoint}?{x.parameter}" for x in boundary_candidates[:120]],
                        "evidence_reports": evidence_reports[:120],
                    },
                    metadata={
                        "priority_level": "CRITICAL" if critical_endpoints else "HIGH",
                        "novelty": 84.0,
                        "confidence": 86.0,
                        "confidence_score": 86.0,
                        "impact": 73.0,
                        "priority_score": 100.0 if critical_endpoints else 90.0,
                        "discovery_source": self.name,
                        "spawn_tasks": spawn_tasks,
                    },
                )
            )

        return findings
