from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from hunterops.http_client import json_keys, request_http_async
from hunterops.intelligence import http_diff_score
from hunterops.plugin_base import Plugin
from hunterops.session_profiles import auth_header, load_sessions
from hunterops.types import Finding, Task


def add_query(url: str, key: str, value: str) -> str:
    p = urlparse(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    q.append((key, value))
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(q), p.fragment))


def _path(value: str):
    from pathlib import Path

    return Path(value)


class PluginImpl(Plugin):
    name = "behavioral_diff_engine"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        timeout = int(context["runtime"]["timeout_seconds"])
        base = f"https://{task.target}"
        payload = task.payload if isinstance(task.payload, dict) else {}
        paths = payload.get("paths") if isinstance(payload.get("paths"), list) else cfg.get("paths", ["/api/me", "/api/profile", "/search?q=test"])
        sessions = load_sessions(_path(cfg.get("sessions_file", "data/sessions.yaml")))
        leaked_indicators = payload.get("leaked_indicators", []) if isinstance(payload.get("leaked_indicators"), list) else []

        findings: list[Finding] = []
        for p in paths:
            url = p if p.startswith("http") else f"{base}{p}"
            base_resp = await request_http_async("GET", url, headers={}, timeout=timeout)
            variant_url = add_query(url, "view", "summary")
            if leaked_indicators:
                variant_url = add_query(variant_url, "identifier", str(leaked_indicators[0]))
            variant_resp = await request_http_async("GET", variant_url, headers={"X-Requested-With": "XMLHttpRequest"}, timeout=timeout)
            base_meta = {"status": base_resp.get("status", 0), "length": base_resp.get("length", 0), "json_keys": json_keys(str(base_resp.get("text", "")))}
            var_meta = {"status": variant_resp.get("status", 0), "length": variant_resp.get("length", 0), "json_keys": json_keys(str(variant_resp.get("text", "")))}
            diff = http_diff_score(base_meta, var_meta)

            auth_diffs: list[dict[str, object]] = []
            for s_name, s_cfg in sessions.items():
                hdr = auth_header(s_cfg)
                ar = await request_http_async("GET", url, headers=hdr, timeout=timeout)
                ad = http_diff_score(base_meta, {"status": ar.get("status", 0), "length": ar.get("length", 0), "json_keys": json_keys(str(ar.get("text", "")))})
                if ad["anomaly_score"] >= 40:
                    auth_diffs.append({"session": s_name, "diff": ad, "status": ar.get("status", 0), "length": ar.get("length", 0)})

            sensitive_fields = []
            txt = str(variant_resp.get("text", "")).lower()
            for k in ("email", "cpf", "phone", "address", "account", "token"):
                if k in txt:
                    sensitive_fields.append(k)

            if diff["anomaly_score"] >= 40 or auth_diffs:
                findings.append(
                    Finding(
                        plugin=self.name,
                        target=task.target,
                        category="behavioral_response_anomaly",
                        severity="medium",
                        title="Behavioral response anomaly detected",
                        evidence={
                            "request": {"method": "GET", "url": variant_url, "headers": {"X-Requested-With": "XMLHttpRequest"}},
                            "response": {"status": variant_resp.get("status", 0), "length": variant_resp.get("length", 0)},
                            "headers": variant_resp.get("headers", {}),
                            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                            "discovery_source": "behavioral_diff_engine",
                            "base_url": url,
                            "variant_url": variant_url,
                            "base_vs_variant_diff": diff,
                            "auth_context_diffs": auth_diffs,
                            "sensitive_field_indicators": sorted(set(sensitive_fields)),
                            "leaked_indicators": leaked_indicators[:20],
                        },
                        metadata={
                            "novelty": 77,
                            "confidence": 71,
                            "impact": 60,
                            "discovery_source": "behavioral_diff",
                            "anomaly_score": max([diff["anomaly_score"]] + [int(x["diff"]["anomaly_score"]) for x in auth_diffs] if auth_diffs else [diff["anomaly_score"]]),
                        },
                    )
                )
        return findings
