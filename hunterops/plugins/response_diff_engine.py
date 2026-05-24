from __future__ import annotations

import hashlib
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from hunterops.http_client import json_keys, request_http_async
from hunterops.intelligence import http_diff_score
from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task


def toggle_variant(url: str) -> str:
    p = urlparse(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    q.append(("view", "summary"))
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(q), p.fragment))


class PluginImpl(Plugin):
    name = "response_diff_engine"

    async def run(self, task: Task, context: dict) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get(self.name, {})
        timeout = int(context["runtime"]["timeout_seconds"])
        base = f"https://{task.target}"
        paths = cfg.get("paths", ["/api/me", "/api/profile", "/api/orders?id=1", "/search?q=test"])

        findings: list[Finding] = []
        seen_signatures: set[str] = set()
        for p in paths:
            url = p if p.startswith("http") else f"{base}{p}"
            alt = toggle_variant(url)
            r1 = await request_http_async("GET", url, headers={}, timeout=timeout)
            r2 = await request_http_async("GET", alt, headers={}, timeout=timeout)

            keys_a = json_keys(str(r1.get("text", "")))
            keys_b = json_keys(str(r2.get("text", "")))
            d = http_diff_score(
                {"status": r1.get("status", 0), "length": r1.get("length", 0), "json_keys": keys_a},
                {"status": r2.get("status", 0), "length": r2.get("length", 0), "json_keys": keys_b},
            )
            status_base = int(r1.get("status", 0) or 0)
            status_variant = int(r2.get("status", 0) or 0)
            endpoint = urlparse(url).path or "/"
            is_newly_exposed = status_base in {0, 404} and status_variant in {200, 201, 401, 403}
            anomaly_score = int(d.get("anomaly_score", 0) or 0)
            if not is_newly_exposed and anomaly_score < 40:
                continue

            signature_raw = {
                "endpoint": endpoint,
                "status_base": status_base,
                "status_variant": status_variant,
                "json_keys_base": keys_a,
                "json_keys_variant": keys_b,
                "length_base": int(r1.get("length", 0) or 0),
                "length_variant": int(r2.get("length", 0) or 0),
                "delta_kind": "newly_exposed" if is_newly_exposed else "response_anomaly",
            }
            signature = hashlib.sha256(str(signature_raw).encode("utf-8")).hexdigest()
            if signature in seen_signatures:
                continue
            seen_signatures.add(signature)

            severity = "high" if is_newly_exposed else "medium"
            confidence_score = 86.0 if is_newly_exposed else min(95.0, 46.0 + (anomaly_score * 0.8))
            category = "newly_exposed_endpoint" if is_newly_exposed else "response_anomaly"
            findings.append(
                Finding(
                    plugin=self.name,
                    target=task.target,
                    category=category,
                    severity=severity,
                    title="Response diff anomaly detected between baseline and variant",
                    evidence={
                        "endpoint": endpoint,
                        "base_url": url,
                        "variant_url": alt,
                        "base_status": status_base,
                        "variant_status": status_variant,
                        "base_length": int(r1.get("length", 0) or 0),
                        "variant_length": int(r2.get("length", 0) or 0),
                        "base_json_keys": keys_a,
                        "variant_json_keys": keys_b,
                        "diff": d,
                    },
                    metadata={
                        "novelty": 84 if is_newly_exposed else 74,
                        "confidence": confidence_score,
                        "confidence_score": confidence_score,
                        "impact": 78 if is_newly_exposed else 58,
                        "priority_score": 100 if is_newly_exposed else 72,
                        "discovery_source": "response_diff_engine",
                        "delta_kind": "newly_exposed" if is_newly_exposed else "changed_behavior",
                        "endpoint": endpoint,
                        "structural_hash": signature,
                    },
                )
            )
        return findings
