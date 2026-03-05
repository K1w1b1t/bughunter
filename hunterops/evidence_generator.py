from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hunterops.types import Finding


def _mask_value(value: str) -> str:
    raw = str(value or "")
    if len(raw) <= 8:
        return "*" * len(raw)
    return f"{raw[:4]}...{raw[-4:]}"


def _mask_headers(headers: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in headers.items():
        key = str(k)
        val = str(v)
        lk = key.lower()
        if lk == "authorization":
            parts = val.split(" ", 1)
            if len(parts) == 2:
                out[key] = f"{parts[0]} {_mask_value(parts[1])}"
            else:
                out[key] = _mask_value(val)
        elif lk == "cookie" or "token" in lk or "secret" in lk or "api-key" in lk:
            out[key] = _mask_value(val)
        else:
            out[key] = val
    return out


def _curl(method: str, url: str, headers: dict[str, Any]) -> str:
    cmd = f"curl -i -X {method.upper()} \"{url}\""
    for hk, hv in _mask_headers(headers).items():
        cmd += f" -H \"{hk}: {hv}\""
    return cmd


def _impact(category: str) -> str:
    c = category.lower()
    if "oob" in c:
        return "O servidor do alvo tentou conectar-se ao nosso listener externo, confirmando Blind SSRF/RCE."
    if "idor" in c:
        return "An attacker can enumerate object identifiers and access data from other users or tenants."
    if "auth" in c and "bypass" in c:
        return "An attacker can bypass authorization boundaries and reach restricted resources."
    if "logic" in c:
        return "An attacker can abuse state transitions to obtain unauthorized outcomes."
    return "An attacker can access sensitive information without proper authorization checks."


def _to_row(f: Finding) -> dict[str, Any]:
    meta = f.metadata if isinstance(f.metadata, dict) else {}
    ev = f.evidence if isinstance(f.evidence, dict) else {}
    return {
        "plugin": f.plugin,
        "target": f.target,
        "category": f.category,
        "severity": f.severity,
        "title": f.title,
        "confidence": float(meta.get("confidence_score", meta.get("confidence", 0)) or 0),
        "evidence": ev,
        "metadata": meta,
    }


def generate_research_artifacts(
    findings: list[Finding],
    out_root: Path,
    run_id: str,
    min_confidence: float = 85.0,
) -> dict[str, Any]:
    run_dir = out_root / f"run_{run_id}"
    run_dir.mkdir(parents=True, exist_ok=True)

    json_rows = [_to_row(f) for f in findings]
    (run_dir / "findings.json").write_text(
        json.dumps({"run_id": run_id, "count": len(json_rows), "findings": json_rows}, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )

    generated: list[dict[str, Any]] = []
    idx = 0
    for f in findings:
        meta = f.metadata if isinstance(f.metadata, dict) else {}
        confidence = float(meta.get("confidence_score", meta.get("confidence", 0)) or 0)
        if confidence < min_confidence:
            continue
        category = f.category.lower()
        if not any(k in category for k in ("idor", "auth_bypass", "auth", "logic", "oob")):
            continue
        ev = f.evidence if isinstance(f.evidence, dict) else {}
        req_auth = ev.get("request_auth_a", ev.get("request", {})) if isinstance(ev.get("request_auth_a", ev.get("request", {})), dict) else {}
        req_unauth = ev.get("request_auth_b", ev.get("request_unauthenticated", ev.get("request", {}))) if isinstance(ev.get("request_auth_b", ev.get("request_unauthenticated", ev.get("request", {}))), dict) else {}
        resp_auth = ev.get("response_auth_a", ev.get("response", {})) if isinstance(ev.get("response_auth_a", ev.get("response", {})), dict) else {}
        resp_unauth = ev.get("response_auth_b", ev.get("response_unauthenticated", ev.get("response", {}))) if isinstance(ev.get("response_auth_b", ev.get("response_unauthenticated", ev.get("response", {}))), dict) else {}

        base_method = str(req_auth.get("method", "GET"))
        base_url = str(req_auth.get("url", ""))
        base_headers = req_auth.get("headers", {}) if isinstance(req_auth.get("headers"), dict) else {}
        exploit_method = str(req_unauth.get("method", "GET"))
        exploit_url = str(req_unauth.get("url", ""))
        exploit_headers = req_unauth.get("headers", {}) if isinstance(req_unauth.get("headers"), dict) else {}

        idx += 1
        report_path = run_dir / f"autopoc_{idx:03d}.md"
        content = [
            f"# {f.title}",
            "",
            "## Impact",
            _impact(f.category),
            "",
            "## Reproduction",
            "1. Authorized/Owner request:",
            f"```bash\n{_curl(base_method, base_url, base_headers)}\n```",
            "2. Unauthorized/Other context request:",
            f"```bash\n{_curl(exploit_method, exploit_url, exploit_headers)}\n```",
            "",
            "## Side-by-Side Response Comparison",
            "| Context | Status | Length |",
            "|---|---:|---:|",
            f"| Authorized | {int(resp_auth.get('status', 0) or 0)} | {int(resp_auth.get('length', 0) or 0)} |",
            f"| Unauthorized | {int(resp_unauth.get('status', 0) or 0)} | {int(resp_unauth.get('length', 0) or 0)} |",
            "",
            "## Raw Evidence",
            f"- Discovery source: {meta.get('discovery_source', f.plugin)}",
            f"- Timestamp: {datetime.now(UTC).isoformat().replace('+00:00', 'Z')}",
            "",
        ]
        if "oob" in category:
            content.extend(
                [
                    "## OOB Confirmation",
                    "O servidor do alvo tentou conectar-se ao nosso listener externo, confirmando Blind SSRF/RCE.",
                    "",
                ]
            )
        report_path.write_text("\n".join(content), encoding="utf-8")
        generated.append(
            {
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "confidence": confidence,
                "report_path": str(report_path),
            }
        )

    (run_dir / "autopoc_index.json").write_text(
        json.dumps({"run_id": run_id, "count": len(generated), "items": generated}, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return {"run_dir": str(run_dir), "generated_reports": len(generated), "index_file": str(run_dir / "autopoc_index.json")}
