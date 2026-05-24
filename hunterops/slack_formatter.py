from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hunterops.types import Finding


def _truncate(text: str, limit: int) -> str:
    raw = str(text or "")
    if len(raw) <= limit:
        return raw
    return f"{raw[:limit]}...[+{len(raw) - limit} chars]"


def _report_url(report_path: str, report_url_base: str) -> str:
    path = Path(str(report_path or "").strip())
    if not path:
        return ""
    base = str(report_url_base or "").strip().rstrip("/")
    if not base:
        return ""
    raw = path.as_posix()
    if raw.startswith("/opt/hunterops/"):
        raw = raw.replace("/opt/hunterops/", "", 1)
    return f"{base}/{raw.lstrip('/')}"


def build_finding_blocks(
    *,
    finding: Finding,
    run_id: str,
    endpoint_text: str,
    vuln_type: str,
    confidence_score: float,
    impact_score: float,
    severity_label: str,
    curl_command: str,
    poc_snippet: str,
    report_path: str,
    report_url_base: str,
) -> dict[str, Any]:
    title = f"[{severity_label}] Potential Security Finding on {finding.target}"
    body = (
        f"*Endpoint:* `{_truncate(endpoint_text, 200)}`\n"
        f"*Vulnerability Type:* `{_truncate(vuln_type, 80)}`\n"
        f"*Confidence:* `{round(float(confidence_score), 2)}%`\n"
        f"*Calculated Impact:* `{round(float(impact_score), 2)}/100`\n\n"
        "*Golden Evidence (curl)*\n"
        f"```bash\n{_truncate(curl_command, 1800)}\n```"
    )
    if str(poc_snippet or "").strip():
        body += f"\n*PoC Snippet*\n```markdown\n{_truncate(poc_snippet, 1300)}\n```"
    blocks: list[dict[str, Any]] = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{_truncate(title, 180)}*\n{_truncate(body, 2800)}",
            },
        },
        {
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"`run_id={_truncate(run_id, 64)}`"},
                {"type": "mrkdwn", "text": f"`plugin={_truncate(finding.plugin, 64)}`"},
                {"type": "mrkdwn", "text": f"`ts={datetime.now(UTC).isoformat().replace('+00:00', 'Z')}`"},
            ],
        },
    ]
    link = _report_url(report_path, report_url_base)
    if link:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Full Report"},
                        "url": link,
                    }
                ],
            }
        )
    elif str(report_path or "").strip():
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"*Report Path:* `{_truncate(report_path, 220)}`"},
                ],
            }
        )
    return {"text": _truncate(title, 150), "blocks": blocks}


def build_critical_log_blocks(*, message: str, run_id: str) -> dict[str, Any]:
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    blocks = [
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*CRITICAL LOG SIGNAL*\n```{_truncate(message, 2500)}```"}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"`run_id={_truncate(run_id, 64)}`"}, {"type": "mrkdwn", "text": f"`ts={now}`"}]},
    ]
    return {"text": "CRITICAL LOG SIGNAL", "blocks": blocks}

