from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def save_http_evidence(
    root: Path,
    plugin: str,
    target: str,
    request_data: dict[str, Any],
    response_data: dict[str, Any],
) -> dict[str, str]:
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S_%f")
    safe_target = target.replace("*", "wildcard").replace("/", "_")
    d = root / plugin / safe_target
    d.mkdir(parents=True, exist_ok=True)
    req_file = d / f"{ts}_request.json"
    resp_file = d / f"{ts}_response.json"
    req_file.write_text(json.dumps(request_data, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    resp_file.write_text(json.dumps(response_data, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    return {"request_file": str(req_file), "response_file": str(resp_file), "timestamp_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z")}

