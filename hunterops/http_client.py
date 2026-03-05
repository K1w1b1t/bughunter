from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import asyncio


def request_http(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | str | None = None,
    timeout: int = 20,
) -> dict[str, Any]:
    hdrs = headers.copy() if headers else {}
    data = None
    if body is not None:
        if isinstance(body, dict):
            data = json.dumps(body).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        else:
            data = str(body).encode("utf-8")
    req = Request(url=url, data=data, headers=hdrs, method=method.upper())
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            text = raw.decode("utf-8", errors="ignore")
            h = dict(resp.headers.items())
            return {
                "ok": True,
                "status": int(resp.status),
                "headers": h,
                "text": text,
                "length": len(raw),
            }
    except HTTPError as e:
        b = e.read().decode("utf-8", errors="ignore") if hasattr(e, "read") else ""
        return {
            "ok": False,
            "status": int(getattr(e, "code", 0) or 0),
            "headers": dict(getattr(e, "headers", {}).items()) if getattr(e, "headers", None) else {},
            "text": b,
            "length": len(b.encode("utf-8")),
        }
    except URLError as e:
        return {"ok": False, "status": 0, "headers": {}, "text": str(e), "length": 0}


def json_keys(text: str) -> list[str]:
    try:
        obj = json.loads(text)
    except Exception:
        return []
    if isinstance(obj, dict):
        return sorted(list(obj.keys()))
    return []


async def request_http_async(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | str | None = None,
    timeout: int = 20,
) -> dict[str, Any]:
    return await asyncio.to_thread(request_http, method, url, headers, body, timeout)
