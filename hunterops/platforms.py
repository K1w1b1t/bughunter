from __future__ import annotations

import os
from typing import Any
from urllib.request import Request, urlopen


def _get_json(url: str, headers: dict[str, str], timeout: int) -> dict[str, Any]:
    req = Request(url=url, headers=headers)
    with urlopen(req, timeout=timeout) as resp:
        data = resp.read().decode("utf-8", errors="ignore")
    import json

    return json.loads(data) if data else {}


def fetch_hackerone_programs(timeout: int = 15) -> dict[str, Any]:
    token = os.getenv("HACKERONE_API_TOKEN", "")
    user = os.getenv("HACKERONE_API_USER", "")
    if not token or not user:
        return {"enabled": False, "reason": "missing env HACKERONE_API_USER/HACKERONE_API_TOKEN"}
    import base64

    auth = base64.b64encode(f"{user}:{token}".encode("utf-8")).decode("utf-8")
    headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}
    return _get_json("https://api.hackerone.com/v1/hackers/programs", headers=headers, timeout=timeout)


def fetch_hackerone_scopes(timeout: int = 15) -> dict[str, Any]:
    token = os.getenv("HACKERONE_API_TOKEN", "")
    user = os.getenv("HACKERONE_API_USER", "")
    handle = os.getenv("HACKERONE_PROGRAM_HANDLE", "")
    if not token or not user or not handle:
        return {"enabled": False, "reason": "missing env for hackerone scope sync"}
    import base64

    auth = base64.b64encode(f"{user}:{token}".encode("utf-8")).decode("utf-8")
    headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}
    return _get_json(f"https://api.hackerone.com/v1/hackers/programs/{handle}", headers=headers, timeout=timeout)


def fetch_hackerone_reports(timeout: int = 15) -> dict[str, Any]:
    token = os.getenv("HACKERONE_API_TOKEN", "")
    user = os.getenv("HACKERONE_API_USER", "")
    if not token or not user:
        return {"enabled": False, "reason": "missing env for hackerone reports sync"}
    import base64

    auth = base64.b64encode(f"{user}:{token}".encode("utf-8")).decode("utf-8")
    headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}
    return _get_json("https://api.hackerone.com/v1/reports?filter[state]=triaged", headers=headers, timeout=timeout)


def fetch_bugcrowd_programs(timeout: int = 15) -> dict[str, Any]:
    token = os.getenv("BUGCROWD_API_TOKEN", "")
    if not token:
        return {"enabled": False, "reason": "missing env BUGCROWD_API_TOKEN"}
    headers = {"Authorization": f"Token {token}", "Accept": "application/json"}
    # Endpoint may vary by account permission; keep as configurable fallback.
    return _get_json("https://api.bugcrowd.com/programs", headers=headers, timeout=timeout)


def fetch_bugcrowd_submissions(timeout: int = 15) -> dict[str, Any]:
    token = os.getenv("BUGCROWD_API_TOKEN", "")
    if not token:
        return {"enabled": False, "reason": "missing env BUGCROWD_API_TOKEN"}
    headers = {"Authorization": f"Token {token}", "Accept": "application/json"}
    return _get_json("https://api.bugcrowd.com/submissions", headers=headers, timeout=timeout)
