#!/usr/bin/env python3
"""Shared helpers for HunterOps scripts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = "\n".join(json.dumps(r, ensure_ascii=True) for r in rows)
    if payload:
        payload += "\n"
    path.write_text(payload, encoding="utf-8")


def finding_signature(item: dict[str, Any]) -> str:
    parts = [
        item.get("program", ""),
        item.get("asset", ""),
        item.get("surface", ""),
        item.get("endpoint", ""),
        item.get("parameter", ""),
        item.get("title", "")
    ]
    raw = "|".join(str(p).strip().lower() for p in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
