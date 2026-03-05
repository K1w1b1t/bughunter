from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any

import yaml


def load_program_packs(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return cfg.get("program_packs", [])


def resolve_pack(target: str, packs: list[dict[str, Any]]) -> dict[str, Any] | None:
    t = target.strip().lower()
    for pack in packs:
        for pat in pack.get("scope", []):
            if fnmatch.fnmatch(t, str(pat).lower()):
                return pack
    return None

