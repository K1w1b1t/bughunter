from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any


async def read_text(path: Path, encoding: str = "utf-8") -> str:
    return await asyncio.to_thread(path.read_text, encoding=encoding)


async def write_text(path: Path, content: str, encoding: str = "utf-8") -> None:
    await asyncio.to_thread(path.write_text, content, encoding=encoding)


async def read_json(path: Path) -> Any:
    raw = await read_text(path)
    return json.loads(raw)


async def write_json(path: Path, payload: Any) -> None:
    await write_text(path, json.dumps(payload, ensure_ascii=True, indent=2) + "\n")
