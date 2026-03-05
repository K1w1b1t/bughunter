from __future__ import annotations

import asyncio
import random
import shlex
import shutil
from typing import Any


DEFAULT_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/122.0 Safari/537.36",
]


async def run_command(command: str, timeout: int, stealth_mode: bool, proxies: list[str]) -> dict[str, Any]:
    parts = shlex.split(command)
    tool = parts[0]
    if shutil.which(tool) is None:
        return {"rc": 127, "stdout": "", "stderr": f"tool not found: {tool}"}

    env = None
    if stealth_mode:
        env = dict(**__import__("os").environ)
        env["HUNTEROPS_USER_AGENT"] = random.choice(DEFAULT_UAS)
        if proxies:
            env["HTTP_PROXY"] = random.choice(proxies)
            env["HTTPS_PROXY"] = env["HTTP_PROXY"]

    proc = await asyncio.create_subprocess_exec(
        *parts,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return {"rc": 124, "stdout": "", "stderr": "timeout"}

    return {
        "rc": proc.returncode,
        "stdout": out.decode("utf-8", errors="ignore"),
        "stderr": err.decode("utf-8", errors="ignore"),
    }

