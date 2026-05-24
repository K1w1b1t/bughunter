from __future__ import annotations

import asyncio
import os
import random
import shlex
import shutil
from pathlib import Path
from typing import Any

LINUX_BIN_DIR = Path("/usr/local/bin")

DEFAULT_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

HTTP_TOOL_TIMEOUT_SECONDS = 30
HTTP_TOOL_RETRIES = 2
HTTP_TOOL_NAMES = {"httpx", "nuclei"}


def _tool_name(token: str) -> str:
    return Path(str(token or "")).name.strip().lower()


def _has_any_flag(parts: list[str], flags: set[str]) -> bool:
    for token in parts:
        if token in flags:
            return True
        for flag in flags:
            if token.startswith(f"{flag}="):
                return True
    return False


def _inject_http_tool_defaults(parts: list[str], *, user_agent: str) -> list[str]:
    if not parts:
        return parts

    tool = _tool_name(parts[0])
    if tool not in HTTP_TOOL_NAMES:
        return parts

    out = list(parts)
    if not _has_any_flag(out, {"-timeout"}):
        out.extend(["-timeout", str(HTTP_TOOL_TIMEOUT_SECONDS)])
    if not _has_any_flag(out, {"-retries"}):
        out.extend(["-retries", str(HTTP_TOOL_RETRIES)])
    if user_agent and not _has_any_flag(out, {"-H", "-header"}):
        out.extend(["-H", f"User-Agent: {user_agent}"])
    return out


async def run_command(command: str, timeout: int, stealth_mode: bool, proxies: list[str]) -> dict[str, Any]:
    parts = shlex.split(command)
    tool = parts[0]
    resolved_tool = tool
    if "/" not in tool:
        preferred = LINUX_BIN_DIR / tool
        if preferred.exists() and os.access(preferred, os.X_OK):
            resolved_tool = str(preferred)
        else:
            found = shutil.which(tool)
            if found:
                resolved_tool = found
            else:
                resolved_tool = ""
    elif shutil.which(tool):
        resolved_tool = str(shutil.which(tool))
    if not resolved_tool:
        return {"rc": 127, "stdout": "", "stderr": f"tool not found: {tool}"}
    parts[0] = resolved_tool

    env = None
    user_agent = ""
    if stealth_mode:
        env = dict(**__import__("os").environ)
        user_agent = str(env.get("HUNTEROPS_USER_AGENT", "")).strip() or random.choice(DEFAULT_UAS)
        env["HUNTEROPS_USER_AGENT"] = user_agent
        if proxies:
            env["HTTP_PROXY"] = random.choice(proxies)
            env["HTTPS_PROXY"] = env["HTTP_PROXY"]
    else:
        user_agent = str(os.getenv("HUNTEROPS_USER_AGENT", "")).strip()

    parts = _inject_http_tool_defaults(parts, user_agent=user_agent)

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
