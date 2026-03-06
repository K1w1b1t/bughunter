from __future__ import annotations

import asyncio
import os
from typing import Any


def install_uvloop_if_available(logger: Any | None = None) -> bool:
    if os.name != "posix":
        return False
    if os.getenv("HUNTEROPS_DISABLE_UVLOOP", "0").strip() == "1":
        return False
    try:
        import uvloop  # type: ignore
    except Exception:
        return False
    try:
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        if logger is not None:
            logger.info("uvloop_enabled=true")
        return True
    except Exception:
        return False
