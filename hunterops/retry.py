from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any


async def retry_async(
    fn: Callable[[], Awaitable[Any]],
    retries: int,
    base_delay: float,
) -> Any:
    last_err: Exception | None = None
    for i in range(retries + 1):
        try:
            return await fn()
        except Exception as err:  # fail-safe execution
            last_err = err
            if i >= retries:
                break
            await asyncio.sleep(base_delay * (2**i))
    if last_err:
        raise last_err
    return None

