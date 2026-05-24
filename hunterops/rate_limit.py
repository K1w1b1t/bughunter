from __future__ import annotations

import asyncio
import time


class AsyncRateLimiter:
    def __init__(self, rate_per_sec: float) -> None:
        self.rate_per_sec = max(0.1, rate_per_sec)
        self.min_interval = 1.0 / self.rate_per_sec
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            delta = now - self._last
            if delta < self.min_interval:
                await asyncio.sleep(self.min_interval - delta)
            self._last = time.monotonic()

