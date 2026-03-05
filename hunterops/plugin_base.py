from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from hunterops.types import Finding, Task


class Plugin(ABC):
    name: str = "base"

    @abstractmethod
    async def run(self, task: Task, context: dict[str, Any]) -> list[Finding]:
        raise NotImplementedError

