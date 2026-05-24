from __future__ import annotations

from abc import ABC, abstractmethod
import hashlib
import json
from typing import Any

from hunterops.types import Finding, Task


class Plugin(ABC):
    name: str = "base"

    @abstractmethod
    async def run(self, task: Task, context: dict[str, Any]) -> list[Finding]:
        raise NotImplementedError

    @staticmethod
    def _structural_hash(payload: dict[str, Any]) -> str:
        try:
            encoded = json.dumps(payload, sort_keys=True, ensure_ascii=True, default=str)
        except Exception:
            encoded = str(payload)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def normalize_findings(self, findings: list[Finding], task: Task | None = None) -> list[Finding]:
        normalized: list[Finding] = []
        for finding in findings or []:
            meta = finding.metadata.copy() if isinstance(finding.metadata, dict) else {}
            evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
            discovery_source = str(meta.get("discovery_source", "")).strip() or self.name
            confidence_score = float(meta.get("confidence_score", meta.get("confidence", 0)) or 0)
            if confidence_score <= 0:
                confidence_score = 60.0
            structural_basis = {
                "plugin": finding.plugin or self.name,
                "target": finding.target,
                "category": finding.category,
                "title": finding.title,
                "endpoint": evidence.get("endpoint", evidence.get("path", evidence.get("url", ""))),
                "evidence": evidence,
            }
            structural_hash = str(meta.get("structural_hash", "")).strip() or self._structural_hash(structural_basis)

            meta["discovery_source"] = discovery_source
            meta["confidence_score"] = confidence_score
            meta["structural_hash"] = structural_hash
            if "confidence" not in meta:
                meta["confidence"] = confidence_score

            normalized.append(
                Finding(
                    plugin=finding.plugin or self.name,
                    target=finding.target if finding.target else (task.target if task else ""),
                    category=finding.category,
                    severity=finding.severity,
                    title=finding.title,
                    evidence=evidence,
                    metadata=meta,
                )
            )
        return normalized
