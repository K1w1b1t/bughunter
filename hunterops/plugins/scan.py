from __future__ import annotations

from typing import Any

from hunterops.intelligence import detect_sensitive
from hunterops.plugin_base import Plugin
from hunterops.tool_runner import run_command
from hunterops.types import Finding, Task

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


def _severity_rank(value: str) -> int:
    raw = str(value or "").strip().lower()
    if raw in SEVERITY_ORDER:
        return SEVERITY_ORDER.index(raw)
    return SEVERITY_ORDER.index("low")


def _extract_severity_summary(lines: list[str]) -> tuple[str, dict[str, int]]:
    counters: dict[str, int] = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
    for line in lines:
        low = str(line or "").lower()
        for key in counters:
            if f"[{key}]" in low or f"severity={key}" in low:
                counters[key] += 1
    for key in ("critical", "high", "medium", "low", "info"):
        if counters[key] > 0:
            return key, counters
    return "medium", counters


class PluginImpl(Plugin):
    name = "scan"

    async def run(self, task: Task, context: dict[str, Any]) -> list[Finding]:
        cfg = context["config"].get("modules", {}).get("scan", {})
        timeout = context["runtime"]["timeout_seconds"]
        stealth = context["runtime"]["stealth_mode"]
        proxies = context["runtime"]["proxies"]
        min_emit_severity = str(cfg.get("min_emit_severity", "high")).strip().lower() or "high"
        min_rank = _severity_rank(min_emit_severity)
        findings: list[Finding] = []

        for cmd_tpl in cfg.get("commands", []):
            cmd = cmd_tpl.format(target=task.target)
            result = await run_command(cmd, timeout=timeout, stealth_mode=stealth, proxies=proxies)
            lines = [x.strip() for x in result["stdout"].splitlines() if x.strip()]
            if lines:
                highest_severity, severity_counts = _extract_severity_summary(lines)
                if _severity_rank(highest_severity) >= min_rank:
                    confidence = 82 if highest_severity in {"critical", "high"} else 70
                    impact = 88 if highest_severity == "critical" else 76 if highest_severity == "high" else 60
                    findings.append(
                        Finding(
                            plugin=self.name,
                            target=task.target,
                            category="vulnerability_signal",
                            severity=highest_severity,
                            title=f"Scanner output has {len(lines)} potential issues ({highest_severity})",
                            evidence={"sample": lines[:30], "command": cmd, "severity_counts": severity_counts},
                            metadata={"novelty": 55, "confidence": confidence, "impact": impact},
                        )
                    )

            hits = detect_sensitive(result["stdout"] + "\n" + result["stderr"])
            if hits:
                findings.append(
                    Finding(
                        plugin=self.name,
                        target=task.target,
                        category="sensitive_pattern",
                        severity="high",
                        title=f"Sensitive patterns detected ({len(hits)})",
                        evidence={"hits": hits[:20], "command": cmd},
                        metadata={"novelty": 80, "confidence": 78, "impact": 85},
                    )
                )
        return findings
