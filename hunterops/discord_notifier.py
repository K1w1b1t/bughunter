from __future__ import annotations

import asyncio
import os
import re
from datetime import UTC, datetime
from typing import Any

import httpx

TOKEN_RE = re.compile(r"""(?i)\b(bearer\s+)([a-z0-9\-._~+/]+=*)""")
SECRET_KV_RE = re.compile(r"""(?i)\b(token|secret|api[_-]?key|authorization)\s*[:=]\s*([^\s,;]+)""")
URL_SECRET_RE = re.compile(r"""(?i)(token|key|secret|auth)=([^&\s]+)""")

BLUE = 3447003
ORANGE = 16753920
RED = 15158332


def _mask(value: str) -> str:
    raw = str(value or "")
    if len(raw) <= 8:
        return "*" * len(raw)
    return f"{raw[:4]}...{raw[-4:]}"


def _redact_text(value: str) -> str:
    text = str(value or "")
    if not text:
        return ""
    text = TOKEN_RE.sub(lambda m: f"{m.group(1)}{_mask(m.group(2))}", text)
    text = SECRET_KV_RE.sub(lambda m: f"{m.group(1)}={_mask(m.group(2))}", text)
    text = URL_SECRET_RE.sub(lambda m: f"{m.group(1)}={_mask(m.group(2))}", text)
    return text


def _truncate(value: str, size: int = 700) -> str:
    text = str(value or "")
    if len(text) <= size:
        return text
    return f"{text[:size]}...[+{len(text) - size} chars]"


class DiscordDispatch:
    """Async multi-channel Discord routing with non-blocking delivery."""

    def __init__(self, cfg: dict[str, Any] | None, logger: Any) -> None:
        settings = cfg if isinstance(cfg, dict) else {}
        self.logger = logger
        self.enabled = bool(settings.get("enabled", True))
        self.bot_name = str(settings.get("bot_name", "Pinguinho")).strip() or "Pinguinho"
        self.recon_webhook = str(settings.get("recon_webhook_url", "")).strip()
        self.findings_webhook = str(settings.get("findings_webhook_url", "")).strip()
        recon_env = str(settings.get("recon_webhook_env", "HUNTEROPS_DISCORD_RECON_WEBHOOK")).strip()
        findings_env = str(settings.get("findings_webhook_env", "HUNTEROPS_DISCORD_FINDINGS_WEBHOOK")).strip()
        if recon_env and not self.recon_webhook:
            self.recon_webhook = str(os.getenv(recon_env, "")).strip()
        if findings_env and not self.findings_webhook:
            self.findings_webhook = str(os.getenv(findings_env, "")).strip()
        self.timeout_seconds = float(settings.get("timeout_seconds", 4.0))
        self.max_concurrent = max(1, int(settings.get("max_concurrent", 4)))
        self.send_startup_check = bool(settings.get("send_startup_check", True))
        self._sem = asyncio.Semaphore(self.max_concurrent)
        self._client: httpx.AsyncClient | None = None
        self._pending: set[asyncio.Task[Any]] = set()

    @property
    def available(self) -> bool:
        return self.enabled and bool(self.recon_webhook or self.findings_webhook)

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=False)
        return self._client

    async def _post(self, webhook: str, payload: dict[str, Any], route: str) -> None:
        if not webhook:
            return
        try:
            async with self._sem:
                response = await self._get_client().post(webhook, json=payload)
            if response.status_code == 429:
                retry_after = 0.0
                try:
                    body = response.json()
                    retry_after = float(body.get("retry_after", 0) or 0)
                except Exception:
                    retry_after = 0.0
                self.logger.warning(f"discord_rate_limited route={route} retry_after={retry_after}")
                return
            if response.status_code >= 400:
                self.logger.warning(f"discord_dispatch_failed route={route} status={response.status_code}")
        except Exception as err:
            self.logger.warning(f"discord_dispatch_error route={route} err={err}")

    def _schedule(self, coro: Any) -> None:
        if not self.available:
            return
        task = asyncio.create_task(coro)
        self._pending.add(task)
        task.add_done_callback(lambda t: self._pending.discard(t))

    @staticmethod
    def _embed(title: str, description: str, color: int, fields: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        embed: dict[str, Any] = {
            "title": _truncate(_redact_text(title), 240),
            "description": _truncate(_redact_text(description), 3500),
            "color": int(color),
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
        if fields:
            embed["fields"] = fields[:12]
        return embed

    def route_recon_delta(
        self,
        *,
        target: str,
        delta_score: float,
        new_endpoints: list[str],
        changed_js: list[str],
        new_parameters: list[str],
    ) -> None:
        if not self.recon_webhook:
            return
        description = f"Surface Expansion Detected on `{target}`"
        fields = [
            {"name": "Delta Score", "value": f"`{round(float(delta_score), 2)}`", "inline": True},
            {"name": "New Endpoints", "value": f"`{len(new_endpoints)}`", "inline": True},
            {"name": "Changed JS", "value": f"`{len(changed_js)}`", "inline": True},
            {"name": "New Parameters", "value": f"`{len(new_parameters)}`", "inline": True},
        ]
        if new_endpoints:
            sample = "\n".join([f"- `{_truncate(ep, 90)}`" for ep in new_endpoints[:8]])
            fields.append({"name": "Route Sample", "value": _truncate(sample, 900), "inline": False})
        if changed_js:
            sample = "\n".join([f"- `{_truncate(js, 90)}`" for js in changed_js[:6]])
            fields.append({"name": "JS Delta Sample", "value": _truncate(sample, 700), "inline": False})
        if new_parameters:
            sample = "\n".join([f"- `{_truncate(p, 90)}`" for p in new_parameters[:8]])
            fields.append({"name": "Parameter Delta Sample", "value": _truncate(sample, 700), "inline": False})
        payload = {"username": self.bot_name, "embeds": [self._embed("Surface Expansion Detected", description, BLUE, fields)]}
        self._schedule(self._post(self.recon_webhook, payload, "recon"))

    def route_finding_confirmed(
        self,
        *,
        target: str,
        title: str,
        impact: str,
        confidence: float,
        endpoint: str,
        evidence_snippet: str,
        report_path: str,
        severity_level: str = "",
        estimated_payout: str = "",
    ) -> None:
        if not self.findings_webhook:
            return
        color = RED if confidence >= 80 else ORANGE
        fields = [
            {"name": "Target", "value": f"`{_truncate(target, 80)}`", "inline": True},
            {"name": "Confidence (C)", "value": f"`{round(float(confidence), 2)}`", "inline": True},
            {"name": "Severity", "value": f"`{_truncate(str(severity_level or 'unspecified'), 40)}`", "inline": True},
            {"name": "Endpoint", "value": f"`{_truncate(endpoint, 150)}`", "inline": False},
            {"name": "Impact", "value": _truncate(_redact_text(impact), 700), "inline": False},
            {"name": "Evidence Snippet", "value": _truncate(_redact_text(evidence_snippet), 900), "inline": False},
            {"name": "Estimated Payout", "value": f"`{_truncate(_redact_text(estimated_payout or 'N/A'), 80)}`", "inline": True},
            {"name": "Report", "value": f"`{_truncate(_redact_text(report_path or 'pending_generation'), 250)}`", "inline": False},
        ]
        payload = {
            "username": self.bot_name,
            "embeds": [self._embed("Vulnerability Confirmed", _truncate(_redact_text(title), 350), color, fields)],
        }
        self._schedule(self._post(self.findings_webhook, payload, "findings"))

    async def send_system_online(self, *, run_id: str, targets_count: int, plugins_count: int) -> None:
        if not self.send_startup_check or not self.available:
            return
        fields = [
            {"name": "Run ID", "value": f"`{_truncate(run_id, 80)}`", "inline": True},
            {"name": "Targets", "value": f"`{targets_count}`", "inline": True},
            {"name": "Plugins", "value": f"`{plugins_count}`", "inline": True},
            {"name": "Status", "value": "`System Online: Research Agent Active`", "inline": False},
        ]
        payload = {"username": self.bot_name, "embeds": [self._embed("System Online", "Research Agent Active", BLUE, fields)]}
        tasks: list[Any] = []
        if self.recon_webhook:
            tasks.append(self._post(self.recon_webhook, payload, "recon_startup"))
        if self.findings_webhook:
            tasks.append(self._post(self.findings_webhook, payload, "findings_startup"))
        if tasks:
            try:
                await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=self.timeout_seconds + 1.5)
            except Exception:
                # Never block pipeline startup on notifier failures/timeouts.
                self.logger.warning("discord_startup_check_timeout")

    async def close(self) -> None:
        if self._pending:
            try:
                await asyncio.wait_for(asyncio.gather(*list(self._pending), return_exceptions=True), timeout=2.0)
            except Exception:
                pass
        self._pending.clear()
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass
            self._client = None
