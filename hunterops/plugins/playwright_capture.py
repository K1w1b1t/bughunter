from __future__ import annotations

from typing import Any

from hunterops.plugin_base import Plugin
from hunterops.types import Finding, Task


class PluginImpl(Plugin):
    name = "playwright_capture"

    async def run(self, task: Task, context: dict[str, Any]) -> list[Finding]:
        try:
            from playwright.async_api import async_playwright
        except Exception:
            return []

        timeout_ms = int(context["runtime"]["timeout_seconds"] * 1000)
        url = f"https://{task.target}"
        hidden_endpoints: set[str] = set()
        cookies_dump: list[dict[str, Any]] = []

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()

            def on_req(req: Any) -> None:
                hidden_endpoints.add(req.url)

            page.on("request", on_req)
            try:
                await page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                await page.wait_for_timeout(2500)
                cookies_dump = await page.context.cookies()
            except Exception:
                pass
            finally:
                await browser.close()

        if not hidden_endpoints and not cookies_dump:
            return []

        token_like = []
        for c in cookies_dump:
            name = str(c.get("name", "")).lower()
            if any(k in name for k in ("token", "jwt", "auth", "session")):
                token_like.append(c.get("name", ""))

        return [
            Finding(
                plugin=self.name,
                target=task.target,
                category="client_side_discovery",
                severity="info",
                title="Playwright captured hidden requests/cookies",
                evidence={
                    "intercepted_requests_sample": sorted(hidden_endpoints)[:30],
                    "cookies_sample": cookies_dump[:10],
                    "token_like_cookies": token_like[:10],
                },
                metadata={"novelty": 70, "confidence": 75, "impact": 35},
            )
        ]

