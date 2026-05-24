#!/usr/bin/env python3
"""Authenticated surface collector using Playwright.

This runner is intentionally non-destructive:
- login
- keep session
- visit seed URLs
- collect reachable endpoints
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from common import write_json


def load_profiles(path: Path) -> list[dict[str, Any]]:
    cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return cfg.get("program_profiles", [])


def load_seed_urls(raw_dir: Path) -> list[str]:
    alive = raw_dir / "alive_urls.txt"
    if not alive.exists():
        return []
    urls: list[str] = []
    for line in alive.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        urls.append(line.split()[0].strip())
    return urls


def same_domain(url: str, base: str) -> bool:
    try:
        return urlparse(url).netloc.endswith(urlparse(base).netloc)
    except Exception:
        return False


def run_profile(profile: dict[str, Any], date_str: str, raw_root: Path, out_file: Path) -> dict[str, Any]:
    auth = profile.get("auth", {})
    if not auth.get("enabled", False):
        return {"program": profile.get("name"), "skipped": True, "reason": "auth.disabled"}

    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return {"program": profile.get("name"), "skipped": True, "reason": "playwright.not_installed"}

    login_url = str(auth.get("login_url", "")).strip()
    user_env = str(auth.get("username_env", "")).strip()
    pass_env = str(auth.get("password_env", "")).strip()
    if not login_url or not user_env or not pass_env:
        return {"program": profile.get("name"), "skipped": True, "reason": "auth.config_missing"}

    username = os.getenv(user_env, "")
    password = os.getenv(pass_env, "")
    if not username or not password:
        return {"program": profile.get("name"), "skipped": True, "reason": "auth.env_missing"}

    seed_urls = load_seed_urls(raw_root / date_str)
    if not seed_urls:
        seed_urls = [login_url]

    visited: set[str] = set()
    discovered: set[str] = set()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context()
        page = ctx.new_page()
        page.goto(login_url, wait_until="domcontentloaded", timeout=60000)

        # Generic login flow; adjust selectors per program if needed.
        if page.locator("input[type='email']").count() > 0:
            page.fill("input[type='email']", username)
        elif page.locator("input[name='username']").count() > 0:
            page.fill("input[name='username']", username)

        if page.locator("input[type='password']").count() > 0:
            page.fill("input[type='password']", password)

        if page.locator("button[type='submit']").count() > 0:
            page.click("button[type='submit']")
        page.wait_for_timeout(3000)

        for url in seed_urls[:50]:
            if not same_domain(url, login_url):
                continue
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=30000)
                visited.add(url)
                links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                for lnk in links:
                    if same_domain(str(lnk), login_url):
                        discovered.add(str(lnk))
            except Exception:
                continue

        storage_path = out_file.parent / f"{profile.get('name')}_storage_state.json"
        ctx.storage_state(path=str(storage_path))
        browser.close()

    return {
        "program": profile.get("name"),
        "skipped": False,
        "visited_count": len(visited),
        "discovered_count": len(discovered),
        "visited": sorted(visited),
        "discovered_urls": sorted(discovered),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Authenticated crawling with Playwright")
    parser.add_argument("--profiles", default="config/program_profiles.yaml")
    parser.add_argument("--date", required=True)
    parser.add_argument("--raw-root", default="data/raw")
    parser.add_argument("--out", default="data/processed/auth_surface.json")
    args = parser.parse_args()

    profiles = load_profiles(Path(args.profiles))
    out_path = Path(args.out)
    results: list[dict[str, Any]] = []

    for profile in profiles:
        results.append(run_profile(profile, args.date, Path(args.raw_root), out_path))

    write_json(out_path, {"date": args.date, "results": results})
    print("[auth-runner] out=" + args.out)
    done = sum(1 for r in results if not r.get("skipped", False))
    print("[auth-runner] completed_profiles=" + str(done))


if __name__ == "__main__":
    main()
