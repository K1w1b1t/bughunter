#!/usr/bin/env python3
"""Delta recon analysis: compare today vs previous day and output only changes."""

from __future__ import annotations

import argparse
import re
from datetime import date, timedelta
from pathlib import Path

from common import write_json


def parse_day(day: str) -> date:
    return date.fromisoformat(day)


def read_lines(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {x.strip() for x in path.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()}


def collect_hosts(day_dir: Path) -> set[str]:
    hosts: set[str] = set()
    for pattern in ("*.subfinder.txt", "*.amass.txt", "*.assetfinder.txt", "merged_hosts.txt"):
        for f in day_dir.glob(pattern):
            for line in read_lines(f):
                if not line.startswith("[skip]"):
                    hosts.add(line)
    return hosts


def collect_alive(day_dir: Path) -> dict[str, dict[str, str]]:
    """
    Parse httpx lines in the basic format:
    https://a.example.com [200] [Title] [nginx]
    """
    results: dict[str, dict[str, str]] = {}
    path = day_dir / "alive_urls.txt"
    if not path.exists():
        return results
    line_re = re.compile(r"^(https?://\S+)\s+\[(\d{3})\](?:\s+\[(.*?)\])?(?:\s+\[(.*?)\])?$")
    for line in read_lines(path):
        m = line_re.match(line)
        if not m:
            url = line.split()[0]
            results[url] = {"status": "", "title": "", "tech": ""}
            continue
        url, status, title, tech = m.groups()
        results[url] = {"status": status or "", "title": title or "", "tech": tech or ""}
    return results


def collect_endpoints(day_dir: Path) -> set[str]:
    endpoints: set[str] = set()
    for f in day_dir.glob("*.katana.txt"):
        for line in read_lines(f):
            if line.startswith("http://") or line.startswith("https://"):
                endpoints.add(line)
    return endpoints


def collect_ports(day_dir: Path) -> set[str]:
    ports: set[str] = set()
    for f in day_dir.glob("*.naabu.txt"):
        ports.update(read_lines(f))
    for url in collect_alive(day_dir).keys():
        m = re.match(r"^https?://[^:/]+:(\d+)", url)
        if m:
            ports.add(m.group(1))
    return ports


def main() -> None:
    parser = argparse.ArgumentParser(description="Delta recon: day-over-day infrastructure changes")
    parser.add_argument("--today", required=True, help="YYYY-MM-DD")
    parser.add_argument("--yesterday", default="", help="YYYY-MM-DD (optional)")
    parser.add_argument("--raw-root", default="data/raw")
    parser.add_argument("--out", default="data/reports/delta_recon.json")
    args = parser.parse_args()

    today = parse_day(args.today)
    yesterday = parse_day(args.yesterday) if args.yesterday else (today - timedelta(days=1))
    raw_root = Path(args.raw_root)
    today_dir = raw_root / today.isoformat()
    yesterday_dir = raw_root / yesterday.isoformat()

    t_hosts = collect_hosts(today_dir)
    y_hosts = collect_hosts(yesterday_dir)
    t_endpoints = collect_endpoints(today_dir)
    y_endpoints = collect_endpoints(yesterday_dir)
    t_ports = collect_ports(today_dir)
    y_ports = collect_ports(yesterday_dir)

    t_alive = collect_alive(today_dir)
    y_alive = collect_alive(yesterday_dir)
    stack_changes: list[dict[str, str]] = []
    for url, tdata in t_alive.items():
        ydata = y_alive.get(url)
        if not ydata:
            continue
        if tdata.get("tech", "") != ydata.get("tech", ""):
            stack_changes.append(
                {"url": url, "old_tech": ydata.get("tech", ""), "new_tech": tdata.get("tech", "")}
            )

    payload = {
        "today": today.isoformat(),
        "yesterday": yesterday.isoformat(),
        "delta": {
            "new_subdomains": sorted(t_hosts - y_hosts),
            "new_endpoints": sorted(t_endpoints - y_endpoints),
            "new_ports": sorted(t_ports - y_ports),
            "stack_changes": stack_changes,
        },
    }

    write_json(Path(args.out), payload)
    print("[delta-recon] out=" + args.out)
    print(
        "[delta-recon] counts "
        f"subdomains={len(payload['delta']['new_subdomains'])} "
        f"endpoints={len(payload['delta']['new_endpoints'])} "
        f"ports={len(payload['delta']['new_ports'])} "
        f"stack_changes={len(payload['delta']['stack_changes'])}"
    )


if __name__ == "__main__":
    main()
