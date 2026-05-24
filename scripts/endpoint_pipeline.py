#!/usr/bin/env python3
"""Extract endpoints and parameters and cluster by business function keywords."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from common import write_json


CLUSTER_KEYWORDS = {
    "billing": ["billing", "invoice", "payment", "plan", "subscription", "charge"],
    "admin": ["admin", "manage", "console", "staff", "operator"],
    "exports": ["export", "download", "report", "csv", "backup"],
    "tokens": ["token", "jwt", "apikey", "secret", "auth", "session"],
    "accounts": ["account", "user", "profile", "tenant", "organization"],
}


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [x.strip() for x in path.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()]


def collect_urls(day_dir: Path) -> set[str]:
    urls: set[str] = set()
    for pattern in ("*.katana.txt", "*.gau.txt", "*.waybackurls.txt"):
        for f in day_dir.glob(pattern):
            for line in read_lines(f):
                if line.startswith("http://") or line.startswith("https://"):
                    urls.add(line)
    return urls


def cluster_for_path(path: str) -> str:
    p = path.lower()
    for cluster, keywords in CLUSTER_KEYWORDS.items():
        if any(k in p for k in keywords):
            return cluster
    return "general"


def normalize_endpoint(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def extract_params(url: str) -> list[str]:
    parsed = urlparse(url)
    names = list(parse_qs(parsed.query).keys())
    # also capture route-like ids
    route_params = re.findall(r"/([a-zA-Z_]*id)\b", parsed.path)
    return sorted(set(names + route_params))


def main() -> None:
    parser = argparse.ArgumentParser(description="Endpoint and parameter pipeline")
    parser.add_argument("--date", required=True, help="YYYY-MM-DD")
    parser.add_argument("--raw-root", default="data/raw")
    parser.add_argument("--out", default="data/processed/endpoints_catalog.json")
    args = parser.parse_args()

    day_dir = Path(args.raw_root) / args.date
    urls = sorted(collect_urls(day_dir))
    clusters: dict[str, list[dict[str, object]]] = {k: [] for k in list(CLUSTER_KEYWORDS.keys()) + ["general"]}

    for u in urls:
        endpoint = normalize_endpoint(u)
        params = extract_params(u)
        cluster = cluster_for_path(endpoint)
        clusters[cluster].append({"url": u, "endpoint": endpoint, "params": params})

    payload = {
        "date": args.date,
        "total_urls": len(urls),
        "clusters": clusters,
    }
    write_json(Path(args.out), payload)
    print("[endpoint-pipeline] out=" + args.out)
    print("[endpoint-pipeline] total_urls=" + str(len(urls)))


if __name__ == "__main__":
    main()
