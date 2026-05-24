#!/usr/bin/env python3
"""Filter candidate hosts by program scope patterns."""

from __future__ import annotations

import argparse
import fnmatch
from pathlib import Path

import yaml


def load_programs(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def in_scope(host: str, include: list[str], exclude: list[str]) -> bool:
    host = host.strip().lower()
    if not host:
        return False

    included = any(fnmatch.fnmatch(host, pattern.lower()) for pattern in include)
    excluded = any(fnmatch.fnmatch(host, pattern.lower()) for pattern in exclude)
    return included and not excluded


def collect_scope(programs_data: dict, program: str) -> tuple[list[str], list[str]]:
    includes: list[str] = []
    excludes: list[str] = []

    for entry in programs_data.get("programs", []):
        if program != "all" and entry.get("name") != program:
            continue
        includes.extend(entry.get("in_scope", []))
        excludes.extend(entry.get("out_of_scope", []))

    return includes, excludes


def main() -> None:
    parser = argparse.ArgumentParser(description="Scope guard for authorized targets")
    parser.add_argument("--config", default="config/programs.yaml")
    parser.add_argument("--program", default="all")
    parser.add_argument("--in", dest="input_file", required=True)
    parser.add_argument("--out", dest="output_file", required=True)
    args = parser.parse_args()

    config = Path(args.config)
    hosts_file = Path(args.input_file)
    output_file = Path(args.output_file)

    programs_data = load_programs(config)
    include, exclude = collect_scope(programs_data, args.program)

    if not include:
        raise SystemExit("No in-scope patterns loaded. Check config/programs.yaml")

    kept: list[str] = []
    for line in hosts_file.read_text(encoding="utf-8").splitlines():
        host = line.strip()
        if in_scope(host, include, exclude):
            kept.append(host)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text("\n".join(sorted(set(kept))) + "\n", encoding="utf-8")
    print(f"[scope_guard] kept={len(set(kept))} out={output_file}")


if __name__ == "__main__":
    main()
