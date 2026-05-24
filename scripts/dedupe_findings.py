#!/usr/bin/env python3
"""Dedupe structured findings by stable signature."""

from __future__ import annotations

import argparse
from pathlib import Path

from common import finding_signature, read_jsonl, write_jsonl


def main() -> None:
    parser = argparse.ArgumentParser(description="Dedupe finding candidates")
    parser.add_argument("--in", dest="input_file", required=True)
    parser.add_argument("--out", dest="output_file", required=True)
    args = parser.parse_args()

    candidates = read_jsonl(Path(args.input_file))
    seen: set[str] = set()
    unique: list[dict] = []

    for item in candidates:
        sig = finding_signature(item)
        if sig in seen:
            continue
        seen.add(sig)
        item["signature"] = sig
        unique.append(item)

    write_jsonl(Path(args.output_file), unique)
    print(f"[dedupe] input={len(candidates)} unique={len(unique)}")


if __name__ == "__main__":
    main()
