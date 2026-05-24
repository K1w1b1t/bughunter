#!/usr/bin/env python3
"""Run a recon pipeline on authorized targets and store raw outputs."""

from __future__ import annotations

import argparse
import datetime as dt
import shutil
import subprocess
from pathlib import Path


def run_cmd(command: list[str], output_path: Path) -> int:
    proc = subprocess.run(command, capture_output=True, text=True, check=False)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else ""), encoding="utf-8")
    return proc.returncode


def tool_exists(tool: str) -> bool:
    return shutil.which(tool) is not None


def main() -> None:
    parser = argparse.ArgumentParser(description="Authorized recon pipeline")
    parser.add_argument("--in", dest="input_file", required=True)
    parser.add_argument("--date", default=dt.date.today().isoformat())
    args = parser.parse_args()

    input_file = Path(args.input_file)
    run_date = args.date
    raw_dir = Path("data/raw") / run_date

    targets = [x.strip() for x in input_file.read_text(encoding="utf-8").splitlines() if x.strip()]
    if not targets:
        raise SystemExit("No targets to process.")

    for target in targets:
        safe_target = target.replace("*", "wildcard").replace("/", "_")

        if tool_exists("subfinder"):
            out = raw_dir / f"{safe_target}.subfinder.txt"
            rc = run_cmd(["subfinder", "-d", target, "-silent"], out)
            print(f"[recon] subfinder target={target} rc={rc}")
        else:
            print("[warn] subfinder not found")

        if tool_exists("amass"):
            out = raw_dir / f"{safe_target}.amass.txt"
            rc = run_cmd(["amass", "enum", "-passive", "-d", target], out)
            print(f"[recon] amass target={target} rc={rc}")
        else:
            print("[warn] amass not found")

    print(f"[recon] completed date={run_date}")


if __name__ == "__main__":
    main()
