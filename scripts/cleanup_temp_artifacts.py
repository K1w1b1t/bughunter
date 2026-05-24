#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hunterops.runtime_paths import app_root, resolve_path


def _is_safe_root(path: Path, workspace: Path) -> bool:
    try:
        resolved = path.resolve()
    except Exception:
        return False
    if str(resolved).startswith("/tmp/") or str(resolved) == "/tmp":
        return True
    try:
        resolved.relative_to(workspace)
        return True
    except Exception:
        return False


def _iter_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for node in root.rglob("*"):
        if node.is_file():
            out.append(node)
    return out


def _iter_dirs_desc(root: Path) -> list[Path]:
    out: list[Path] = []
    for node in root.rglob("*"):
        if node.is_dir():
            out.append(node)
    out.sort(key=lambda path: len(path.parts), reverse=True)
    return out


def run_cleanup(*, roots: list[Path], max_age_hours: float, dry_run: bool) -> dict[str, Any]:
    now = time.time()
    max_age_seconds = max(0.0, float(max_age_hours) * 3600.0)
    workspace = app_root()

    deleted_files = 0
    deleted_dirs = 0
    reclaimed_bytes = 0
    skipped_roots: list[str] = []
    scanned_roots: list[str] = []

    for root in roots:
        if not root.exists():
            continue
        if not _is_safe_root(root, workspace):
            skipped_roots.append(str(root))
            continue
        scanned_roots.append(str(root))

        for file_path in _iter_files(root):
            try:
                stat_info = file_path.stat()
            except Exception:
                continue
            age = now - float(stat_info.st_mtime)
            if age < max_age_seconds:
                continue
            size = int(stat_info.st_size)
            if not dry_run:
                try:
                    file_path.unlink(missing_ok=True)
                except Exception:
                    continue
            deleted_files += 1
            reclaimed_bytes += size

        for dir_path in _iter_dirs_desc(root):
            try:
                if not dir_path.exists() or not dir_path.is_dir():
                    continue
            except Exception:
                continue
            if dir_path == root:
                continue
            with os.scandir(dir_path) as it:
                if any(True for _ in it):
                    continue
            if not dry_run:
                try:
                    dir_path.rmdir()
                except Exception:
                    continue
            deleted_dirs += 1

    return {
        "ok": True,
        "dry_run": bool(dry_run),
        "max_age_hours": float(max_age_hours),
        "deleted_files": int(deleted_files),
        "deleted_dirs": int(deleted_dirs),
        "reclaimed_bytes": int(reclaimed_bytes),
        "scanned_roots": scanned_roots,
        "skipped_roots": skipped_roots,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cleanup temporary recon artifacts (amass/katana/raw outputs).")
    parser.add_argument(
        "--roots",
        default="data/raw,data/tmp,/tmp/amass,/tmp/katana,/tmp/hunterops",
        help="Comma-separated list of directories.",
    )
    parser.add_argument("--max-age-hours", type=float, default=24.0)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--out", default="data/reports/cleanup_temp_artifacts.json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    roots: list[Path] = []
    for item in [x.strip() for x in str(args.roots).split(",") if x.strip()]:
        if item.startswith("/"):
            roots.append(Path(item))
        else:
            roots.append(resolve_path(item, prefer_existing=False))

    report = run_cleanup(roots=roots, max_age_hours=float(args.max_age_hours), dry_run=bool(args.dry_run))
    out = resolve_path(args.out, prefer_existing=False)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"ok": report["ok"], "deleted_files": report["deleted_files"], "out": str(out)}, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
