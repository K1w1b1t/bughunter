from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

APP_HOME_ENV = "HUNTEROPS_HOME"
DEFAULT_APP_ROOT = Path("/opt/hunterops")


def _looks_like_project_root(path: Path) -> bool:
    required = (
        path / "hunterops",
        path / "config",
        path / "scripts",
    )
    return all(p.exists() for p in required)


def app_root() -> Path:
    raw = os.getenv(APP_HOME_ENV, "").strip()
    if raw:
        return Path(raw).expanduser().resolve()

    cwd = Path.cwd().resolve()
    if _looks_like_project_root(cwd):
        return cwd

    repo_root = Path(__file__).resolve().parent.parent
    if _looks_like_project_root(repo_root):
        return repo_root

    default_root = DEFAULT_APP_ROOT.resolve()
    if default_root.exists():
        return default_root

    return default_root


def resolve_path(value: str | Path, *, base: Path | None = None, prefer_existing: bool = True) -> Path:
    raw = str(value).strip()
    if not raw:
        return app_root()
    candidate = Path(raw).expanduser()
    if candidate.is_absolute():
        return candidate.resolve()

    root = (base or app_root()).resolve()
    preferred = (root / candidate).resolve()
    if not prefer_existing:
        return preferred

    if preferred.exists():
        return preferred
    return preferred


def ensure_directory(path: Path, *, mode: int = 0o755) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    chmod_if_posix(path, mode=mode)
    return path


def chmod_if_posix(path: Path, *, mode: int) -> None:
    if os.name != "posix":
        return
    try:
        current = stat.S_IMODE(path.stat().st_mode)
        if current != mode:
            path.chmod(mode)
    except Exception:
        return


def secure_secret_file(path: Path) -> None:
    chmod_if_posix(path, mode=0o600)


def executable_binary(path: Path) -> None:
    chmod_if_posix(path, mode=0o755)


def coerce_path(value: Any, *, default: str) -> Path:
    raw = str(value).strip() if value is not None else ""
    if not raw:
        raw = default
    return resolve_path(raw)
