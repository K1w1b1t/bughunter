from __future__ import annotations

import os
from pathlib import Path

from hunterops.runtime_paths import resolve_path


def load_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        out[key] = value
    return out


def apply_env_values(env_values: dict[str, str], *, override: bool = False) -> None:
    for key, value in env_values.items():
        if not key:
            continue
        if override or key not in os.environ:
            os.environ[key] = value


def read_secret_with_env_file(name: str, env_values: dict[str, str]) -> str:
    key = str(name or "").strip()
    if not key:
        return ""

    direct = os.getenv(key, "").strip()
    if direct:
        return direct

    from_env_file = str(env_values.get(key, "")).strip()
    if from_env_file:
        return from_env_file

    file_key = f"{key}_FILE"
    runtime_file = os.getenv(file_key, "").strip()
    env_file_file = str(env_values.get(file_key, "")).strip()
    secret_file = runtime_file or env_file_file
    if secret_file:
        try:
            path = resolve_path(secret_file, prefer_existing=True)
            return path.read_text(encoding="utf-8").strip()
        except Exception:
            return ""

    cred_dir = os.getenv("CREDENTIALS_DIRECTORY", "").strip() or str(env_values.get("CREDENTIALS_DIRECTORY", "")).strip()
    if cred_dir:
        try:
            path = Path(cred_dir) / key
            if path.exists():
                return path.read_text(encoding="utf-8").strip()
        except Exception:
            return ""

    return ""
