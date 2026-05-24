from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from hunterops.env_utils import REQUIRED_BINARIES, collect_plugin_binary_dependencies, resolve_binary_for_plugin

_TRUTHY = {"1", "true", "yes", "y", "on"}


def _env_truthy(name: str, default: bool = False) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in _TRUTHY


def _is_linux_runtime() -> bool:
    return os.name == "posix" and Path("/proc").exists()


def _is_wsl_runtime() -> bool:
    if os.getenv("WSL_DISTRO_NAME", "").strip():
        return True
    release_files = ("/proc/sys/kernel/osrelease", "/proc/version")
    for candidate in release_files:
        path = Path(candidate)
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
        except Exception:
            continue
        if "microsoft" in text or "wsl" in text:
            return True
    return False


def _normalize_plugins(requested_plugins: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in requested_plugins:
        item = str(raw or "").strip().lower()
        if not item or item in seen:
            continue
        seen.add(item)
        normalized.append(item)
    return normalized


def validate_toolchain_preflight(
    config: dict[str, Any],
    requested_plugins: list[str],
    *,
    strict: bool | None = None,
) -> dict[str, Any]:
    strict_mode = bool(_env_truthy("HUNTEROPS_PREFLIGHT_STRICT", True) if strict is None else strict)
    is_linux = _is_linux_runtime()
    is_wsl = _is_wsl_runtime()
    if not is_linux:
        return {
            "ok": True,
            "strict": strict_mode,
            "skipped": True,
            "runtime": "non-linux",
            "is_wsl": False,
            "checked_tools": [],
            "resolved": {},
            "missing": [],
            "requested_plugins": _normalize_plugins(requested_plugins),
        }

    dep_map = collect_plugin_binary_dependencies(config)
    plugins = _normalize_plugins(requested_plugins)
    toolset: set[str] = {str(item) for item in REQUIRED_BINARIES}
    for plugin in plugins:
        toolset.update(dep_map.get(plugin, set()))

    checked_tools = sorted([str(tool).strip() for tool in toolset if str(tool).strip()])
    resolved: dict[str, str] = {}
    missing: list[str] = []
    for tool in checked_tools:
        binary = resolve_binary_for_plugin(tool)
        if binary:
            resolved[tool] = binary
        else:
            missing.append(tool)

    ok = not missing or not strict_mode
    return {
        "ok": ok,
        "strict": strict_mode,
        "skipped": False,
        "runtime": "wsl" if is_wsl else "linux",
        "is_wsl": is_wsl,
        "checked_tools": checked_tools,
        "resolved": resolved,
        "missing": missing,
        "requested_plugins": plugins,
    }

