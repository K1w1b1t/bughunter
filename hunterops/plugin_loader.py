from __future__ import annotations

import importlib
from typing import Any

from hunterops.plugin_base import Plugin


def load_plugins(plugin_names: list[str]) -> dict[str, Plugin]:
    loaded: dict[str, Plugin] = {}
    for name in plugin_names:
        module_name = f"hunterops.plugins.{name}"
        mod = importlib.import_module(module_name)
        if not hasattr(mod, "PluginImpl"):
            raise RuntimeError(f"Plugin module missing PluginImpl: {module_name}")
        plugin = mod.PluginImpl()
        if not isinstance(plugin, Plugin):
            raise RuntimeError(f"Invalid plugin type in {module_name}")
        loaded[plugin.name] = plugin
    return loaded


def enabled_plugins(config: dict[str, Any]) -> list[str]:
    plugins = config.get("plugins", [])
    return [p["module"] for p in plugins if p.get("enabled", True)]

