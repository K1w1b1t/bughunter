from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "extra_data"):
            payload["extra"] = getattr(record, "extra_data")
        return json.dumps(payload, ensure_ascii=True)


class ColorFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\x1b[37m",
        "INFO": "\x1b[36m",
        "WARNING": "\x1b[33m",
        "ERROR": "\x1b[31m",
        "CRITICAL": "\x1b[35m",
    }
    RESET = "\x1b[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)
        return f"{color}[{record.levelname}] {record.getMessage()}{self.RESET}"


class AlertRouterLogHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.CRITICAL)
        self.router: Any | None = None

    def emit(self, record: logging.LogRecord) -> None:
        if record.levelno < logging.CRITICAL:
            return
        if record.name.startswith("hunterops.alert_router"):
            return
        router = self.router
        if router is None:
            return
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)
        run_id = "runtime"
        try:
            extra_data = getattr(record, "extra_data", {})
            if isinstance(extra_data, dict):
                run_id = str(extra_data.get("run_id", run_id))
        except Exception:
            pass
        try:
            router.enqueue_critical_log(message=message, run_id=run_id)
        except Exception:
            return


def attach_alert_router(logger: logging.Logger, router: Any | None) -> None:
    for handler in logger.handlers:
        if isinstance(handler, AlertRouterLogHandler):
            handler.router = router
            return
    bridge = AlertRouterLogHandler()
    bridge.router = router
    logger.addHandler(bridge)


def setup_logging(log_file: Path, verbose: bool = False) -> logging.Logger:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("hunterops")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    use_color_console = os.getenv("HUNTEROPS_COLOR_LOGS", "0").strip() == "1"
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(ColorFormatter() if use_color_console else JsonFormatter())
    logger.addHandler(console)

    json_file = logging.FileHandler(log_file, encoding="utf-8")
    json_file.setLevel(logging.DEBUG)
    json_file.setFormatter(JsonFormatter())
    logger.addHandler(json_file)
    attach_alert_router(logger, None)

    return logger
