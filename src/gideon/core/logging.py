"""
gideon.core.logging
~~~~~~~~~~~~~~~~~~~
Structured application logging for GIDEON.

Supports two output formats:
  * text  — human-readable (default, good for development)
  * json  — machine-readable (good for log aggregators)

Usage::

    from gideon.core.config import Settings
    from gideon.core.logging import configure_logging

    settings = Settings.load()
    logger = configure_logging(settings)
    logger.info("hello", extra={"key": "value"})
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gideon.core.config import Settings

# ---------------------------------------------------------------------------
# Public names
# ---------------------------------------------------------------------------

__all__ = ["configure_logging", "get_logger"]

# Root logger name used throughout the project.
_ROOT_LOGGER = "gideon"


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------


class _TextFormatter(logging.Formatter):
    """Human-readable log formatter with timestamps."""

    _LEVEL_COLOURS = {
        "DEBUG": "\033[36m",     # cyan
        "INFO": "\033[32m",      # green
        "WARNING": "\033[33m",   # yellow
        "ERROR": "\033[31m",     # red
        "CRITICAL": "\033[35m",  # magenta
    }
    _RESET = "\033[0m"

    def __init__(self, *, use_colour: bool = True) -> None:
        super().__init__()
        self._use_colour = use_colour and sys.stderr.isatty()

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        )[:-3] + "Z"
        level = record.levelname
        if self._use_colour:
            colour = self._LEVEL_COLOURS.get(level, "")
            level_str = f"{colour}{level:<8}{self._RESET}"
        else:
            level_str = f"{level:<8}"

        msg = f"{ts} {level_str} [{record.name}] {record.getMessage()}"

        # Append any *extra* fields as key=value pairs
        extra = _extract_extra(record)
        if extra:
            pairs = "  ".join(f"{k}={v!r}" for k, v in sorted(extra.items()))
            msg = f"{msg}  {pairs}"

        if record.exc_info:
            msg += "\n" + self.formatException(record.exc_info)

        return msg


class _JsonFormatter(logging.Formatter):
    """JSON-lines log formatter — one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        payload.update(_extract_extra(record))

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Fields that are always present on a LogRecord — we strip these so that
# only user-supplied *extra* keys are forwarded.
_LOGRECORD_BUILTIN_KEYS: frozenset[str] = frozenset(
    vars(logging.LogRecord("", 0, "", 0, "", (), None)).keys()
    | {"message", "asctime"}
)


def _extract_extra(record: logging.LogRecord) -> dict:
    return {
        k: v
        for k, v in vars(record).items()
        if k not in _LOGRECORD_BUILTIN_KEYS
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def configure_logging(settings: "Settings") -> logging.Logger:
    """Configure the root *gideon* logger from *settings*.

    This function is idempotent — calling it more than once simply
    replaces the handlers on the root logger.

    Returns the configured logger.
    """
    logger = logging.getLogger(_ROOT_LOGGER)
    logger.setLevel(settings.log_level_int)
    logger.handlers.clear()
    logger.propagate = False

    use_json = settings.log_format == "json"
    formatter: logging.Formatter = _JsonFormatter() if use_json else _TextFormatter()

    # Always add a stdout/stderr handler
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    # Optionally also write to a file
    if settings.log_file is not None:
        try:
            file_handler = logging.FileHandler(settings.log_file, encoding="utf-8")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except OSError as exc:
            logger.warning("Could not open log file %s: %s", settings.log_file, exc)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger namespaced under the *gideon* root.

    Example::

        log = get_logger(__name__)   # → logging.getLogger("gideon.core.foo")
    """
    # Strip leading "gideon." so callers can pass __name__ directly.
    short = name.removeprefix("gideon.").removeprefix("src.gideon.")
    return logging.getLogger(f"{_ROOT_LOGGER}.{short}")
