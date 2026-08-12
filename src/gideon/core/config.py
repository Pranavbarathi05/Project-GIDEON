"""
gideon.core.config
~~~~~~~~~~~~~~~~~~
Typed configuration loaded from environment variables (and an optional
.env file via python-dotenv).

All settings are read-only after construction.  Use Settings.load() as
the single factory; never instantiate Settings directly outside of tests.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Allowed value sets
# ---------------------------------------------------------------------------

_VALID_ENVS = {"development", "staging", "production"}
_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_VALID_LOG_FORMATS = {"text", "json"}


# ---------------------------------------------------------------------------
# Settings dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable application configuration."""

    env: str = "development"
    agent_name: str = "GIDEON"
    log_level: str = "INFO"
    log_format: str = "text"
    log_file: Path | None = None

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, dotenv_path: str | Path | None = None) -> "Settings":
        """Load settings from environment variables.

        Args:
            dotenv_path: Optional explicit path to a .env file.  When
                *None* python-dotenv will search parent directories for
                a .env file automatically (standard behaviour).
        """
        load_dotenv(dotenv_path=dotenv_path, override=False)

        env = _get_env_str("GIDEON_ENV", "development", _VALID_ENVS)
        agent_name = os.environ.get("GIDEON_AGENT_NAME", "GIDEON").strip() or "GIDEON"
        log_level = _get_env_str("GIDEON_LOG_LEVEL", "INFO", _VALID_LOG_LEVELS)
        log_format = _get_env_str("GIDEON_LOG_FORMAT", "text", _VALID_LOG_FORMATS)
        log_file_raw = os.environ.get("GIDEON_LOG_FILE", "").strip()
        log_file: Path | None = Path(log_file_raw) if log_file_raw else None

        return cls(
            env=env,
            agent_name=agent_name,
            log_level=log_level,
            log_format=log_format,
            log_file=log_file,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def log_level_int(self) -> int:
        """Return the stdlib logging integer constant for log_level."""
        return logging.getLevelName(self.log_level)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_env_str(key: str, default: str, allowed: set[str]) -> str:
    """Read *key* from the environment, validate against *allowed*, and fall
    back to *default* with a warning if the value is unrecognised."""
    raw = os.environ.get(key, default).strip()
    value = raw.upper() if key.endswith("LEVEL") else raw.lower() if key.endswith(("ENV", "FORMAT")) else raw
    if value not in allowed:
        import warnings
        warnings.warn(
            f"[gideon] '{key}={raw}' is not valid; "
            f"expected one of {sorted(allowed)!r}. "
            f"Falling back to '{default}'.",
            stacklevel=3,
        )
        return default
    return value
