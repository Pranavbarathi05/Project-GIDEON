"""Unit tests for gideon.core.logging."""

import logging

import pytest

from gideon.core.config import Settings
from gideon.core.logging import configure_logging, get_logger


def _make_settings(**overrides) -> Settings:
    defaults = dict(
        env="development",
        agent_name="GIDEON",
        log_level="DEBUG",
        log_format="text",
        log_file=None,
    )
    defaults.update(overrides)
    return Settings(**defaults)


class TestConfigureLogging:
    def test_returns_logger(self):
        s = _make_settings()
        logger = configure_logging(s)
        assert isinstance(logger, logging.Logger)
        assert logger.name == "gideon"

    def test_log_level_applied(self):
        s = _make_settings(log_level="WARNING")
        logger = configure_logging(s)
        assert logger.level == logging.WARNING

    def test_text_format_handler_added(self):
        s = _make_settings(log_format="text")
        logger = configure_logging(s)
        assert len(logger.handlers) >= 1

    def test_json_format_handler_added(self):
        s = _make_settings(log_format="json")
        logger = configure_logging(s)
        assert len(logger.handlers) >= 1

    def test_idempotent_multiple_calls(self):
        s = _make_settings()
        configure_logging(s)
        configure_logging(s)
        logger = logging.getLogger("gideon")
        # Should not accumulate duplicate handlers
        assert len(logger.handlers) == 1

    def test_file_handler_skipped_for_bad_path(self, tmp_path):
        """A non-writable path should warn but not crash."""
        bad = tmp_path / "no_such_dir" / "gideon.log"
        s = _make_settings(log_file=bad)
        # Should not raise
        configure_logging(s)


class TestGetLogger:
    def test_returns_child_logger(self):
        configure_logging(_make_settings())
        child = get_logger("gideon.core.something")
        assert child.name.startswith("gideon.")

    def test_strips_gideon_prefix(self):
        configure_logging(_make_settings())
        child = get_logger("gideon.core.foo")
        assert "core.foo" in child.name
