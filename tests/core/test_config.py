"""Unit tests for gideon.core.config."""

import os

import pytest

from gideon.core.config import Settings


class TestSettingsDefaults:
    def test_defaults_without_env(self, monkeypatch):
        """All GIDEON_ vars absent → defaults are used."""
        for key in ("GIDEON_ENV", "GIDEON_AGENT_NAME", "GIDEON_LOG_LEVEL",
                    "GIDEON_LOG_FORMAT", "GIDEON_LOG_FILE"):
            monkeypatch.delenv(key, raising=False)

        s = Settings.load()
        assert s.env == "development"
        assert s.agent_name == "GIDEON"
        assert s.log_level == "INFO"
        assert s.log_format == "text"
        assert s.log_file is None

    def test_log_level_int(self, monkeypatch):
        monkeypatch.delenv("GIDEON_LOG_LEVEL", raising=False)
        import logging
        s = Settings.load()
        assert s.log_level_int == logging.INFO


class TestSettingsFromEnv:
    def test_custom_values(self, monkeypatch):
        monkeypatch.setenv("GIDEON_ENV", "production")
        monkeypatch.setenv("GIDEON_AGENT_NAME", "MyAgent")
        monkeypatch.setenv("GIDEON_LOG_LEVEL", "DEBUG")
        monkeypatch.setenv("GIDEON_LOG_FORMAT", "json")
        monkeypatch.setenv("GIDEON_LOG_FILE", "/tmp/gideon.log")

        s = Settings.load()
        assert s.env == "production"
        assert s.agent_name == "MyAgent"
        assert s.log_level == "DEBUG"
        assert s.log_format == "json"
        assert s.log_file is not None
        assert str(s.log_file) == "/tmp/gideon.log"

    def test_invalid_env_falls_back(self, monkeypatch):
        monkeypatch.setenv("GIDEON_ENV", "nonsense")
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            s = Settings.load()
        assert s.env == "development"
        assert any("GIDEON_ENV" in str(warning.message) for warning in w)

    def test_invalid_log_level_falls_back(self, monkeypatch):
        monkeypatch.setenv("GIDEON_LOG_LEVEL", "VERBOSE")
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            s = Settings.load()
        assert s.log_level == "INFO"

    def test_empty_log_file_is_none(self, monkeypatch):
        monkeypatch.setenv("GIDEON_LOG_FILE", "  ")
        s = Settings.load()
        assert s.log_file is None

    def test_settings_is_frozen(self, monkeypatch):
        monkeypatch.delenv("GIDEON_ENV", raising=False)
        s = Settings.load()
        with pytest.raises((AttributeError, TypeError)):
            s.env = "production"  # type: ignore[misc]
