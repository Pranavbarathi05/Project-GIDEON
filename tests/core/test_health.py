"""Unit tests for gideon.core.health."""

import sys

import pytest

from gideon.core.config import Settings
from gideon.core.health import CheckResult, HealthStatus, Status


def _make_settings(**overrides) -> Settings:
    defaults = dict(
        env="development",
        agent_name="GIDEON",
        log_level="INFO",
        log_format="text",
        log_file=None,
    )
    defaults.update(overrides)
    return Settings(**defaults)


class TestStatus:
    def test_values(self):
        assert Status.OK.value == "ok"
        assert Status.DEGRADED.value == "degraded"
        assert Status.ERROR.value == "error"


class TestCheckResult:
    def test_ok_dict(self):
        r = CheckResult(Status.OK, "all good")
        d = r.to_dict()
        assert d["status"] == "ok"
        assert d["message"] == "all good"

    def test_no_message_omitted(self):
        r = CheckResult(Status.OK)
        d = r.to_dict()
        assert "message" not in d


class TestHealthStatus:
    def test_create_returns_health(self):
        h = HealthStatus.create(_make_settings())
        assert isinstance(h, HealthStatus)

    def test_status_ok_on_python_313(self):
        # This test will only be meaningful when running Python 3.13+.
        h = HealthStatus.create(_make_settings())
        if sys.version_info >= (3, 13):
            assert h.status == Status.OK
        else:
            assert h.status == Status.ERROR

    def test_agent_name_from_settings(self):
        h = HealthStatus.create(_make_settings(agent_name="TestBot"))
        assert h.agent_name == "TestBot"

    def test_env_from_settings(self):
        h = HealthStatus.create(_make_settings(env="production"))
        assert h.env == "production"

    def test_python_version_present(self):
        h = HealthStatus.create(_make_settings())
        assert h.python_version.count(".") == 2

    def test_checks_populated(self):
        h = HealthStatus.create(_make_settings())
        assert "python_version" in h.checks
        assert "configuration" in h.checks

    def test_to_dict_structure(self):
        h = HealthStatus.create(_make_settings())
        d = h.to_dict()
        for key in ("status", "agent_name", "version", "env",
                    "python_version", "platform", "timestamp", "checks"):
            assert key in d

    def test_frozen(self):
        h = HealthStatus.create(_make_settings())
        with pytest.raises((AttributeError, TypeError)):
            h.status = Status.ERROR  # type: ignore[misc]
