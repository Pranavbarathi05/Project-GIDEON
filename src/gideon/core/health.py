"""
gideon.core.health
~~~~~~~~~~~~~~~~~~
A lightweight health / status object.

HealthStatus is a pure data snapshot — it has no side-effects, no threads,
and no I/O.  Other subsystems can contribute checks by adding entries to
the *checks* mapping before the snapshot is frozen.

Example::

    from gideon.core.config import Settings
    from gideon.core.health import HealthStatus, Status

    health = HealthStatus.create(Settings.load())
    print(health.status)        # Status.OK
    print(health.to_dict())     # {'status': 'ok', 'checks': {...}, ...}
"""

from __future__ import annotations

import platform
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gideon.core.config import Settings


# ---------------------------------------------------------------------------
# Status enum
# ---------------------------------------------------------------------------


class Status(str, Enum):
    """High-level health classification."""

    OK = "ok"
    DEGRADED = "degraded"
    ERROR = "error"


# ---------------------------------------------------------------------------
# Individual check result
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CheckResult:
    """Result of a single health check."""

    status: Status
    message: str = ""

    def to_dict(self) -> dict:
        d: dict = {"status": self.status.value}
        if self.message:
            d["message"] = self.message
        return d


# ---------------------------------------------------------------------------
# HealthStatus snapshot
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HealthStatus:
    """Immutable health snapshot produced at start-up."""

    status: Status
    agent_name: str
    version: str
    env: str
    python_version: str
    platform: str
    timestamp: str
    checks: dict[str, CheckResult] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def create(cls, settings: "Settings") -> "HealthStatus":
        """Build a HealthStatus snapshot from *settings*.

        The overall status is derived automatically from the individual
        check results:
        - Any ERROR  → overall ERROR
        - Any DEGRADED → overall DEGRADED
        - Otherwise  → OK
        """
        from gideon import __version__

        checks: dict[str, CheckResult] = {}

        # ── Check: Python version ───────────────────────────────────────
        py_version = sys.version_info
        if py_version >= (3, 13):
            checks["python_version"] = CheckResult(
                Status.OK, f"{py_version.major}.{py_version.minor}.{py_version.micro}"
            )
        else:
            checks["python_version"] = CheckResult(
                Status.ERROR,
                f"Python 3.13+ required, got "
                f"{py_version.major}.{py_version.minor}.{py_version.micro}",
            )

        # ── Check: configuration integrity ─────────────────────────────
        checks["configuration"] = CheckResult(Status.OK, f"env={settings.env}")

        # ── Derive overall status ───────────────────────────────────────
        statuses = {c.status for c in checks.values()}
        if Status.ERROR in statuses:
            overall = Status.ERROR
        elif Status.DEGRADED in statuses:
            overall = Status.DEGRADED
        else:
            overall = Status.OK

        return cls(
            status=overall,
            agent_name=settings.agent_name,
            version=__version__,
            env=settings.env,
            python_version=".".join(map(str, sys.version_info[:3])),
            platform=platform.platform(),
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            checks=checks,
        )

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a plain dict suitable for JSON serialisation."""
        return {
            "status": self.status.value,
            "agent_name": self.agent_name,
            "version": self.version,
            "env": self.env,
            "python_version": self.python_version,
            "platform": self.platform,
            "timestamp": self.timestamp,
            "checks": {name: result.to_dict() for name, result in self.checks.items()},
        }
