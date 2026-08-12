"""
gideon.__main__
~~~~~~~~~~~~~~~
CLI entry point.  Run with:

    python -m gideon
    gideon          (after pip install -e .)
"""

from __future__ import annotations

import sys

from gideon.core.config import Settings
from gideon.core.health import HealthStatus, Status
from gideon.core.logging import configure_logging


def main() -> None:
    """Bootstrap GIDEON and report its current status."""
    # 1. Load configuration from environment / .env file
    settings = Settings.load()

    # 2. Set up structured logging
    logger = configure_logging(settings)

    logger.info(
        "GIDEON starting",
        extra={
            "agent_name": settings.agent_name,
            "env": settings.env,
            "log_level": settings.log_level,
        },
    )

    # 3. Build a health/status snapshot
    health = HealthStatus.create(settings)

    # 4. Report status to the user
    logger.info("Status report", extra={"status": health.to_dict()})

    if health.status == Status.OK:
        print(f"\n✓ {settings.agent_name} is operational ({settings.env})\n")
        sys.exit(0)
    else:
        print(f"\n✗ {settings.agent_name} reports degraded status: {health.status.value}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
