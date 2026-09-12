"""Collector process entrypoint — owns every BackgroundScheduler job.

Run as:

    python -m app.collector

This is the single process a split (default) deployment should run
separately from the Gunicorn web workers — see docker-compose.yml's
`collector` service and container.md. It reuses the exact same
create_app() factory the web process uses (so every scheduler module's
init_scheduler(app) call, and every Flask extension/config those
schedulers rely on via app.app_context(), works identically to today's
single-process mode) — the only difference is that this process forces
RUN_SCHEDULERS="inline" regardless of the deployment's own .env value,
so the schedulers start here even when the web service's own
RUN_SCHEDULERS is left at the split-mode default ("off").

The collector process does not serve HTTP. It has no gunicorn, no
bound port, nothing listening — it exists purely so the
BackgroundScheduler instances (and the daemon threads APScheduler's
executor pool spins up) stay alive. See
~/Documents/4thealth-notes/scale-review-1000-devices.md section C1 for
why this process split exists.
"""

from __future__ import annotations

import logging
import os
import time

# Must be set BEFORE `from app import create_app` triggers app.config's
# module-level `os.environ.get("RUN_SCHEDULERS", "off")` read.
os.environ["RUN_SCHEDULERS"] = "inline"

from app import create_app  # noqa: E402

logger = logging.getLogger(__name__)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    app = create_app()
    logger.info(
        "collector: every BackgroundScheduler job started, entering idle loop"
    )
    with app.app_context():
        while True:
            time.sleep(3600)


if __name__ == "__main__":
    main()
