"""Ordered, jittered start-up warm-up for the collector's caches (F7).

Every cache used to fire its first refresh the instant the collector booted, so
a restart hit FortiManager with all of them at once. With ``INVENTORY_CACHE`` on,
``defer`` instead holds each job until the inventory's first refresh has
finished (or ``_GATE_TIMEOUT_SECONDS`` has passed) and then starts it
``priority x _STEP_SECONDS`` plus jitter later. Priority 0 (the inventory) starts
at once. With the layer off, ``defer`` just starts the job on a daemon thread now,
exactly like the call sites did before.

Priorities: 0 inventory; 1 ADOM list / summary / versions / map; 2 pending status
and the executive device sweep; 3 backup, license and the hygiene sweep.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from collections.abc import Callable

from app.config import Config

logger = logging.getLogger(__name__)

_STEP_SECONDS = 15.0
_JITTER_SECONDS = 10.0
_GATE_TIMEOUT_SECONDS = 120.0

sleep = time.sleep  # seam for tests

_gate = threading.Event()
_lock = threading.Lock()
_threads: list[threading.Thread] = []


def delay_for(priority: int) -> float:
    """Seconds to wait after the gate opens: priority x step plus bounded jitter."""
    if priority <= 0:
        return 0.0
    return priority * _STEP_SECONDS + random.uniform(0.0, _JITTER_SECONDS)


def mark_inventory_ready() -> None:
    """Open the gate: the inventory's first refresh has finished (ok or not)."""
    _gate.set()


def _run(name: str, fn: Callable[[], None], priority: int) -> None:
    try:
        if priority > 0:
            if not _gate.wait(_GATE_TIMEOUT_SECONDS):
                logger.warning(
                    "boot_warmup: inventory not ready after %.0fs, starting %s anyway",
                    _GATE_TIMEOUT_SECONDS,
                    name,
                )
            sleep(delay_for(priority))
        fn()
    except Exception:
        logger.exception("boot_warmup: %s failed", name)


def defer(name: str, fn: Callable[[], None], priority: int) -> None:
    """Start *fn* in a daemon thread now (layer off) or in warm-up order (layer on)."""
    if not Config.INVENTORY_CACHE:
        thread = threading.Thread(target=fn, name=f"{name}_startup", daemon=True)
    else:
        thread = threading.Thread(
            target=_run, args=(name, fn, priority), name=f"{name}_warmup", daemon=True
        )
    with _lock:
        _threads.append(thread)
    thread.start()


def join(timeout: float = 5.0) -> bool:
    """Wait for every deferred job to finish (tests). True if all did."""
    deadline = time.monotonic() + timeout
    with _lock:
        threads = list(_threads)
    for t in threads:
        t.join(max(0.0, deadline - time.monotonic()))
    return not any(t.is_alive() for t in threads)


def reset() -> None:
    """Forget all state (tests)."""
    _gate.clear()
    with _lock:
        _threads.clear()
