"""F1 FMG access layer: shared HTTP session pool, in-flight cap, retry policy.

``FMGClient._post`` is the single choke point for FortiManager traffic; this
module holds the process-wide state it uses. The in-flight slot wraps only one
HTTP round trip, never a whole operation, so task polling and backoff sleeps
never hold a slot.
"""

from __future__ import annotations

import contextlib
import random
import threading
import time
from collections.abc import Iterator

import requests
from requests.adapters import HTTPAdapter

from app import fmg_metrics
from app.config import Config

sleep = time.sleep  # seam: tests replace this so backoff does not wait

_BACKOFF_BASE = 0.5
_BACKOFF_MAX = 8.0
_COLLECTOR_CAP = 8
_WEB_CAP = 4

_POOL_CONNECTIONS = 4
_POOL_MAXSIZE = 32

_lock = threading.Lock()
_sessions: dict[bool, requests.Session] = {}

_slot_lock = threading.Lock()
_semaphore: threading.BoundedSemaphore | None = None
_semaphore_cap = 0
_inflight = 0
_peak = 0


def get_session(verify_ssl: bool) -> requests.Session:
    """One pooled ``requests.Session`` per ``verify_ssl`` value per process."""
    with _lock:
        session = _sessions.get(bool(verify_ssl))
        if session is None:
            session = requests.Session()
            session.mount(
                "https://",
                HTTPAdapter(
                    pool_connections=_POOL_CONNECTIONS, pool_maxsize=_POOL_MAXSIZE
                ),
            )
            _sessions[bool(verify_ssl)] = session
        return session


def inflight_cap() -> int:
    """Per-process cap on concurrent FMG round trips; 0 means unlimited."""
    explicit = Config.FMG_MAX_INFLIGHT
    if explicit is not None:
        return max(0, explicit)
    return _COLLECTOR_CAP if fmg_metrics.role() == "collector" else _WEB_CAP


def _get_semaphore(cap: int) -> threading.BoundedSemaphore:
    global _semaphore, _semaphore_cap
    with _slot_lock:
        if _semaphore is None or _semaphore_cap != cap:
            _semaphore = threading.BoundedSemaphore(cap)
            _semaphore_cap = cap
        return _semaphore


@contextlib.contextmanager
def slot() -> Iterator[float]:
    """Hold one in-flight slot for one round trip; yields seconds spent waiting."""
    global _inflight, _peak
    cap = inflight_cap()
    sem = _get_semaphore(cap) if cap > 0 else None
    started = time.monotonic()
    if sem is not None:
        sem.acquire()
    waited = time.monotonic() - started
    with _slot_lock:
        _inflight += 1
        _peak = max(_peak, _inflight)
    try:
        yield waited
    finally:
        with _slot_lock:
            _inflight -= 1
        if sem is not None:
            sem.release()


def peak_inflight() -> int:
    """Highest number of concurrent slots seen since the last ``reset()``."""
    with _slot_lock:
        return _peak


def reset() -> None:
    """Drop all process-wide state (tests)."""
    global _semaphore, _semaphore_cap, _inflight, _peak
    with _slot_lock:
        _semaphore, _semaphore_cap, _inflight, _peak = None, 0, 0, 0
    with _lock:
        for session in _sessions.values():
            session.close()
        _sessions.clear()


def backoff_delay(attempt: int) -> float:
    """Seconds to wait after failed attempt *attempt* (1-based): doubling, capped, jittered."""
    ceiling = min(_BACKOFF_MAX, _BACKOFF_BASE * (2 ** (attempt - 1)))
    return random.uniform(0.5 * ceiling, ceiling)


def _refused_before_send(exc: BaseException) -> bool:
    """True when the failure happened while connecting, so FMG never saw the request."""
    if isinstance(exc, requests.ConnectTimeout):
        return True
    text = f"{exc!r} {exc}"
    return (
        "NewConnectionError" in text or "Failed to establish a new connection" in text
    )


def is_retryable(method: str, exc: BaseException | None, status: int | None) -> bool:
    """Whether a failed ``_post`` may be sent again without risking a duplicate.

    A request that provably never reached FMG (connection refused/timeout while
    connecting) is always safe. Anything that may have been processed (5xx,
    read timeout, connection dropped mid-flight) is replayed only for ``get``.
    """
    if exc is not None and _refused_before_send(exc):
        return True
    if str(method).lower() != "get":
        return False
    if status is not None:
        return status >= 500
    return isinstance(exc, requests.ConnectionError | requests.Timeout)


_LAYER_FLAGS = ("INVENTORY_CACHE", "POLICY_STORE", "AUDIT_SNAPSHOTS", "JOB_QUEUE")


def warn_if_password_auth(logger) -> bool:
    """Warn once when username/password auth is used with a scale layer on.

    Password auth opens a real FortiManager admin session per client and FMG
    caps those; an API token has no session. Returns True when it warned.
    """
    if Config.FMG_API_TOKEN or not Config.FMG_USERNAME:
        return False
    if not any(getattr(Config, flag, False) for flag in _LAYER_FLAGS):
        return False
    logger.warning(
        "FMG username/password auth is in use with a scale layer enabled; "
        "FortiManager caps admin sessions. Set FMG_API_TOKEN instead."
    )
    return True
