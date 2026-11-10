"""F1 FMG access layer: shared HTTP session pool, in-flight cap, retry policy.

``FMGClient._post`` is the single choke point for FortiManager traffic; this
module holds the process-wide state it uses. The in-flight slot wraps only one
HTTP round trip, never a whole operation, so task polling and backoff sleeps
never hold a slot.
"""

from __future__ import annotations

import threading

import requests
from requests.adapters import HTTPAdapter

_POOL_CONNECTIONS = 4
_POOL_MAXSIZE = 32

_lock = threading.Lock()
_sessions: dict[bool, requests.Session] = {}


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


def reset() -> None:
    """Drop all process-wide state (tests)."""
    with _lock:
        for session in _sessions.values():
            session.close()
        _sessions.clear()
