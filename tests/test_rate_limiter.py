import os
import time

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

import importlib


def _fresh_module():
    """Import auth_routes with a clean rate-limiter state."""
    import app.routes.auth_routes as m
    importlib.reload(m)
    return m


def test_username_case_normalisation():
    """'Admin' and 'admin' should share the same rate-limit bucket."""
    m = _fresh_module()
    now = time.monotonic()
    # Inject failures under 'admin' (lowercase)
    with m._lock:
        m._user_failures["admin"] = [now] * m._USER_MAX

    # Checking 'Admin' (mixed case) should see those failures
    assert m._is_rate_limited("1.2.3.4", "Admin") is True


def test_username_strip_normalisation():
    """' admin ' (with spaces) should be normalised to 'admin'."""
    m = _fresh_module()
    now = time.monotonic()
    with m._lock:
        m._user_failures["admin"] = [now] * m._USER_MAX

    assert m._is_rate_limited("1.2.3.4", " admin ") is True


def test_user_failures_memory_bound():
    """_user_failures dict should not exceed _USER_FAILURES_MAX_KEYS entries."""
    m = _fresh_module()
    for i in range(m._USER_FAILURES_MAX_KEYS + 50):
        m._record_failure("1.2.3.4", f"attacker_{i}")

    assert len(m._user_failures) <= m._USER_FAILURES_MAX_KEYS
