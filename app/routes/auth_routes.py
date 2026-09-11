import threading
import time
from collections import defaultdict
from urllib.parse import urlparse

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from app import registry
from app.app_logger import app_log
from app.auth import authenticate
from app.groups import get_allowed_tabs

# ---------------------------------------------------------------------------
# In-memory sliding-window rate limiter for /login
# Limits: 10 attempts per IP per 10 minutes, 5 attempts per username per 10 minutes.
# ---------------------------------------------------------------------------
_WINDOW_SECONDS = 600  # 10 minutes
_IP_MAX = 10  # max failures per IP per window
_USER_MAX = 5  # max failures per username per window
_USER_FAILURES_MAX_KEYS = 10_000  # memory bound on the attacker-controlled key space

_lock = threading.Lock()
_ip_failures: dict[str, list[float]] = defaultdict(list)
_user_failures: dict[str, list[float]] = defaultdict(list)


def _norm_username(username: str) -> str:
    return username.strip().lower()


def _is_rate_limited(ip: str, username: str) -> bool:
    now = time.monotonic()
    cutoff = now - _WINDOW_SECONDS
    norm = _norm_username(username)
    with _lock:
        _ip_failures[ip] = [t for t in _ip_failures[ip] if t > cutoff]
        _user_failures[norm] = [t for t in _user_failures[norm] if t > cutoff]
        return (
            len(_ip_failures[ip]) >= _IP_MAX or len(_user_failures[norm]) >= _USER_MAX
        )


def _record_failure(ip: str, username: str) -> None:
    now = time.monotonic()
    norm = _norm_username(username)
    with _lock:
        _ip_failures[ip].append(now)
        # Evict oldest key if at capacity (FIFO approximation using dict ordering)
        if (
            len(_user_failures) >= _USER_FAILURES_MAX_KEYS
            and norm not in _user_failures
        ):
            oldest_key = next(iter(_user_failures))
            del _user_failures[oldest_key]
        _user_failures[norm].append(now)


def _clear_failures(ip: str, username: str) -> None:
    norm = _norm_username(username)
    with _lock:
        _ip_failures.pop(ip, None)
        _user_failures.pop(norm, None)


def _safe_redirect(url: str) -> bool:
    """Return True only for relative paths with no scheme or netloc."""
    parsed = urlparse(url)
    return (
        not parsed.scheme
        and not parsed.netloc
        and parsed.path.startswith("/")
        and url != "/login"
    )


bp = Blueprint("auth", __name__)


def _first_allowed_url(allowed_tabs: list) -> str:
    """Return the URL for the first tab the user can access, in registry order."""
    for key, meta in registry.get_registry().items():
        if key in allowed_tabs:
            return url_for(meta["endpoint"])
    return url_for("auth.login")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("login.html"), 400

        ip = request.remote_addr or ""
        if _is_rate_limited(ip, username):
            app_log("WARN", "auth", "Login rate-limited", username=username, remote=ip)
            from app import login_metrics as _lm

            _lm.record_event(False)
            flash(
                "Too many failed attempts. Please wait before trying again.", "danger"
            )
            return render_template("login.html"), 429

        auth_result = authenticate(username, password)
        if auth_result is not None:
            role, ad_groups = auth_result
            _clear_failures(ip, username)
            session.permanent = True
            session["user"] = username
            session["role"] = role
            session["ad_groups"] = ad_groups
            allowed = list(get_allowed_tabs(username, ad_groups=ad_groups, role=role))
            session["allowed_tabs"] = allowed
            session["login_at"] = int(time.time())
            app_log(
                "INFO",
                "auth",
                "Login successful",
                username=username,
                role=session["role"],
            )
            from app import login_metrics as _lm

            _lm.record_event(True)
            next_url = request.args.get("next", "").strip()
            if next_url and _safe_redirect(next_url):
                return redirect(next_url)
            return redirect(_first_allowed_url(allowed))

        _record_failure(ip, username)
        app_log("WARN", "auth", "Failed login attempt", username=username, remote=ip)
        from app import login_metrics as _lm

        _lm.record_event(False)
        flash("Invalid credentials.", "danger")
        return render_template("login.html"), 401
    return render_template("login.html")


@bp.route("/logout", methods=["POST"])
def logout():
    username = session.get("user", "unknown")
    app_log("INFO", "auth", "Logout", username=username)
    session.clear()
    return redirect(url_for("auth.login"))
