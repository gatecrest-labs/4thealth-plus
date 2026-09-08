"""Shared route decorators — import these instead of redefining in every blueprint.

Usage::

    from app.decorators import login_required, tab_required, admin_required

    @bp.route("/my-page")
    @tab_required("my_tab")
    def my_page():
        ...

    @bp.route("/admin-only")
    @admin_required
    def admin_only():
        ...
"""

from __future__ import annotations

import time as _time
from functools import wraps

from flask import abort, current_app, jsonify, redirect, request, url_for
from flask import session as flask_session


def _revalidate_session() -> tuple | None:
    """Re-check that the session is still valid on every request.

    Returns a Flask response tuple (to be returned immediately) if the
    session is stale or the user no longer exists, else None.
    """
    # --- Absolute session cap ---
    login_at = flask_session.get("login_at")
    if login_at is None:
        # Session pre-dates this feature — force re-login.
        flask_session.clear()
        return redirect(url_for("auth.login")), 302

    lifetime = current_app.config.get("SESSION_ABSOLUTE_LIFETIME", 36000)
    if _time.time() - login_at > lifetime:
        flask_session.clear()
        if (
            request.path.startswith("/api/")
            or request.path.startswith("/admin/api/")
            or request.path.startswith("/external/api/")
        ):
            return jsonify({"error": "Session expired"}), 401
        return redirect(url_for("auth.login")), 302

    # --- User still exists + role unchanged ---
    username = flask_session.get("user", "")
    if username:
        from app.auth import _load_users
        from app.groups import get_allowed_tabs

        users = _load_users()
        entry = users.get(username)
        ad_groups = flask_session.get("ad_groups", [])
        if entry is None:
            # RADIUS-only users are not in users.json — keep session valid
            # as long as they have a role set from authentication.
            if not flask_session.get("role"):
                flask_session.clear()
                if (
                    request.path.startswith("/api/")
                    or request.path.startswith("/admin/api/")
                    or request.path.startswith("/external/api/")
                ):
                    return jsonify({"error": "Not authenticated"}), 401
                return redirect(url_for("auth.login")), 302
        else:
            # Re-sync role and tabs from disk for local users
            flask_session["role"] = entry.get("role", "viewer")
        flask_session["allowed_tabs"] = list(
            get_allowed_tabs(
                username, ad_groups=ad_groups, role=flask_session.get("role")
            )
        )

    return None


def login_required(f):
    """Redirect to /login when no session exists."""

    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in flask_session:
            if request.path.startswith("/api/") or request.path.startswith(
                "/admin/api/"
            ):
                return jsonify({"error": "Not authenticated"}), 401
            return redirect(url_for("auth.login", next=request.path))
        err = _revalidate_session()
        if err is not None:
            return err
        return f(*args, **kwargs)

    return decorated


def tab_required(*tab_keys: str):
    """Allow only users who have permission for any of ``tab_keys`` (or admin role)."""

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user" not in flask_session:
                if request.path.startswith("/api/"):
                    return jsonify({"error": "Not authenticated"}), 401
                return redirect(url_for("auth.login", next=request.path))
            err = _revalidate_session()
            if err is not None:
                return err
            if flask_session.get("role") != "admin" and not set(tab_keys) & set(
                flask_session.get("allowed_tabs", [])
            ):
                if request.path.startswith("/api/"):
                    return jsonify({"error": "Access denied"}), 403
                abort(403)
            return f(*args, **kwargs)

        return decorated

    return decorator


def admin_required(f):
    """Allow only users with role == 'admin'; return 403 or redirect otherwise."""

    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in flask_session:
            if request.path.startswith("/api/") or request.path.startswith(
                "/admin/api/"
            ):
                return jsonify({"error": "Not authenticated"}), 401
            return redirect(url_for("auth.login", next=request.path))
        err = _revalidate_session()
        if err is not None:
            return err
        if flask_session.get("role") != "admin":
            if request.path.startswith("/api/") or request.path.startswith(
                "/admin/api/"
            ):
                return jsonify({"error": "Admin role required"}), 403
            abort(403)
        return f(*args, **kwargs)

    return decorated


def check_adom_access(adom: str) -> tuple | None:
    """Return a 403 JSON response tuple if the current user cannot access ``adom``.

    Returns None when access is permitted (caller should proceed normally).
    Always permits admin users.  For non-admins, delegates to groups.user_can_access_adom.

    Usage inside a route::

        if err := check_adom_access(adom):
            return err
    """
    if flask_session.get("role") == "admin":
        return None
    from app.groups import user_can_access_adom

    ad_groups = flask_session.get("ad_groups", [])
    if not user_can_access_adom(
        flask_session.get("user", ""), adom, ad_groups=ad_groups
    ):
        return jsonify(
            {"error": f"Access to ADOM '{adom}' is not permitted for your account"}
        ), 403
    return None
