"""4tSuite plugin-protocol adapter -- vendor this single file into a sub-app.

Copy it next to the app's own sso_verify.py (for example app/tsuite_adapter.py),
delete the app's old /4tsuite/groups route, and register the blueprint:

    from app.sso_verify import APP_ID, verify_service_token
    from app.tsuite_adapter import create_blueprint

    app.register_blueprint(create_blueprint(
        app_id=APP_ID,
        display_name="4tLog",
        health_path="/login",
        get_tabs=lambda: sorted(KNOWN_TABS),
        get_groups=list_group_names,
        apply_group_change=apply_group_change,   # (username, group, is_member) -> None
        verify_service_token=verify_service_token,
        capabilities=["revocations"] if checker else [],
    ))

where `checker = session_checker_from_env()` (None unless TSUITE_REVOCATIONS_URL
and TSUITE_REVOCATIONS_TOKEN are set). On each request that relies on an SSO
session, call `checker(username, login_at)` and end the session when it returns
False; login_at is the epoch time the app established that session.

The app's CSRF protection must exempt this blueprint (these are bearer-token
API routes with no session): exempt the /4tsuite/ prefix or call
csrf.exempt(blueprint), whichever the app already does for its old route.

Depends on Flask only. Spec: Docs/superpowers/specs/2026-10-07-plugin-protocol-design.md
in the 4tSuite repo. Keep the copies in every sub-app identical; the conformance
CLI (python -m tools.check_app) reports a stale ADAPTER_VERSION.
"""

from __future__ import annotations

import json
import math
import os
import ssl
import threading
import time
import urllib.error  # noqa: F401
import urllib.request
from collections.abc import Callable, Sequence

from flask import Blueprint, abort, jsonify, request

ADAPTER_VERSION = "1.2.0"
PROTOCOL_VERSION = 1


def create_blueprint(
    *,
    app_id: str,
    display_name: str,
    health_path: str,
    get_tabs: Callable[[], list[str]],
    get_groups: Callable[[], list[str]],
    apply_group_change: Callable[[str, str, bool], None],
    verify_service_token: Callable[[str, str], dict | None],
    capabilities: Sequence[str] = (),
) -> Blueprint:
    bp = Blueprint("tsuite_adapter", __name__)

    def require_scope(scope: str) -> None:
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        try:
            claims = verify_service_token(token, scope)
        except Exception:  # noqa: BLE001
            # The verifier is app-supplied; whatever it raises must fail
            # closed as 403, never surface as a 500.
            claims = None
        if not isinstance(claims, dict) or claims.get("scope") != scope:
            abort(403)

    @bp.get("/4tsuite/manifest")
    def manifest():
        require_scope("manifest_read")
        return jsonify(
            {
                "protocol_version": PROTOCOL_VERSION,
                "adapter_version": ADAPTER_VERSION,
                "app_id": app_id,
                "display_name": display_name,
                "health_path": health_path,
                "tabs": list(get_tabs()),
                "groups": list(get_groups()),
                "capabilities": list(capabilities),
            }
        )

    @bp.get("/4tsuite/health")
    def health():
        require_scope("health_read")
        return jsonify({"status": "ok", "protocol_version": PROTOCOL_VERSION})

    @bp.post("/4tsuite/groups")
    def receive_group_push():
        require_scope("groups_push")
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            abort(400, description="body must be a JSON object")
        username = data.get("username")
        group = data.get("group")
        member = data.get("member")
        if not isinstance(username, str) or not username:
            abort(400, description="username must be a non-empty string")
        if not isinstance(group, str) or not group:
            abort(400, description="group must be a non-empty string")
        if not isinstance(member, bool):
            abort(400, description="member must be true or false")
        if username.startswith("_service:"):
            abort(400, description="cannot grant group membership to a service sentinel username")
        if group not in get_groups():
            abort(400, description=f"no such group: {group}")
        apply_group_change(username, group, member)
        return "", 204

    return bp


GRACE_SECONDS = 300
CACHE_SECONDS = 30
RETRY_SECONDS = 5  # re-probe interval after a failed fetch once the grace has run out
_MAX_BODY = 1024 * 1024
_CHUNK = 8192


def _parse_revocations(payload) -> tuple[dict[str, float], float]:
    if not isinstance(payload, dict):
        raise ValueError("revocations payload must be an object")
    users = payload.get("users")
    server_time = payload.get("server_time")
    if (
        not isinstance(users, dict)
        or isinstance(server_time, bool)
        or not isinstance(server_time, (int, float))
        or not math.isfinite(server_time)
    ):
        raise ValueError("revocations payload has the wrong shape")
    parsed = {}
    for name, ts in users.items():
        if (
            not isinstance(name, str)
            or isinstance(ts, bool)
            or not isinstance(ts, (int, float))
            or not math.isfinite(ts)
        ):
            raise ValueError("revocations payload has a bad entry")
        parsed[name] = float(ts)
    return parsed, float(server_time)


def make_session_checker(
    *,
    fetch: Callable[[], dict],
    cache_seconds: float = CACHE_SECONDS,
    grace_seconds: float = GRACE_SECONDS,
    clock: Callable[[], float] = time.time,
) -> Callable[[str, float], bool]:
    """Return sso_session_valid(username, login_at) -> bool.

    login_at is the sub-app's own epoch time when it established the SSO
    session. Invalid when 4tSuite recorded a logout for that user later than
    login_at (corrected for clock skew). When 4tSuite cannot be reached the
    last known list still applies, and sessions stay valid only until
    grace_seconds have passed since the last successful check (or since this
    checker was created, if none ever succeeded).
    """
    lock = threading.Lock()
    state = {
        "users": {},
        "offset": 0.0,
        "fetched_at": None,
        "last_good": clock(),
    }

    def refresh(now: float) -> None:
        try:
            users, server_time = _parse_revocations(fetch())
        except Exception:  # noqa: BLE001 - any failure is "4tSuite unavailable"
            # Do not hammer a down server. Once past the grace every session is already
            # rejected, so probe again soon: recovery must not wait out a full cache window.
            retry = cache_seconds
            if now - state["last_good"] > grace_seconds:
                retry = min(cache_seconds, RETRY_SECONDS)
            state["fetched_at"] = now - cache_seconds + retry
            return
        state["users"] = users
        state["offset"] = server_time - now
        state["fetched_at"] = now
        state["last_good"] = now

    def sso_session_valid(username: str, login_at: float) -> bool:
        now = clock()
        with lock:
            fetched_at = state["fetched_at"]
            if fetched_at is None or now - fetched_at >= cache_seconds:
                refresh(now)
            if now - state["last_good"] > grace_seconds:
                return False
            logged_out_at = state["users"].get(username)
            offset = state["offset"]
        if logged_out_at is None:
            return True
        return not (logged_out_at > login_at + offset)

    return sso_session_valid


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # never forward the bearer token
        return None


def make_http_fetch(
    suite_url: str, token: str, *, verify_tls: bool = True, timeout: float = 3
) -> Callable[[], dict]:
    url = suite_url.rstrip("/") + "/revocations"
    context = None if verify_tls else ssl._create_unverified_context()  # noqa: S323 - opt-in, local stacks
    handlers = [_NoRedirect()]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)

    def fetch() -> dict:
        request_ = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        deadline = time.monotonic() + 2 * timeout
        chunks: list[bytes] = []
        total = 0
        with opener.open(request_, timeout=timeout) as response:
            while total <= _MAX_BODY:
                if time.monotonic() > deadline:
                    raise TimeoutError("revocations response too slow")
                chunk = response.read1(min(_CHUNK, _MAX_BODY + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
        if total > _MAX_BODY:
            raise ValueError("revocations response too large")
        return json.loads(b"".join(chunks))

    return fetch


def session_checker_from_env(environ=os.environ) -> Callable[[str, float], bool] | None:
    url = environ.get("TSUITE_REVOCATIONS_URL", "").strip()
    token = environ.get("TSUITE_REVOCATIONS_TOKEN", "").strip()
    if not url or not token:
        return None
    verify = environ.get("TSUITE_REVOCATIONS_VERIFY_TLS", "true").strip().lower() not in (
        "false", "0", "no",
    )
    return make_session_checker(fetch=make_http_fetch(url, token, verify_tls=verify))
