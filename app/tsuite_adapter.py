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
    ))

The app's CSRF protection must exempt this blueprint (these are bearer-token
API routes with no session): exempt the /4tsuite/ prefix or call
csrf.exempt(blueprint), whichever the app already does for its old route.

Depends on Flask only. Spec: Docs/superpowers/specs/2026-10-07-plugin-protocol-design.md
in the 4tSuite repo. Keep the copies in every sub-app identical; the conformance
CLI (python -m tools.check_app) reports a stale ADAPTER_VERSION.
"""

from __future__ import annotations

from collections.abc import Callable

from flask import Blueprint, abort, jsonify, request

ADAPTER_VERSION = "1.0.0"
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
