"""Receives 4tSuite's pushed group-membership changes for this app.

Exempt from this app's CSRF check via the /4tsuite/ path prefix in
app/__init__.py's before_request hook -- this is a pure bearer-token
API endpoint, authenticated by verify_service_token instead. See that
file's existing /external/api/ exemption for the established pattern
this follows.
"""

from __future__ import annotations

from flask import Blueprint, abort, request

from app.groups import add_group_member, get_group, remove_group_member
from app.sso_verify import verify_service_token

bp = Blueprint("sync", __name__)


@bp.route("/4tsuite/groups", methods=["POST"])
def receive_group_push():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    claims = verify_service_token(token, expected_scope="groups_push")
    if claims is None:
        abort(403)
    data = request.get_json()
    if data["username"].startswith("_service:"):
        abort(400, description="cannot grant group membership to a service sentinel username")
    if get_group(data["group"]) is None:
        abort(400, description=f"no such group: {data['group']}")
    if data["member"]:
        add_group_member(data["group"], data["username"])
    else:
        remove_group_member(data["group"], data["username"])
    return "", 204
