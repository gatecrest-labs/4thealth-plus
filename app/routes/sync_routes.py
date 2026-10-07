"""4tSuite plugin-protocol routes (manifest, health, group push).

All logic lives in the vendored app/tsuite_adapter.py; this module only
supplies this app's callbacks. Exempt from CSRF via the /4tsuite/ path prefix
in app/__init__.py's before_request hook -- these are pure bearer-token API
endpoints, authenticated by verify_service_token instead.
"""

from __future__ import annotations

from app import groups
from app.sso_verify import APP_ID, verify_service_token
from app.tsuite_adapter import create_blueprint


def _apply_group_change(username: str, group: str, is_member: bool) -> None:
    if is_member:
        groups.add_group_member(group, username)
    else:
        groups.remove_group_member(group, username)


bp = create_blueprint(
    app_id=APP_ID,
    display_name="4tHealth+",
    health_path="/login",
    # KNOWN_TABS is reassigned at startup (app/__init__.py), so read it lazily.
    get_tabs=lambda: sorted(groups.KNOWN_TABS),
    get_groups=lambda: [g["name"] for g in groups.list_groups()],
    apply_group_change=_apply_group_change,
    verify_service_token=verify_service_token,
)
