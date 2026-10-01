"""Group management — local store backed by groups.json.

A group has:
  name           str   unique identifier
  members        list  of local username strings (users.json accounts)
  ad_groups      list  of AD/RADIUS group name strings — any user whose RADIUS
                       reply contains one of these values is treated as a member
  allowed_tabs   list  of tab keys (see KNOWN_TABS)
  adom_restrict  bool  when True, only ADOMs in allowed_adoms are accessible
  allowed_adoms  list  of ADOM name strings (only used when adom_restrict=True)

Tab keys are the canonical identifiers the nav uses. When a new route/tab is
added to the app, just add its key to KNOWN_TABS — it will appear automatically
in the admin UI.

ADOM access rules:
  - Admin users always have unrestricted access to all ADOMs.
  - For non-admin users the effective allowed ADOM set is the UNION of
    allowed_adoms across all groups where adom_restrict=True that they belong
    to, PLUS all ADOMs if they belong to any group where adom_restrict=False.
  - In other words: a single unrestricted group grants full ADOM access.
  - If a user belongs to no group, they have no ADOM access.

AD group membership (ad_groups):
  When a user authenticates via RADIUS, FortiAuthenticator returns Filter-Id /
  Class attributes listing the user's AD groups.  Those values are stored in
  session['ad_groups'] and passed into get_allowed_tabs() / get_allowed_adoms()
  so membership is resolved at login time without any extra LDAP query.
"""

import json
import threading
from pathlib import Path

GROUPS_FILE = Path(__file__).parent.parent / "groups.json"
_lock = threading.Lock()

# Populated at startup by app/__init__.py from app.registry.
# Do not edit manually — add new tabs via registry.register() in your blueprint.
KNOWN_TABS: dict[str, str] = {}


def _load() -> dict:
    if not GROUPS_FILE.exists():
        return {}
    with GROUPS_FILE.open() as f:
        return json.load(f)


def _save(data: dict) -> None:
    with GROUPS_FILE.open("w") as f:
        json.dump(data, f, indent=2)


# ── Public API ────────────────────────────────────────────────────────────────


def _group_to_dict(name: str, g: dict) -> dict:
    return {
        "name": name,
        "members": g.get("members", []),
        "ad_groups": g.get("ad_groups", []),
        "allowed_tabs": g.get("allowed_tabs", []),
        "adom_restrict": bool(g.get("adom_restrict", False)),
        "allowed_adoms": g.get("allowed_adoms", []),
    }


def list_groups() -> list[dict]:
    with _lock:
        groups = _load()
    return [_group_to_dict(name, g) for name, g in groups.items()]


def get_group(name: str) -> dict | None:
    with _lock:
        groups = _load()
    g = groups.get(name)
    if g is None:
        return None
    return _group_to_dict(name, g)


def create_group(
    name: str,
    members: list[str] | None = None,
    ad_groups: list[str] | None = None,
    allowed_tabs: list[str] | None = None,
    adom_restrict: bool = False,
    allowed_adoms: list[str] | None = None,
) -> bool:
    """Returns False if the group name already exists."""
    name = name.strip()
    if not name:
        raise ValueError("Group name cannot be empty.")
    with _lock:
        groups = _load()
        if name in groups:
            return False
        groups[name] = {
            "members": list(members or []),
            "ad_groups": list(ad_groups or []),
            "allowed_tabs": list(allowed_tabs or []),
            "adom_restrict": bool(adom_restrict),
            "allowed_adoms": list(allowed_adoms or []),
        }
        _save(groups)
    return True


def update_group(
    name: str,
    members: list[str],
    allowed_tabs: list[str],
    adom_restrict: bool = False,
    allowed_adoms: list[str] | None = None,
    ad_groups: list[str] | None = None,
) -> bool:
    """Returns False if the group does not exist."""
    with _lock:
        groups = _load()
        if name not in groups:
            return False
        groups[name]["members"] = list(members)
        groups[name]["ad_groups"] = list(ad_groups or [])
        # Only filter against KNOWN_TABS when the registry has been populated
        # (it's empty before the Flask app factory runs — skip filtering in that case
        # so manage scripts and tests don't silently clear tab lists).
        if KNOWN_TABS:
            groups[name]["allowed_tabs"] = [t for t in allowed_tabs if t in KNOWN_TABS]
        else:
            groups[name]["allowed_tabs"] = list(allowed_tabs)
        groups[name]["adom_restrict"] = bool(adom_restrict)
        groups[name]["allowed_adoms"] = list(allowed_adoms or [])
        _save(groups)
    return True


def add_group_member(group_name: str, username: str) -> None:
    """No-op if the group does not exist."""
    group = get_group(group_name)
    if group is None:
        return
    members = set(group["members"])
    members.add(username)
    update_group(
        group_name,
        members=sorted(members),
        allowed_tabs=group["allowed_tabs"],
        adom_restrict=group["adom_restrict"],
        allowed_adoms=group["allowed_adoms"],
        ad_groups=group["ad_groups"],
    )


def remove_group_member(group_name: str, username: str) -> None:
    """No-op if the group does not exist."""
    group = get_group(group_name)
    if group is None:
        return
    members = set(group["members"])
    members.discard(username)
    update_group(
        group_name,
        members=sorted(members),
        allowed_tabs=group["allowed_tabs"],
        adom_restrict=group["adom_restrict"],
        allowed_adoms=group["allowed_adoms"],
        ad_groups=group["ad_groups"],
    )


def delete_group(name: str) -> bool:
    with _lock:
        groups = _load()
        if name not in groups:
            return False
        del groups[name]
        _save(groups)
    return True


def get_allowed_tabs(
    username: str, ad_groups: list[str] | None = None, role: str | None = None
) -> set[str]:
    """Return the set of tab keys the user may access.

    Rules:
    - Admins always get all tabs.
    - Non-admins get the union of allowed_tabs across all groups they belong to.
    - Group membership is satisfied by either:
        (a) username in group['members']  — explicit local membership
        (b) any value in ad_groups overlaps group['ad_groups']  — AD/RADIUS group match
    - If a user is in no group they get no tabs (empty set).
    """
    from app.auth import _load_users  # local import to avoid circular

    # role passed explicitly (e.g. from RADIUS) takes precedence over users.json
    if role == "admin":
        return set(KNOWN_TABS.keys())

    users = _load_users()
    user_entry = users.get(username, {})
    if user_entry.get("role") == "admin":
        return set(KNOWN_TABS.keys())

    with _lock:
        groups = _load()

    ad_set = set(ad_groups or [])
    tabs: set[str] = set()
    for g in groups.values():
        if username in g.get("members", []) or ad_set & set(g.get("ad_groups", [])):
            tabs.update(g.get("allowed_tabs", []))
    return tabs


def user_can_access_tab(username: str, tab_key: str) -> bool:
    return tab_key in get_allowed_tabs(username)


def get_allowed_adoms(
    username: str, ad_groups: list[str] | None = None, role: str | None = None
) -> list[str] | None:
    """Return the list of ADOM names the user may access, or None for unrestricted.

    Rules:
    - Admin users → None (unrestricted; caller must treat None as "allow all").
    - Non-admin users with at least one group where adom_restrict=False → None.
    - Non-admin users where every group has adom_restrict=True → union of their
      allowed_adoms lists (may be empty, meaning no ADOM access at all).
    - Users in no group → empty list (no access).

    Group membership is satisfied by username in group['members'] OR by any
    overlap between ad_groups and group['ad_groups'].
    """
    from app.auth import _load_users  # local import to avoid circular

    # role passed explicitly (e.g. from RADIUS) takes precedence over users.json
    if role == "admin":
        return None  # unrestricted

    users = _load_users()
    user_entry = users.get(username, {})
    if user_entry.get("role") == "admin":
        return None  # unrestricted

    with _lock:
        groups = _load()

    ad_set = set(ad_groups or [])
    user_groups = [
        g
        for g in groups.values()
        if username in g.get("members", []) or ad_set & set(g.get("ad_groups", []))
    ]

    if not user_groups:
        return []  # no group membership → no access

    # If any group is unrestricted, the user gets full ADOM access
    if any(not g.get("adom_restrict", False) for g in user_groups):
        return None  # unrestricted

    # All groups restrict ADOMs — return the union
    allowed: set[str] = set()
    for g in user_groups:
        allowed.update(g.get("allowed_adoms", []))
    return sorted(allowed)


def user_can_access_adom(
    username: str, adom: str, ad_groups: list[str] | None = None
) -> bool:
    """Return True if the user may access the given ADOM."""
    allowed = get_allowed_adoms(username, ad_groups=ad_groups)
    if allowed is None:
        return True  # unrestricted
    return adom in allowed
