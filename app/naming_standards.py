"""Validation and atomic persistence for naming.yaml, backing the
Admin → Naming Standards UI.

Mirrors app/app_settings.py's atomic-write pattern. Unlike app_settings.py
this file validates before writing: an admin save that would leave
naming.yaml unable to render a name (missing pattern, unknown token) is
rejected with a 400 and a list of errors, never partially applied.
"""

from __future__ import annotations

import threading
from pathlib import Path

import yaml

from app.atomic_io import atomic_write_text
from app.planner import standards as _standards
from app.planner.naming_template import render

_REPO_ROOT = Path(__file__).parent.parent
_NAMING_PATH = _standards._NAMING_FILE
_NAMING_EXAMPLE_PATH = _REPO_ROOT / "naming.example.yaml"

_lock = threading.Lock()

# In-scope, live-rendered object types (see spec's Scope section) and the
# per-type dummy token values used to smoke-test each pattern before a save.
# Each type gets ONLY the tokens it actually receives at generation time in
# app.planner.standards.object_name()/policy_name() — mirrors
# app/static/js/admin.js's NS_TOKEN_FIELDS exactly. Validating a pattern
# against a pooled, all-types token set would let e.g. a host pattern that
# references <TICKET_ID> pass validation and then blow up for real at
# generation time, since object_name("host", ...) never supplies that token.
_EDITABLE_TYPES = ("host", "network", "service", "policy")
_DUMMY_TOKENS_BY_TYPE = {
    "host": {
        "IP_ADDRESS": "10.0.0.1",
    },
    "network": {
        "NETWORK_ADDRESS": "10.0.0.0",
        "PREFIX_LEN": "24",
    },
    "service": {
        "PROTO": "tcp",
        "PORT": "443",
    },
    "policy": {
        "TICKET_ID": "CHG000000",
        "SRC_INTF": "WAN1",
        "DST_INTF": "DMZ",
        "SEQ": "001",
    },
}


class NamingValidationError(Exception):
    """Raised by save_naming() when validate_naming() finds errors."""

    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors


def get_naming() -> dict:
    return _standards.load_naming(path=_NAMING_PATH)


def validate_naming(data: dict) -> list[str]:
    """Render each in-scope pattern against its own type's dummy token set.
    Returns a list of human-readable errors (empty = valid)."""
    errors: list[str] = []
    conventions = (
        (data or {}).get("platforms", {}).get("fortigate", {}).get("conventions", {})
    )
    for obj_type in _EDITABLE_TYPES:
        entry = conventions.get(obj_type)
        if not entry:
            errors.append(f"{obj_type}: no convention entry found")
            continue
        pattern = entry.get("pattern")
        if not pattern:
            errors.append(f"{obj_type}: pattern is empty or missing")
            continue
        try:
            render(pattern, **_DUMMY_TOKENS_BY_TYPE[obj_type])
        except Exception as exc:  # NamingTemplateError, but keep this broad
            errors.append(f"{obj_type}: {exc}")

    log_settings = (data or {}).get("log_settings")
    if not isinstance(log_settings, dict) or not log_settings:
        errors.append(
            "log_settings: missing — importing/saving a naming.yaml without "
            "log_settings would break Rule Validation's logging-requirement "
            "lookups"
        )
    return errors


def save_naming(data: dict) -> None:
    errors = validate_naming(data)
    if errors:
        raise NamingValidationError(errors)
    with _lock:
        atomic_write_text(
            _NAMING_PATH,
            yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100),
        )


def reset_to_default() -> None:
    with _lock:
        atomic_write_text(
            _NAMING_PATH, _NAMING_EXAMPLE_PATH.read_text(encoding="utf-8")
        )
