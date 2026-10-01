"""Verify a 4tSuite-issued JWT and map it to a username or a service scope.

This is the entire trust boundary between 4thealth-plus and 4tSuite --
kept intentionally tiny and stable. See 4tSuite's
Docs/superpowers/specs/2026-09-26-phase2-sso-trust-hook-design.md for
the login token contract, and
Docs/superpowers/specs/2026-09-26-groupsync-health-restart-design.md
(same 4tSuite repo) for the service-token (scope-based) contract
verify_service_token checks.
"""

from __future__ import annotations

from pathlib import Path

import jwt

PUBLIC_KEY_PATH = Path(__file__).parent.parent / "sso_public_key.pem"
APP_ID = "4thealth-plus"


def _decode(token: str) -> dict | None:
    # is_file(), not exists(): this app can run entirely standalone, with
    # no 4tSuite integration configured at all. When that's true, the
    # docker-compose bind mount for this path has no host file to mount --
    # Docker silently substitutes an empty directory instead of leaving the
    # path absent. exists() would see that directory and proceed to
    # read_bytes(), raising an unhandled IsADirectoryError. is_file() treats
    # that the same as "missing" and fails closed cleanly.
    if not PUBLIC_KEY_PATH.is_file():
        return None
    try:
        return jwt.decode(
            token,
            PUBLIC_KEY_PATH.read_bytes(),
            algorithms=["EdDSA"],
            audience=APP_ID,
            issuer="4tsuite",
            leeway=30,
            options={"require": ["exp", "iat", "nbf", "sub", "aud", "iss"]},
        )
    except jwt.InvalidTokenError:
        return None


def verify_token(token: str) -> str | None:
    """Returns the username claim on success, None on any verification failure."""
    claims = _decode(token)
    if claims is None or "scope" in claims:
        return None
    return claims.get("sub") or None


def verify_service_token(token: str, expected_scope: str) -> dict | None:
    claims = _decode(token)
    if claims is None or claims.get("scope") != expected_scope:
        return None
    return claims
