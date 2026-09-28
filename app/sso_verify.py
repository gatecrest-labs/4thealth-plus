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
    if not PUBLIC_KEY_PATH.exists():
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
