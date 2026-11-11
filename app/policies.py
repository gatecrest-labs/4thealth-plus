"""Facade over the policy/object store (F3): the one place consumers read packages,
policies, policy blocks and firewall objects.

With ``POLICY_STORE`` off (or ``fresh=True``) every function is a straight call on
the FMG client. With it on, data is served from the store the collector fills; a
row that is missing, older than ``policy_store.max_age_seconds()`` or unreadable
fails open to a live call for that read only (counted). Results are copies.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from datetime import UTC, datetime

from app import policy_store
from app.config import Config

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_counters = {"hits": 0, "fallbacks": 0, "store_errors": 0}

_GLOBAL_KINDS = frozenset({"address", "addrgrp", "vip", "ippool"})
_LIVE_OBJECT_METHOD = {
    "address": "get_address_objects",
    "addrgrp": "get_address_groups",
    "service": "get_service_objects",
    "svcgrp": "get_service_groups",
    "vip": "get_vip_objects",
    "ippool": "get_ippool_objects",
}


def _bump(name: str) -> None:
    with _lock:
        _counters[name] += 1


def counters() -> dict:
    with _lock:
        return dict(_counters)


def reset_counters() -> None:
    with _lock:
        for key in _counters:
            _counters[key] = 0


def _enabled() -> bool:
    return bool(Config.POLICY_STORE)


def _is_system_adom(adom: str) -> bool:
    """``forti*`` ADOMs are FortiManager system ADOMs the collector never stores."""
    return adom.lower().startswith("forti")


def _fresh(age: float | None) -> bool:
    return age is not None and age <= policy_store.max_age_seconds()


def _hit(value):
    _bump("hits")
    return value


def _fallback():
    _bump("fallbacks")


def _store_error(exc: Exception) -> None:
    _bump("store_errors")
    logger.warning("policies: store unreadable, going live: %s", exc)


# ── packages ─────────────────────────────────────────────────────────────────


def _stored_packages(adom: str) -> list[dict] | None:
    try:
        row = policy_store.get_packages(adom)
    except policy_store.PolicyStoreError as exc:
        _store_error(exc)
        return None
    if row is not None and _fresh(row["age_seconds"]):
        return row["entries"]
    return None


def packages(client, adom: str, fresh: bool = False) -> list[dict]:
    if not _enabled() or fresh:
        return client.get_policy_packages(adom)
    if _is_system_adom(adom):
        return []
    entries = _stored_packages(adom)
    if entries is not None:
        return _hit(entries)
    _fallback()
    return client.get_policy_packages(adom)


def _entry(adom: str, pkg_path: str) -> dict | None:
    for entry in _stored_packages(adom) or []:
        if isinstance(entry, dict) and entry.get("path") == pkg_path:
            return entry
    return None


def pkg_settings(client, adom: str, pkg_path: str, fresh: bool = False) -> dict:
    if not _enabled() or fresh:
        return client.get_pkg_settings(adom, pkg_path)
    if _is_system_adom(adom):
        return {}
    entry = _entry(adom, pkg_path)
    if entry is not None and "package settings" in entry:
        return _hit(entry.get("package settings") or {})
    _fallback()
    return client.get_pkg_settings(adom, pkg_path)


def pkg_scope(client, adom: str, pkg_path: str, fresh: bool = False) -> list:
    if not _enabled() or fresh:
        return client.get_pkg_scope_members(adom, pkg_path)
    if _is_system_adom(adom):
        return []
    entry = _entry(adom, pkg_path)
    if entry is not None and ("scope member" in entry or "scope_member" in entry):
        scope = entry.get("scope member") or entry.get("scope_member") or []
        return _hit(scope if isinstance(scope, list) else [])
    _fallback()
    return client.get_pkg_scope_members(adom, pkg_path)


# ── policies and policy blocks ───────────────────────────────────────────────


def policies(client, adom: str, pkg_path: str, fresh: bool = False) -> list[dict]:
    if not _enabled() or fresh:
        return client.get_policies(adom, pkg_path)
    if _is_system_adom(adom):
        return []
    try:
        row = policy_store.get_policies(adom, pkg_path)
    except policy_store.PolicyStoreError as exc:
        _store_error(exc)
        row = None
    if row is not None and _fresh(row["age_seconds"]):
        return _hit(row["policies"])
    _fallback()
    return client.get_policies(adom, pkg_path)


def pblock_policies(client, adom: str, block: str, strict: bool = False) -> list[dict]:
    if not _enabled():
        return client.get_pblock_policies(adom, block, strict=strict)
    if _is_system_adom(adom):
        return []
    try:
        row = policy_store.get_block(adom, block)
    except policy_store.PolicyStoreError as exc:
        _store_error(exc)
        row = None
    if row is not None and _fresh(row["age_seconds"]):
        return _hit(row["policies"])
    _fallback()
    return client.get_pblock_policies(adom, block, strict=strict)


# ── objects ──────────────────────────────────────────────────────────────────


def objects(
    client, adom: str, kind: str, scope: str = "all", fresh: bool = False
) -> list[dict]:
    """Firewall objects of *kind* (address, addrgrp, service, svcgrp, vip, ippool)."""
    method = getattr(client, _LIVE_OBJECT_METHOD[kind])

    def live(adom_name: str, scope: str = "all"):
        # The default scope is passed implicitly: older callers' clients (and test
        # doubles) take only the ADOM for some object kinds.
        return method(adom_name) if scope == "all" else method(adom_name, scope=scope)

    if not _enabled() or fresh:
        return live(adom, scope=scope)
    if _is_system_adom(adom):
        return []
    keys: list[str] = []
    if scope in ("all", "local"):
        keys.append(adom)
    if scope in ("all", "global") and kind in _GLOBAL_KINDS:
        keys.append(policy_store.GLOBAL_KEY)
    merged: list[dict] = []
    try:
        for key in keys:
            row = policy_store.get_objects(key, kind)
            if row is None or not _fresh(row["age_seconds"]):
                merged = None
                break
            merged.extend(row["objects"])
    except policy_store.PolicyStoreError as exc:
        _store_error(exc)
        merged = None
    if merged is not None:
        return _hit(merged)
    _fallback()
    return live(adom, scope=scope)


# ── per-package state (no blobs loaded) ──────────────────────────────────────


def package_state(adom: str) -> dict[str, dict]:
    """``{package path: {fingerprint, fetched_at, age_seconds, policy_count, status}}``
    for the ADOM's packages that have fresh stored data; ``{}`` when the layer is
    off, the ADOM is a system ADOM or the store is unreadable. No policy blob is
    loaded, so a sweep can tell cheaply which packages are unchanged."""
    if not _enabled() or _is_system_adom(adom):
        return {}
    try:
        meta = policy_store.package_meta(adom)
    except policy_store.PolicyStoreError as exc:
        _store_error(exc)
        return {}
    return {
        m["pkg"]: {
            k: m[k]
            for k in (
                "fingerprint",
                "fetched_at",
                "age_seconds",
                "policy_count",
                "status",
            )
        }
        for m in meta
        if m["fetched_at"] and _fresh(m["age_seconds"])
    }


def package_counts(adom: str) -> dict[str, int]:
    """``{package path: rule count}`` from the store (see ``package_state``)."""
    return {path: row["policy_count"] for path, row in package_state(adom).items()}


def generation(adom: str) -> str | None:
    """A token that changes only when the stored *content* behind an ADOM changes
    (package, policy-block and object fingerprints), not when a refetch merely
    refreshes ages. ``None`` when the layer is off or nothing is stored. Used to
    decide when an in-process index built from the store must be rebuilt."""
    if not _enabled() or _is_system_adom(adom):
        return None
    try:
        packages = [m for m in policy_store.package_meta(adom) if m["fetched_at"]]
        if not packages:
            return None
        parts = [f"p:{m['pkg']}:{m['fingerprint']}" for m in packages]
        parts += [
            f"b:{m['block']}:{m['fingerprint']}"
            for m in policy_store.block_meta(adom)
            if m["fetched_at"]
        ]
        parts += [
            f"o:{m['scope_key']}:{m['kind']}:{m['fingerprint']}"
            for m in policy_store.objects_meta()
            if m["fetched_at"] and m["scope_key"] in (adom, policy_store.GLOBAL_KEY)
        ]
    except policy_store.PolicyStoreError:
        return None
    return hashlib.sha1("\n".join(sorted(parts)).encode()).hexdigest()


# ── freshness ────────────────────────────────────────────────────────────────


def data_as_of(adom: str, pkg_path: str | None = None) -> str | None:
    """When the data behind a package (or the oldest package of an ADOM) was fetched."""
    if not _enabled():
        return None
    try:
        if pkg_path is not None:
            row = policy_store.get_policies(adom, pkg_path)
            return row["fetched_at"] if row else None
        stamps = [
            m["fetched_at"] for m in policy_store.package_meta(adom) if m["fetched_at"]
        ]
    except policy_store.PolicyStoreError:
        return None
    return min(stamps) if stamps else None


def age_note_html(adom: str, threshold_seconds: float = 900.0) -> str:
    """A one-line HTML note for scheduled reports when the data behind them is older
    than *threshold_seconds*; ``""`` when the layer is off, nothing is stored or the
    data is recent."""
    stamp = data_as_of(adom)
    if not stamp:
        return ""
    try:
        taken = datetime.fromisoformat(stamp)
    except ValueError:
        return ""
    age = (datetime.now(UTC) - taken).total_seconds()
    if age <= threshold_seconds:
        return ""
    ago = f"{round(age / 3600)} h" if age >= 5400 else f"{round(age / 60)} min"
    return (
        '<p style="font-size:12px;color:#6b7280;margin:0 0 12px 0">'
        f"Policy data as of {taken.strftime('%Y-%m-%d %H:%M')} UTC ({ago} ago). "
        "The collector refreshes policies from FortiManager about every 6 hours.</p>"
    )
