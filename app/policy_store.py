"""Policy and object store in the shared collector database (F3).

Written only by the collector (``app.policy_cache``); web workers read it through
``app.policies`` and only ever write a tiny per-package refresh request.

One row per package (policies), policy block, and (scope, object kind); packages
of an ADOM are one row. Bodies are zlib-compressed JSON blobs so a 300-rule
package is tens of KB and a read touches only the row it needs. A failed refresh
sets ``status='error'`` and keeps the previous blob: ``None`` from a getter means
"never collected", an empty list means "collected and empty".
"""

from __future__ import annotations

import json
import zlib
from datetime import UTC, datetime

from app.config import Config
from app.hygiene_pkg_store import effective_ttl_for
from app.hygiene_pkg_store import fingerprint as fingerprint_of  # noqa: F401  (re-export)
from app.inventory_store import InventoryStoreError, _age, _Conn

PolicyStoreError = InventoryStoreError

KINDS = ("address", "addrgrp", "service", "svcgrp", "vip", "ippool")
GLOBAL_KEY = "global"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS policy_adom_pkgs (
    adom TEXT PRIMARY KEY, fetched_at TEXT NOT NULL, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS policy_pkg (
    adom TEXT NOT NULL, pkg TEXT NOT NULL, fetched_at TEXT, fingerprint TEXT,
    policy_count INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL, error TEXT, blob BLOB,
    PRIMARY KEY (adom, pkg));
CREATE TABLE IF NOT EXISTS policy_block (
    adom TEXT NOT NULL, block TEXT NOT NULL, fetched_at TEXT, fingerprint TEXT,
    policy_count INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL, error TEXT, blob BLOB,
    PRIMARY KEY (adom, block));
CREATE TABLE IF NOT EXISTS policy_objects (
    scope_key TEXT NOT NULL, kind TEXT NOT NULL, fetched_at TEXT, fingerprint TEXT,
    status TEXT NOT NULL, error TEXT, blob BLOB, PRIMARY KEY (scope_key, kind));
CREATE TABLE IF NOT EXISTS policy_refresh_request (
    adom TEXT NOT NULL, pkg TEXT NOT NULL, last_requested_at TEXT NOT NULL,
    pending INTEGER NOT NULL, PRIMARY KEY (adom, pkg));
"""
_SCHEMA_ID = "policy_store"


def _conn(write: bool = False) -> _Conn:
    return _Conn(write=write, schema=_SCHEMA, schema_id=_SCHEMA_ID)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _pack(obj) -> bytes:
    return zlib.compress(json.dumps(obj, separators=(",", ":")).encode(), 6)


def _unpack(blob: bytes):
    return json.loads(zlib.decompress(blob))


def effective_ttl_seconds(adom: str, pkg: str) -> float:
    """Package TTL: configured hours x a stable 0.75..1.25 factor (spreads refetches)."""
    return effective_ttl_for(adom, pkg, float(Config.POLICY_PACKAGE_TTL_HOURS) * 3600.0)


def max_age_seconds() -> float:
    """Age beyond which a reader goes live (default 2 x the longest jittered TTL)."""
    configured = Config.POLICY_MAX_AGE_SECS
    if configured and configured > 0:
        return float(configured)
    return 2.0 * 1.25 * float(Config.POLICY_PACKAGE_TTL_HOURS) * 3600.0


# ── generic row helpers ──────────────────────────────────────────────────────


def _put(
    table: str, keys: dict, *, fingerprint: str, count: int | None, blob_obj
) -> None:
    cols = list(keys)
    names = ", ".join(cols)
    marks = ", ".join("?" for _ in cols)
    extra_cols = ["fetched_at", "fingerprint", "status", "error", "blob"]
    extra_vals = [_now(), fingerprint, "ok", None, _pack(blob_obj)]
    if count is not None:
        extra_cols.append("policy_count")
        extra_vals.append(count)
    updates = ", ".join(f"{c}=excluded.{c}" for c in extra_cols)
    with _conn(write=True) as conn:
        conn.execute(
            f"INSERT INTO {table} ({names}, {', '.join(extra_cols)}) "
            f"VALUES ({marks}, {', '.join('?' for _ in extra_cols)}) "
            f"ON CONFLICT({names}) DO UPDATE SET {updates}",
            [*keys.values(), *extra_vals],
        )
        conn.commit()


def _touch(table: str, keys: dict) -> None:
    where = " AND ".join(f"{c}=?" for c in keys)
    with _conn(write=True) as conn:
        conn.execute(
            f"UPDATE {table} SET fetched_at=?, status='ok', error=NULL WHERE {where}",
            [_now(), *keys.values()],
        )
        conn.commit()


def _mark_error(table: str, keys: dict, error: str) -> None:
    cols = list(keys)
    names = ", ".join(cols)
    marks = ", ".join("?" for _ in cols)
    with _conn(write=True) as conn:
        conn.execute(
            f"INSERT INTO {table} ({names}, status, error) VALUES ({marks}, 'error', ?) "
            f"ON CONFLICT({names}) DO UPDATE SET status='error', error=excluded.error",
            [*keys.values(), error[:500]],
        )
        conn.commit()


def _get(table: str, keys: dict, extra: str = "") -> dict | None:
    where = " AND ".join(f"{c}=?" for c in keys)
    with _conn() as conn:
        row = conn.execute(
            f"SELECT fetched_at, fingerprint, status, error, blob{extra} "
            f"FROM {table} WHERE {where}",
            list(keys.values()),
        ).fetchone()
    if row is None or row[4] is None:
        return None
    out = {
        "fetched_at": row[0],
        "age_seconds": _age(row[0]),
        "fingerprint": row[1],
        "status": row[2],
        "error": row[3],
        "data": _unpack(row[4]),
    }
    if extra:
        out["policy_count"] = row[5]
    return out


# ── packages (one row per ADOM) ──────────────────────────────────────────────


def put_packages(adom: str, entries: list[dict]) -> None:
    with _conn(write=True) as conn:
        conn.execute(
            "INSERT INTO policy_adom_pkgs (adom, fetched_at, blob) VALUES (?,?,?) "
            "ON CONFLICT(adom) DO UPDATE SET fetched_at=excluded.fetched_at, blob=excluded.blob",
            (adom, _now(), _pack(entries)),
        )
        conn.commit()


def get_packages(adom: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute(
            "SELECT fetched_at, blob FROM policy_adom_pkgs WHERE adom=?", (adom,)
        ).fetchone()
    if row is None:
        return None
    return {
        "entries": _unpack(row[1]),
        "fetched_at": row[0],
        "age_seconds": _age(row[0]),
    }


# ── package policies ─────────────────────────────────────────────────────────


def put_policies(adom: str, pkg: str, policies: list[dict], fingerprint: str) -> None:
    _put(
        "policy_pkg",
        {"adom": adom, "pkg": pkg},
        fingerprint=fingerprint,
        count=len(policies),
        blob_obj=policies,
    )


def get_policies(adom: str, pkg: str) -> dict | None:
    got = _get("policy_pkg", {"adom": adom, "pkg": pkg}, extra=", policy_count")
    if got is None:
        return None
    got["policies"] = got.pop("data")
    return got


def touch_policies(adom: str, pkg: str) -> None:
    _touch("policy_pkg", {"adom": adom, "pkg": pkg})


def mark_policies_error(adom: str, pkg: str, error: str) -> None:
    _mark_error("policy_pkg", {"adom": adom, "pkg": pkg}, error)


def package_meta(adom: str) -> list[dict]:
    """Per-package freshness without loading any blob."""
    with _conn() as conn:
        rows = conn.execute(
            "SELECT pkg, fetched_at, fingerprint, policy_count, status, error "
            "FROM policy_pkg WHERE adom=? ORDER BY pkg",
            (adom,),
        ).fetchall()
    return [
        {
            "pkg": r[0],
            "fetched_at": r[1],
            "age_seconds": _age(r[1]),
            "fingerprint": r[2],
            "policy_count": r[3],
            "status": r[4],
            "error": r[5],
        }
        for r in rows
    ]


def delete_missing_packages(adom: str, keep: set[str]) -> int:
    with _conn(write=True) as conn:
        have = [
            r[0]
            for r in conn.execute("SELECT pkg FROM policy_pkg WHERE adom=?", (adom,))
        ]
        gone = [p for p in have if p not in keep]
        for p in gone:
            conn.execute("DELETE FROM policy_pkg WHERE adom=? AND pkg=?", (adom, p))
        conn.commit()
    return len(gone)


# ── policy blocks ────────────────────────────────────────────────────────────


def put_block(adom: str, block: str, policies: list[dict], fingerprint: str) -> None:
    _put(
        "policy_block",
        {"adom": adom, "block": block},
        fingerprint=fingerprint,
        count=len(policies),
        blob_obj=policies,
    )


def get_block(adom: str, block: str) -> dict | None:
    got = _get("policy_block", {"adom": adom, "block": block}, extra=", policy_count")
    if got is None:
        return None
    got["policies"] = got.pop("data")
    return got


def touch_block(adom: str, block: str) -> None:
    _touch("policy_block", {"adom": adom, "block": block})


def mark_block_error(adom: str, block: str, error: str) -> None:
    _mark_error("policy_block", {"adom": adom, "block": block}, error)


def block_meta(adom: str) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT block, fetched_at, fingerprint, status, error, policy_count "
            "FROM policy_block WHERE adom=? ORDER BY block",
            (adom,),
        ).fetchall()
    return [
        {
            "block": r[0],
            "fetched_at": r[1],
            "age_seconds": _age(r[1]),
            "fingerprint": r[2],
            "status": r[3],
            "error": r[4],
            "policy_count": r[5],
        }
        for r in rows
    ]


def delete_missing_blocks(adom: str, keep: set[str]) -> int:
    with _conn(write=True) as conn:
        have = [
            r[0]
            for r in conn.execute(
                "SELECT block FROM policy_block WHERE adom=?", (adom,)
            )
        ]
        gone = [b for b in have if b not in keep]
        for b in gone:
            conn.execute("DELETE FROM policy_block WHERE adom=? AND block=?", (adom, b))
        conn.commit()
    return len(gone)


# ── objects ──────────────────────────────────────────────────────────────────


def put_objects(
    scope_key: str, kind: str, objects: list[dict], fingerprint: str
) -> None:
    _put(
        "policy_objects",
        {"scope_key": scope_key, "kind": kind},
        fingerprint=fingerprint,
        count=None,
        blob_obj=objects,
    )


def get_objects(scope_key: str, kind: str) -> dict | None:
    got = _get("policy_objects", {"scope_key": scope_key, "kind": kind})
    if got is None:
        return None
    got["objects"] = got.pop("data")
    return got


def touch_objects(scope_key: str, kind: str) -> None:
    _touch("policy_objects", {"scope_key": scope_key, "kind": kind})


def mark_objects_error(scope_key: str, kind: str, error: str) -> None:
    _mark_error("policy_objects", {"scope_key": scope_key, "kind": kind}, error)


def object_state(scope_key: str, kind: str) -> dict | None:
    """Status/error/fetched_at of an object table even when it never succeeded."""
    with _conn() as conn:
        row = conn.execute(
            "SELECT fetched_at, status, error FROM policy_objects WHERE scope_key=? AND kind=?",
            (scope_key, kind),
        ).fetchone()
    return {"fetched_at": row[0], "status": row[1], "error": row[2]} if row else None


def objects_meta() -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT scope_key, kind, fetched_at, fingerprint, status, error FROM policy_objects "
            "ORDER BY scope_key, kind"
        ).fetchall()
    return [
        {
            "scope_key": r[0],
            "kind": r[1],
            "fetched_at": r[2],
            "age_seconds": _age(r[2]),
            "fingerprint": r[3],
            "status": r[4],
            "error": r[5],
        }
        for r in rows
    ]


def known_adoms() -> set[str]:
    """ADOMs that currently have any package or package-list row."""
    with _conn() as conn:
        out = {r[0] for r in conn.execute("SELECT DISTINCT adom FROM policy_adom_pkgs")}
        out |= {r[0] for r in conn.execute("SELECT DISTINCT adom FROM policy_pkg")}
    return out


# ── ADOM-level cleanup ───────────────────────────────────────────────────────


def delete_missing_adoms(keep: set[str]) -> None:
    """Drop every row of ADOMs no longer in FortiManager (the global scope stays)."""
    with _conn(write=True) as conn:
        known: set[str] = set()
        for table, col in (
            ("policy_adom_pkgs", "adom"),
            ("policy_pkg", "adom"),
            ("policy_block", "adom"),
            ("policy_refresh_request", "adom"),
            ("policy_objects", "scope_key"),
        ):
            known |= {r[0] for r in conn.execute(f"SELECT DISTINCT {col} FROM {table}")}
        for adom in known - set(keep) - {GLOBAL_KEY}:
            for table, col in (
                ("policy_adom_pkgs", "adom"),
                ("policy_pkg", "adom"),
                ("policy_block", "adom"),
                ("policy_refresh_request", "adom"),
                ("policy_objects", "scope_key"),
            ):
                conn.execute(f"DELETE FROM {table} WHERE {col}=?", (adom,))
        conn.commit()


# ── per-package refresh requests (the Refresh button) ────────────────────────


def request_package_refresh(adom: str, pkg: str, min_interval_s: float) -> bool:
    """Queue a collector refresh of one package; False if requested too recently."""
    with _conn(write=True) as conn:
        row = conn.execute(
            "SELECT last_requested_at FROM policy_refresh_request WHERE adom=? AND pkg=?",
            (adom, pkg),
        ).fetchone()
        age = _age(row[0]) if row else None
        if age is not None and age < min_interval_s:
            return False
        conn.execute(
            "INSERT INTO policy_refresh_request (adom, pkg, last_requested_at, pending) "
            "VALUES (?,?,?,1) ON CONFLICT(adom, pkg) DO UPDATE SET "
            "last_requested_at=excluded.last_requested_at, pending=1",
            (adom, pkg, _now()),
        )
        conn.commit()
        return True


def refresh_request_age_seconds(adom: str, pkg: str) -> float | None:
    with _conn() as conn:
        row = conn.execute(
            "SELECT last_requested_at FROM policy_refresh_request WHERE adom=? AND pkg=?",
            (adom, pkg),
        ).fetchone()
    return _age(row[0]) if row else None


def pop_refresh_requests(limit: int) -> list[tuple[str, str]]:
    """Take up to *limit* pending requests (oldest first), marking them handled."""
    with _conn(write=True) as conn:
        rows = conn.execute(
            "SELECT adom, pkg FROM policy_refresh_request WHERE pending=1 "
            "ORDER BY last_requested_at LIMIT ?",
            (limit,),
        ).fetchall()
        for adom, pkg in rows:
            conn.execute(
                "UPDATE policy_refresh_request SET pending=0 WHERE adom=? AND pkg=?",
                (adom, pkg),
            )
        conn.commit()
    return [(r[0], r[1]) for r in rows]


def _set_fetched_at_for_test(table: str, key_values: tuple, fetched_at: str) -> None:
    cols = {
        "policy_pkg": "adom=? AND pkg=?",
        "policy_block": "adom=? AND block=?",
        "policy_objects": "scope_key=? AND kind=?",
    }
    with _conn(write=True) as conn:
        conn.execute(
            f"UPDATE {table} SET fetched_at=? WHERE {cols[table]}",
            (fetched_at, *key_values),
        )
        conn.commit()
