"""Inventory tables in the shared collector store (F2).

The collector (the only writer) replaces one ADOM's devices and package status
in a single transaction, so readers always see one complete generation. Reads
are indexed per-ADOM queries. "Never collected" returns ``None``; a store that
cannot be read raises ``InventoryStoreError`` so callers can fail open to a
live FMG call instead of mistaking a broken store for an empty fleet.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime

from app import collector_store

_SCHEMA = """
CREATE TABLE IF NOT EXISTS inventory_adom (
    name TEXT PRIMARY KEY, ord INTEGER NOT NULL, json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS inventory_device (
    adom TEXT NOT NULL, name TEXT NOT NULL, json TEXT NOT NULL,
    PRIMARY KEY (adom, name));
CREATE TABLE IF NOT EXISTS inventory_pkg (
    adom TEXT NOT NULL, dev TEXT NOT NULL, vdom TEXT NOT NULL,
    pkg TEXT, status TEXT, json TEXT NOT NULL,
    PRIMARY KEY (adom, dev, vdom));
CREATE TABLE IF NOT EXISTS inventory_meta (
    adom TEXT PRIMARY KEY, collected_at TEXT, device_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL, error TEXT);
CREATE TABLE IF NOT EXISTS inventory_state (key TEXT PRIMARY KEY, value TEXT);
"""

_ADOM_LIST_AT = "adom_list_collected_at"
_REFRESH_LAST = "refresh_last_requested"
_REFRESH_PENDING = "refresh_pending"


class InventoryStoreError(Exception):
    """The inventory store could not be read or written."""


def _now() -> datetime:
    return datetime.now(UTC)


def _age(collected_at: str | None) -> float | None:
    if not collected_at:
        return None
    try:
        return max(0.0, (_now() - datetime.fromisoformat(collected_at)).total_seconds())
    except (TypeError, ValueError):
        return None


class _Conn:
    """Per-operation connection under the store's process lock; errors normalised."""

    def __enter__(self) -> sqlite3.Connection:
        collector_store._lock.acquire()
        try:
            self.conn = collector_store._connect()
            collector_store._retry_locked(lambda: self.conn.executescript(_SCHEMA))
        except sqlite3.Error as exc:
            collector_store._lock.release()
            raise InventoryStoreError(str(exc)) from exc
        except BaseException:
            collector_store._lock.release()
            raise
        return self.conn

    def __exit__(self, exc_type, exc, tb) -> bool:
        try:
            try:
                if exc_type is not None and self.conn.in_transaction:
                    self.conn.rollback()
            finally:
                self.conn.close()
        finally:
            collector_store._lock.release()
        if exc_type is not None and issubclass(exc_type, sqlite3.Error):
            raise InventoryStoreError(str(exc)) from exc
        return False


def replace_adom(
    adom: str,
    devices: list[dict],
    pkg_rows: list[dict] | None,
    collected_at: str,
) -> None:
    """Replace one ADOM's devices (and package rows unless ``pkg_rows`` is None) atomically."""
    named = [d for d in devices if isinstance(d, dict) and d.get("name")]
    with _Conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM inventory_device WHERE adom=?", (adom,))
        conn.executemany(
            "INSERT OR REPLACE INTO inventory_device (adom, name, json) VALUES (?,?,?)",
            ((adom, d["name"], json.dumps(d)) for d in named),
        )
        if pkg_rows is not None:
            conn.execute("DELETE FROM inventory_pkg WHERE adom=?", (adom,))
            conn.executemany(
                "INSERT OR REPLACE INTO inventory_pkg "
                "(adom, dev, vdom, pkg, status, json) VALUES (?,?,?,?,?,?)",
                (
                    (
                        adom,
                        r.get("dev", ""),
                        r.get("vdom", ""),
                        r.get("pkg"),
                        r.get("status"),
                        json.dumps(r),
                    )
                    for r in pkg_rows
                    if isinstance(r, dict)
                ),
            )
        conn.execute(
            "INSERT INTO inventory_meta (adom, collected_at, device_count, status, error) "
            "VALUES (?,?,?,'ok',NULL) ON CONFLICT(adom) DO UPDATE SET "
            "collected_at=excluded.collected_at, device_count=excluded.device_count, "
            "status='ok', error=NULL",
            (adom, collected_at, len(named)),
        )
        conn.commit()


def mark_adom_error(adom: str, error: str) -> None:
    """Keep the ADOM's last good rows but flag the failed refresh."""
    with _Conn() as conn:
        conn.execute(
            "INSERT INTO inventory_meta (adom, collected_at, device_count, status, error) "
            "VALUES (?,NULL,0,'error',?) ON CONFLICT(adom) DO UPDATE SET "
            "status='error', error=excluded.error",
            (adom, error[:500]),
        )
        conn.commit()


def write_adom_list(adoms: list[dict]) -> None:
    with _Conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM inventory_adom")
        conn.executemany(
            "INSERT INTO inventory_adom (name, ord, json) VALUES (?,?,?)",
            (
                (a["name"], i, json.dumps(a))
                for i, a in enumerate(adoms)
                if isinstance(a, dict) and a.get("name")
            ),
        )
        conn.execute(
            "INSERT INTO inventory_state (key, value) VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (_ADOM_LIST_AT, _now().isoformat()),
        )
        conn.commit()


def delete_missing_adoms(keep: set[str]) -> None:
    """Drop every row of ADOMs no longer present in FortiManager."""
    with _Conn() as conn:
        known = {
            r[0]
            for t in ("inventory_device", "inventory_pkg", "inventory_meta")
            for r in conn.execute(f"SELECT DISTINCT adom FROM {t}")
        }
        gone = known - set(keep)
        if not gone:
            return
        conn.execute("BEGIN IMMEDIATE")
        for adom in gone:
            for t in ("inventory_device", "inventory_pkg", "inventory_meta"):
                conn.execute(f"DELETE FROM {t} WHERE adom=?", (adom,))
        conn.commit()


def read_adom_list() -> list[dict] | None:
    with _Conn() as conn:
        at = conn.execute(
            "SELECT value FROM inventory_state WHERE key=?", (_ADOM_LIST_AT,)
        ).fetchone()
        if at is None:
            return None
        rows = conn.execute("SELECT json FROM inventory_adom ORDER BY ord").fetchall()
    return [json.loads(r[0]) for r in rows]


def adom_list_age_seconds() -> float | None:
    with _Conn() as conn:
        at = conn.execute(
            "SELECT value FROM inventory_state WHERE key=?", (_ADOM_LIST_AT,)
        ).fetchone()
    return _age(at[0]) if at else None


def read_devices(adom: str) -> list[dict] | None:
    """The ADOM's devices, or ``None`` if it has never been collected."""
    with _Conn() as conn:
        meta = conn.execute(
            "SELECT collected_at FROM inventory_meta WHERE adom=?", (adom,)
        ).fetchone()
        if meta is None or meta[0] is None:
            return None
        rows = conn.execute(
            "SELECT json FROM inventory_device WHERE adom=? ORDER BY rowid", (adom,)
        ).fetchall()
    return [json.loads(r[0]) for r in rows]


def read_pkg_status(adom: str) -> list[dict]:
    with _Conn() as conn:
        rows = conn.execute(
            "SELECT json FROM inventory_pkg WHERE adom=? ORDER BY rowid", (adom,)
        ).fetchall()
    return [json.loads(r[0]) for r in rows]


def _meta_row(r) -> dict:
    return {
        "adom": r["adom"],
        "collected_at": r["collected_at"],
        "age_seconds": _age(r["collected_at"]),
        "status": r["status"],
        "error": r["error"],
        "device_count": r["device_count"],
    }


def read_meta(adom: str | None = None) -> dict | list[dict] | None:
    """One ADOM's meta (``None`` if unknown) or, with no argument, all of them."""
    with _Conn() as conn:
        if adom is not None:
            r = conn.execute(
                "SELECT * FROM inventory_meta WHERE adom=?", (adom,)
            ).fetchone()
            return _meta_row(r) if r else None
        return [
            _meta_row(r)
            for r in conn.execute("SELECT * FROM inventory_meta ORDER BY adom")
        ]


def request_refresh(min_interval_s: float) -> bool:
    """Ask the collector for an immediate refresh; False if asked too recently."""
    with _Conn() as conn:
        last = conn.execute(
            "SELECT value FROM inventory_state WHERE key=?", (_REFRESH_LAST,)
        ).fetchone()
        age = _age(last[0]) if last else None
        if age is not None and age < min_interval_s:
            return False
        now = _now().isoformat()
        for key, value in ((_REFRESH_LAST, now), (_REFRESH_PENDING, "1")):
            conn.execute(
                "INSERT INTO inventory_state (key, value) VALUES (?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
        conn.commit()
        return True


def pop_refresh_request() -> bool:
    """True (once) if a refresh was requested since the last pop."""
    with _Conn() as conn:
        cur = conn.execute(
            "DELETE FROM inventory_state WHERE key=?", (_REFRESH_PENDING,)
        )
        conn.commit()
        return cur.rowcount > 0
