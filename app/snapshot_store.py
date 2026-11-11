"""Device configuration snapshots in the shared collector database (F4).

Written only by the collector (``app.snapshot_cache``); web workers read them
through ``app.audit_data``. One row per (ADOM, device, data key), the key being a
``device_data.DATA_KEYS`` name, with a zlib-JSON blob and its own ``collected_at``.
A failed capture sets ``status='unreachable'`` and keeps the previous blob, so
"we could not ask" never overwrites a real answer; a key that has a blob has
actually been returned by FortiManager (an empty value included). Per-device
state tracks failures and an exponential retry backoff (15 min doubling to 24 h)
so unreachable devices are not retried every batch.
"""

from __future__ import annotations

import hashlib
import json
import zlib
from datetime import UTC, datetime, timedelta

from app.config import Config
from app.inventory_store import InventoryStoreError, _age, _Conn

SnapshotStoreError = InventoryStoreError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS device_snapshot (
    adom TEXT NOT NULL, device TEXT NOT NULL, data_key TEXT NOT NULL,
    collected_at TEXT, status TEXT NOT NULL, error TEXT, fingerprint TEXT, blob BLOB,
    PRIMARY KEY (adom, device, data_key));
CREATE TABLE IF NOT EXISTS device_snapshot_state (
    adom TEXT NOT NULL, device TEXT NOT NULL, last_attempt_at TEXT,
    fail_count INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT, last_ok_at TEXT,
    PRIMARY KEY (adom, device));
"""
_SCHEMA_ID = "snapshot_store"
_BACKOFF_BASE_S = 15 * 60
_BACKOFF_MAX_S = 24 * 3600


def _conn(write: bool = False) -> _Conn:
    return _Conn(write=write, schema=_SCHEMA, schema_id=_SCHEMA_ID)


def _now() -> datetime:
    return datetime.now(UTC)


def _pack(obj) -> bytes:
    return zlib.compress(
        json.dumps(obj, separators=(",", ":"), sort_keys=True).encode(), 6
    )


def backoff_seconds(fail_count: int) -> int:
    """Retry delay after *fail_count* consecutive failures: 15 min doubling, capped at 24 h."""
    return int(min(_BACKOFF_MAX_S, _BACKOFF_BASE_S * (2 ** max(0, fail_count - 1))))


def max_age_seconds() -> float:
    """Age beyond which a reader goes live (default: the window plus one day)."""
    configured = Config.AUDIT_SNAPSHOT_MAX_AGE_HOURS
    if configured and configured > 0:
        return float(configured) * 3600.0
    return float(Config.AUDIT_SNAPSHOT_WINDOW_DAYS * 24 + 24) * 3600.0


def put_keys(adom: str, device: str, values: dict[str, object]) -> None:
    """Store freshly captured keys for a device in one transaction."""
    now = _now().isoformat()
    with _conn(write=True) as conn:
        conn.execute("BEGIN IMMEDIATE")
        for key, value in values.items():
            blob = _pack(value)
            conn.execute(
                "INSERT INTO device_snapshot (adom, device, data_key, collected_at, status, "
                "error, fingerprint, blob) VALUES (?,?,?,?,'ok',NULL,?,?) "
                "ON CONFLICT(adom, device, data_key) DO UPDATE SET "
                "collected_at=excluded.collected_at, status='ok', error=NULL, "
                "fingerprint=excluded.fingerprint, blob=excluded.blob",
                (adom, device, key, now, hashlib.sha256(blob).hexdigest(), blob),
            )
        conn.commit()


def mark_failed(adom: str, device: str, keys: list[str], error: str) -> None:
    """Record that *keys* could not be captured: keep their blobs, back the device off."""
    now = _now()
    with _conn(write=True) as conn:
        conn.execute("BEGIN IMMEDIATE")
        for key in keys:
            conn.execute(
                "INSERT INTO device_snapshot (adom, device, data_key, status, error) "
                "VALUES (?,?,?,'unreachable',?) ON CONFLICT(adom, device, data_key) "
                "DO UPDATE SET status='unreachable', error=excluded.error",
                (adom, device, key, error[:500]),
            )
        row = conn.execute(
            "SELECT fail_count FROM device_snapshot_state WHERE adom=? AND device=?",
            (adom, device),
        ).fetchone()
        fails = (row[0] if row else 0) + 1
        conn.execute(
            "INSERT INTO device_snapshot_state (adom, device, last_attempt_at, fail_count, "
            "next_attempt_at) VALUES (?,?,?,?,?) ON CONFLICT(adom, device) DO UPDATE SET "
            "last_attempt_at=excluded.last_attempt_at, fail_count=excluded.fail_count, "
            "next_attempt_at=excluded.next_attempt_at",
            (
                adom,
                device,
                now.isoformat(),
                fails,
                (now + timedelta(seconds=backoff_seconds(fails))).isoformat(),
            ),
        )
        conn.commit()


def mark_ok(adom: str, device: str) -> None:
    """A complete capture: clear the failure count and backoff."""
    now = _now().isoformat()
    with _conn(write=True) as conn:
        conn.execute(
            "INSERT INTO device_snapshot_state (adom, device, last_attempt_at, fail_count, "
            "next_attempt_at, last_ok_at) VALUES (?,?,?,0,NULL,?) "
            "ON CONFLICT(adom, device) DO UPDATE SET last_attempt_at=excluded.last_attempt_at, "
            "fail_count=0, next_attempt_at=NULL, last_ok_at=excluded.last_ok_at",
            (adom, device, now, now),
        )
        conn.commit()


def get_keys(adom: str, device: str, keys: set[str]) -> dict[str, dict]:
    """``{key: {value, collected_at, age_seconds, status}}`` for keys that have a capture."""
    if not keys:
        return {}
    marks = ",".join("?" for _ in keys)
    with _conn() as conn:
        rows = conn.execute(
            "SELECT data_key, collected_at, status, blob FROM device_snapshot "
            f"WHERE adom=? AND device=? AND blob IS NOT NULL AND data_key IN ({marks})",
            [adom, device, *sorted(keys)],
        ).fetchall()
    return {
        r[0]: {
            "value": json.loads(zlib.decompress(r[3])),
            "collected_at": r[1],
            "age_seconds": _age(r[1]),
            "status": r[2],
        }
        for r in rows
    }


def device_meta_rows(adom: str) -> list[dict]:
    """Per-device capture state without loading any blob."""
    with _conn() as conn:
        snap = {
            r[0]: r
            for r in conn.execute(
                "SELECT device, MIN(CASE WHEN blob IS NOT NULL THEN collected_at END), "
                "SUM(CASE WHEN blob IS NOT NULL THEN 1 ELSE 0 END), "
                "MAX(CASE WHEN status='unreachable' THEN 1 ELSE 0 END) "
                "FROM device_snapshot WHERE adom=? GROUP BY device",
                (adom,),
            )
        }
        state = {
            r[0]: r
            for r in conn.execute(
                "SELECT device, last_attempt_at, fail_count, next_attempt_at, last_ok_at "
                "FROM device_snapshot_state WHERE adom=?",
                (adom,),
            )
        }
    out = []
    for device in sorted(set(snap) | set(state)):
        s, st = snap.get(device), state.get(device)
        out.append(
            {
                "device": device,
                "oldest_key_at": s[1] if s else None,
                "keys": (s[2] or 0) if s else 0,
                "has_unreachable": bool(s[3]) if s else False,
                "last_attempt_at": st[1] if st else None,
                "fail_count": st[2] if st else 0,
                "next_attempt_at": st[3] if st else None,
                "last_ok_at": st[4] if st else None,
            }
        )
    return out


def delete_missing_devices(adom: str, keep: set[str]) -> int:
    """Drop devices of *adom* that left the inventory. Returns how many."""
    with _conn(write=True) as conn:
        have = {
            r[0]
            for r in conn.execute(
                "SELECT DISTINCT device FROM device_snapshot WHERE adom=?", (adom,)
            )
        }
        have |= {
            r[0]
            for r in conn.execute(
                "SELECT device FROM device_snapshot_state WHERE adom=?", (adom,)
            )
        }
        gone = have - set(keep)
        for device in gone:
            conn.execute(
                "DELETE FROM device_snapshot WHERE adom=? AND device=?", (adom, device)
            )
            conn.execute(
                "DELETE FROM device_snapshot_state WHERE adom=? AND device=?",
                (adom, device),
            )
        conn.commit()
    return len(gone)


def delete_missing_adoms(keep: set[str]) -> None:
    with _conn(write=True) as conn:
        known = {
            r[0] for r in conn.execute("SELECT DISTINCT adom FROM device_snapshot")
        }
        known |= {
            r[0]
            for r in conn.execute("SELECT DISTINCT adom FROM device_snapshot_state")
        }
        for adom in known - set(keep):
            conn.execute("DELETE FROM device_snapshot WHERE adom=?", (adom,))
            conn.execute("DELETE FROM device_snapshot_state WHERE adom=?", (adom,))
        conn.commit()


def _set_collected_at_for_test(
    adom: str, device: str, key: str, collected_at: str
) -> None:
    with _conn(write=True) as conn:
        conn.execute(
            "UPDATE device_snapshot SET collected_at=? WHERE adom=? AND device=? AND data_key=?",
            (collected_at, adom, device, key),
        )
        conn.commit()


def _set_last_ok_for_test(adom: str, device: str, last_ok_at: str) -> None:
    with _conn(write=True) as conn:
        conn.execute(
            "UPDATE device_snapshot_state SET last_ok_at=? WHERE adom=? AND device=?",
            (last_ok_at, adom, device),
        )
        conn.commit()
