"""Server-side jobs for long interactive actions (F6), in the shared collector database.

Web enqueues a ``queued`` row and reads/cancels; the collector (``app.job_runner``)
claims, runs and finishes jobs. A job keeps its owner and the ADOM it was created
for, its request (parameters only, never credentials), progress (``done``/``total``
/``message``) and a zlib-JSON result capped at ``JOB_MAX_RESULT_BYTES``. Listing
never loads request or result blobs. A job that was ``running`` when the collector
died is failed at the next start (``recover_orphans``); finished jobs are pruned
after ``JOB_RETENTION_DAYS``.
"""

from __future__ import annotations

import json
import uuid
import zlib
from datetime import UTC, datetime, timedelta

from app.config import Config
from app.inventory_store import InventoryStoreError, _Conn

JobStoreError = InventoryStoreError


class JobLimitError(Exception):
    """The user already has the maximum number of queued jobs."""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS job (
    id TEXT PRIMARY KEY, kind TEXT NOT NULL, owner TEXT NOT NULL, adom TEXT NOT NULL,
    request_blob BLOB, status TEXT NOT NULL, done INTEGER NOT NULL DEFAULT 0,
    total INTEGER NOT NULL DEFAULT 0, message TEXT, created_at TEXT NOT NULL,
    started_at TEXT, finished_at TEXT, result_blob BLOB, error TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS job_status_created ON job (status, created_at);
CREATE INDEX IF NOT EXISTS job_owner ON job (owner, created_at);
"""
_SCHEMA_ID = "job_store"
_FINISHED = ("done", "failed", "cancelled")


def _conn(write: bool = False) -> _Conn:
    return _Conn(write=write, schema=_SCHEMA, schema_id=_SCHEMA_ID)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _pack(obj) -> bytes:
    return zlib.compress(json.dumps(obj, separators=(",", ":")).encode(), 6)


def _unpack(blob):
    return None if blob is None else json.loads(zlib.decompress(blob))


_META = (
    "id, kind, owner, adom, status, done, total, message, created_at, started_at, "
    "finished_at, error, cancel_requested"
)


def _meta(row) -> dict:
    keys = [c.strip() for c in _META.split(",")]
    out = dict(zip(keys, row, strict=True))
    out["cancel_requested"] = bool(out["cancel_requested"])
    return out


def enqueue(kind: str, owner: str, adom: str, request: dict) -> str:
    """Queue a job; raises ``JobLimitError`` past the per-user queued cap."""
    jid = uuid.uuid4().hex
    with _conn(write=True) as conn:
        queued = conn.execute(
            "SELECT COUNT(*) FROM job WHERE owner=? AND status='queued'", (owner,)
        ).fetchone()[0]
        if queued >= Config.JOB_MAX_QUEUED_PER_USER:
            raise JobLimitError(f"{queued} jobs already queued")
        conn.execute(
            "INSERT INTO job (id, kind, owner, adom, request_blob, status, created_at) "
            "VALUES (?,?,?,?,?, 'queued', ?)",
            (jid, kind, owner, adom, _pack(request), _now()),
        )
        conn.commit()
    return jid


def claim_next() -> dict | None:
    """Atomically move the oldest queued job to running and return it (with its request)."""
    with _conn(write=True) as conn:
        row = conn.execute(
            "SELECT id FROM job WHERE status='queued' ORDER BY created_at, rowid LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        cur = conn.execute(
            "UPDATE job SET status='running', started_at=? WHERE id=? AND status='queued'",
            (_now(), row[0]),
        )
        conn.commit()
        if cur.rowcount != 1:
            return None
    return get(row[0])


def running_count() -> int:
    with _conn() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM job WHERE status='running'"
        ).fetchone()[0]


def progress(jid: str, done: int, total: int, message: str = "") -> None:
    with _conn(write=True) as conn:
        conn.execute(
            "UPDATE job SET done=?, total=?, message=? WHERE id=? AND status='running'",
            (int(done), int(total), message[:200], jid),
        )
        conn.commit()


def finish(jid: str, result, cancelled: bool = False) -> None:
    """Store the result. A job that is no longer running (cancelled while queued,
    already finished) is left untouched."""
    blob = _pack(result)
    status, error = ("cancelled" if cancelled else "done"), None
    if len(blob) > Config.JOB_MAX_RESULT_BYTES:
        blob, status = None, "failed"
        error = (
            f"result too large (limit {Config.JOB_MAX_RESULT_BYTES // (1024 * 1024)} MB); "
            "narrow the selection"
        )
    with _conn(write=True) as conn:
        conn.execute(
            "UPDATE job SET status=?, result_blob=?, error=?, finished_at=? "
            "WHERE id=? AND status='running'",
            (status, blob, error, _now(), jid),
        )
        conn.commit()


def fail(jid: str, error: str) -> None:
    with _conn(write=True) as conn:
        conn.execute(
            "UPDATE job SET status='failed', error=?, finished_at=? "
            "WHERE id=? AND status IN ('queued','running')",
            (error[:300], _now(), jid),
        )
        conn.commit()


def request_cancel(jid: str) -> str:
    """``cancelled`` (was queued), ``requested`` (running, cooperative), ``finished`` or ``missing``."""
    with _conn(write=True) as conn:
        row = conn.execute("SELECT status FROM job WHERE id=?", (jid,)).fetchone()
        if row is None:
            return "missing"
        if row[0] == "queued":
            conn.execute(
                "UPDATE job SET status='cancelled', finished_at=? WHERE id=? AND status='queued'",
                (_now(), jid),
            )
            conn.commit()
            return "cancelled"
        if row[0] == "running":
            conn.execute("UPDATE job SET cancel_requested=1 WHERE id=?", (jid,))
            conn.commit()
            return "requested"
        return "finished"


def cancel_requested(jid: str) -> bool:
    with _conn() as conn:
        row = conn.execute(
            "SELECT cancel_requested FROM job WHERE id=?", (jid,)
        ).fetchone()
    return bool(row and row[0])


def get(jid: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute(
            f"SELECT {_META}, request_blob, result_blob FROM job WHERE id=?", (jid,)
        ).fetchone()
    if row is None:
        return None
    out = _meta(row[:-2])
    out["request"] = _unpack(row[-2])
    out["result"] = _unpack(row[-1])
    return out


def list_for(owner: str | None, limit: int = 50) -> list[dict]:
    """Job metadata, newest first; ``owner=None`` lists everyone's (admin). No blobs."""
    sql, args = f"SELECT {_META} FROM job", []
    if owner is not None:
        sql += " WHERE owner=?"
        args.append(owner)
    sql += " ORDER BY created_at DESC, rowid DESC LIMIT ?"
    args.append(int(limit))
    with _conn() as conn:
        return [_meta(r) for r in conn.execute(sql, args)]


def recover_orphans() -> int:
    """Fail every job left ``running`` by a previous collector process."""
    with _conn(write=True) as conn:
        cur = conn.execute(
            "UPDATE job SET status='failed', error='collector restarted while the job was running', "
            "finished_at=? WHERE status='running'",
            (_now(),),
        )
        conn.commit()
        return cur.rowcount


def prune() -> int:
    cutoff = (datetime.now(UTC) - timedelta(days=Config.JOB_RETENTION_DAYS)).isoformat()
    with _conn(write=True) as conn:
        cur = conn.execute(
            "DELETE FROM job WHERE status IN ('done','failed','cancelled') AND finished_at < ?",
            (cutoff,),
        )
        conn.commit()
        return cur.rowcount


def _set_finished_for_test(jid: str, when: str) -> None:
    with _conn(write=True) as conn:
        conn.execute("UPDATE job SET finished_at=? WHERE id=?", (when, jid))
        conn.commit()
