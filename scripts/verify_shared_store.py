"""Prove the shared collector store survives a SIGKILLed writer.

Spawns a writer process that hammers ``collector_store.write_snapshot`` and
a separate reader process that keeps reading it, SIGKILLs the writer
mid-flight, then checks ``PRAGMA integrity_check`` and that the reader only
ever saw a consistent, non-decreasing value. This is the web/collector
sharing pattern, exercised across real processes.

Run on the production RHEL VM as the app user, for example::

    sudo -u 4thealth /opt/4thealth/.venv/bin/python scripts/verify_shared_store.py \\
        --db /opt/4thealth/proof.db --seconds 10

Exit status 0 only if every journal mode tested is safe.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_WRITER = """
from app.collector_store import write_snapshot
i = 0
while True:
    i += 1
    write_snapshot("proof", {"n": i, "pad": "x" * 200000})
"""

_READER = """
import json, sys, time
from app.collector_store import read_snapshot
end = time.time() + float(sys.argv[1])
errors, seen, last, mono = [], 0, 0, True
while time.time() < end:
    try:
        v = read_snapshot("proof")
    except Exception as exc:  # any read failure is a finding
        errors.append(repr(exc))
        time.sleep(0.05)
        continue
    if v is None:
        continue
    seen += 1
    if v["n"] < last:
        mono = False
    last = v["n"]
print(json.dumps({"errors": errors, "seen": seen, "monotonic": mono}))
"""


def _wait_for_first_commit(
    db: Path, timeout: float, proc: subprocess.Popen | None = None
) -> None:
    """Block until the writer has committed at least one snapshot.

    If *proc* exits first, raise with its stderr so a crashed writer is
    diagnosable instead of looking like a hang.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc is not None and proc.poll() is not None:
            err = proc.stderr.read() if proc.stderr else ""
            raise RuntimeError(
                f"writer exited early (rc={proc.returncode}): {err[-800:]}"
            )
        if db.exists():
            try:
                conn = sqlite3.connect(db, timeout=5)
                try:
                    if conn.execute(
                        "SELECT 1 FROM cache_snapshots WHERE cache_key='proof'"
                    ).fetchone():
                        return
                finally:
                    conn.close()
            except sqlite3.Error:
                pass  # table not created yet
        time.sleep(0.05)
    raise TimeoutError("writer never committed a snapshot")


def run_proof(db: Path, seconds: float = 5.0, journal: str = "WAL") -> dict:
    """Run one writer/reader proof against *db* with the given journal mode."""
    db = Path(db)
    # a previous run killed with SIGKILL leaves -wal/-shm/-journal behind; SQLite on
    # Linux fails with "disk I/O error" when it finds them next to a missing database
    for path in (
        db,
        *(db.with_name(db.name + sfx) for sfx in ("-wal", "-shm", "-journal")),
    ):
        path.unlink(missing_ok=True)
    env = dict(
        os.environ,
        COLLECTOR_DB_PATH=str(db),
        COLLECTOR_DB_JOURNAL=journal,
        PYTHONPATH=str(ROOT),
    )
    reader = subprocess.Popen(
        [sys.executable, "-c", _READER, str(seconds + 1.0)],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        text=True,
    )
    writer = subprocess.Popen(
        [sys.executable, "-c", _WRITER],
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        # interpreter start-up can be slow
        _wait_for_first_commit(db, timeout=60.0, proc=writer)
    except Exception:
        writer.kill()
        raise
    time.sleep(seconds)
    writer.send_signal(signal.SIGKILL)
    writer.wait()
    out, _ = reader.communicate(timeout=60)
    reader_result = json.loads(out.strip().splitlines()[-1])

    conn = sqlite3.connect(db)
    try:
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        row = conn.execute(
            "SELECT payload FROM cache_snapshots WHERE cache_key='proof'"
        ).fetchone()
    finally:
        conn.close()
    last_n = json.loads(row[0])["n"] if row else 0
    return {
        "journal": journal,
        "integrity": integrity,
        "reader_errors": reader_result["errors"],
        "monotonic": reader_result["monotonic"],
        "reads": reader_result["seen"],
        "last_n": last_n,
    }


def _safe(r: dict) -> bool:
    return (
        r["integrity"] == "ok"
        and not r["reader_errors"]
        and r["monotonic"]
        and r["last_n"] >= 1
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--db", required=True, help="scratch DB path (deleted first)")
    ap.add_argument("--seconds", type=float, default=5.0)
    args = ap.parse_args(argv)
    ok = True
    for journal in ("WAL", "DELETE"):
        r = run_proof(Path(args.db), args.seconds, journal)
        verdict = "SAFE" if _safe(r) else "UNSAFE"
        ok = ok and _safe(r)
        print(
            f"{journal}: {verdict} integrity={r['integrity']} reads={r['reads']} "
            f"last_n={r['last_n']} reader_errors={len(r['reader_errors'])}"
        )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
