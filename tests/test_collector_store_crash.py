"""A SIGKILLed writer must not corrupt the shared collector store."""

import importlib.util
import sqlite3
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "verify_shared_store.py"


def _load():
    spec = importlib.util.spec_from_file_location("verify_shared_store", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["verify_shared_store"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("journal", ["WAL", "DELETE"])
def test_sigkill_writer_leaves_store_consistent(tmp_path, journal):
    vss = _load()
    db = tmp_path / "proof.db"
    result = vss.run_proof(db, seconds=2.0, journal=journal)

    assert result["reader_errors"] == []
    assert result["monotonic"] is True
    assert result["last_n"] >= 1
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        conn.close()


def test_main_exit_code_zero_when_safe(tmp_path):
    vss = _load()
    assert vss.main(["--db", str(tmp_path / "p.db"), "--seconds", "1"]) == 0


def test_stale_sidecar_files_from_a_previous_run_do_not_break_the_proof(tmp_path):
    """M4: leftover -wal/-shm from a SIGKILLed run must be cleared before the next run."""
    vss = _load()
    db = tmp_path / "proof.db"
    (tmp_path / "proof.db-wal").write_bytes(b"garbage-from-previous-killed-run" * 100)
    (tmp_path / "proof.db-shm").write_bytes(b"\x00" * 32768)
    result = vss.run_proof(db, seconds=1.0, journal="WAL")
    assert result["integrity"] == "ok"
    assert result["reader_errors"] == []
