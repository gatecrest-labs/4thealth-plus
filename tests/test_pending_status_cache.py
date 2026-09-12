import os
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("FMG_PRIMARY_HOST", "127.0.0.1")

from unittest.mock import patch, MagicMock
import pytest


def test_get_cached_devices_returns_none_when_empty():
    import importlib
    import app.pending_status_cache as mod
    importlib.reload(mod)  # reset module state
    assert mod.get_cached_devices("MyADOM") is None


def test_get_cached_devices_returns_snapshot_after_refresh():
    import importlib
    import app.pending_status_cache as mod
    importlib.reload(mod)

    fake_devices = [{"name": "FW1", "ip": "10.0.0.1", "pkg_status": "modified"}]

    with mod._lock:
        mod._cache["MyADOM"] = {
            "devices": fake_devices,
            "last_updated": "2026-07-17T01:00:00",
        }

    result = mod.get_cached_devices("MyADOM")
    assert result == fake_devices


def test_get_cached_devices_returns_copy_not_reference():
    import importlib
    import app.pending_status_cache as mod
    importlib.reload(mod)

    devices = [{"name": "FW1"}]
    with mod._lock:
        mod._cache["ADOM1"] = {"devices": devices, "last_updated": "2026-07-17T01:00:00"}

    result = mod.get_cached_devices("ADOM1")
    result.append({"name": "INJECTED"})
    assert len(mod._cache["ADOM1"]["devices"]) == 1


def test_get_cache_status_initial():
    import importlib
    import app.pending_status_cache as mod
    importlib.reload(mod)
    status = mod.get_cache_status()
    assert status["status"] == "pending"
    assert status["adoms_cached"] == 0


def test_get_all_cached_devices_returns_empty_dict_when_empty():
    import importlib
    import app.pending_status_cache as mod
    importlib.reload(mod)
    assert mod.get_all_cached_devices() == {}


def test_get_all_cached_devices_returns_snapshot_across_adoms():
    import importlib
    import app.pending_status_cache as mod
    importlib.reload(mod)

    with mod._lock:
        mod._cache["ADOM1"] = {
            "devices": [{"name": "FW1", "conf_status": "outofsync"}],
            "last_updated": "2026-07-17T01:00:00",
        }
        mod._cache["ADOM2"] = {
            "devices": [{"name": "FW2", "conf_status": "insync"}],
            "last_updated": "2026-07-17T01:00:00",
        }

    result = mod.get_all_cached_devices()
    assert result == {
        "ADOM1": [{"name": "FW1", "conf_status": "outofsync"}],
        "ADOM2": [{"name": "FW2", "conf_status": "insync"}],
    }


def test_get_all_cached_devices_returns_copies_not_references():
    import importlib
    import app.pending_status_cache as mod
    importlib.reload(mod)

    with mod._lock:
        mod._cache["ADOM1"] = {
            "devices": [{"name": "FW1"}],
            "last_updated": "2026-07-17T01:00:00",
        }

    result = mod.get_all_cached_devices()
    result["ADOM1"].append({"name": "INJECTED"})
    assert len(mod._cache["ADOM1"]["devices"]) == 1


# ── SQLite write-through/read-through for get_cache_status() ───────────────


@pytest.fixture(autouse=True)
def _reset_store():
    # Reset pending_status_cache's in-memory state/cache after every test in
    # this module so SQLite write-through/read-through tests below don't
    # bleed state into (or out of) the importlib.reload-based tests above.
    yield
    import app.pending_status_cache as mod

    with mod._lock:
        mod._cache.clear()
        mod._state.update({"status": "pending", "last_updated": None, "error": None})


def test_get_cache_status_reads_sqlite_when_local_state_never_ran(monkeypatch, tmp_path):
    from app import collector_store, pending_status_cache

    monkeypatch.setattr(collector_store, "_DB_PATH", tmp_path / "test.db")

    collector_store.write_snapshot(
        "pending_status_summary",
        {"status": "ok", "last_updated": "2026-09-12T00:00:00", "adoms_cached": 3, "error": None},
    )

    assert pending_status_cache._state["status"] == "pending"

    status = pending_status_cache.get_cache_status()

    assert status == {
        "status": "ok",
        "last_updated": "2026-09-12T00:00:00",
        "adoms_cached": 3,
        "error": None,
    }


def test_get_cache_status_prefers_local_state_over_sqlite(monkeypatch, tmp_path):
    from app import collector_store, pending_status_cache

    monkeypatch.setattr(collector_store, "_DB_PATH", tmp_path / "test.db")

    collector_store.write_snapshot(
        "pending_status_summary",
        {"status": "ok", "last_updated": "2026-01-01T00:00:00", "adoms_cached": 99, "error": None},
    )

    with pending_status_cache._lock:
        pending_status_cache._state["status"] = "ok"
        pending_status_cache._state["last_updated"] = "2026-09-12T01:00:00"
        pending_status_cache._cache["ADOM1"] = {
            "devices": [],
            "last_updated": "2026-09-12T01:00:00",
        }

    status = pending_status_cache.get_cache_status()

    assert status == {
        "status": "ok",
        "last_updated": "2026-09-12T01:00:00",
        "adoms_cached": 1,
        "error": None,
    }


def test_get_cache_status_falls_back_to_local_pending_when_no_snapshot(monkeypatch, tmp_path):
    from app import collector_store, pending_status_cache

    monkeypatch.setattr(collector_store, "_DB_PATH", tmp_path / "test.db")

    status = pending_status_cache.get_cache_status()

    assert status == {
        "status": "pending",
        "last_updated": None,
        "adoms_cached": 0,
        "error": None,
    }


def test_run_refresh_writes_snapshot_on_success(monkeypatch, tmp_path, app_ctx):
    from app import collector_store, pending_status_cache

    monkeypatch.setattr(collector_store, "_DB_PATH", tmp_path / "test.db")

    fake_client = MagicMock()
    fake_client.get_adoms.return_value = [{"name": "ADOM1"}]
    fake_client.get_devices_with_sync_status.return_value = []
    fake_client.__enter__.return_value = fake_client
    fake_client.__exit__.return_value = False

    monkeypatch.setattr(
        "app.fmg_helpers.make_client", lambda: fake_client
    )

    pending_status_cache._run_refresh(app_ctx)

    snapshot = collector_store.read_snapshot("pending_status_summary")
    assert snapshot is not None
    assert snapshot["status"] == "ok"
    assert snapshot["adoms_cached"] == 1
    assert snapshot["error"] is None


def test_run_refresh_still_succeeds_when_sqlite_write_fails(monkeypatch, tmp_path, app_ctx):
    """A SQLite mirroring failure on the success path must never downgrade
    an already-successful in-memory refresh to 'error' — write_snapshot is
    best-effort mirroring on top of the in-memory state, not a condition
    of refresh success."""
    from app import collector_store, pending_status_cache

    monkeypatch.setattr(collector_store, "_DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(
        collector_store,
        "write_snapshot",
        MagicMock(side_effect=RuntimeError("disk full")),
    )

    fake_client = MagicMock()
    fake_client.get_adoms.return_value = [{"name": "ADOM1"}]
    fake_client.get_devices_with_sync_status.return_value = []
    fake_client.__enter__.return_value = fake_client
    fake_client.__exit__.return_value = False

    monkeypatch.setattr(
        "app.fmg_helpers.make_client", lambda: fake_client
    )

    pending_status_cache._run_refresh(app_ctx)

    assert pending_status_cache._state["status"] == "ok"
    assert pending_status_cache._state["error"] is None


def test_run_refresh_error_path_still_isolates_sqlite_write_failure(monkeypatch, tmp_path, app_ctx):
    """A SQLite mirroring failure on the error path must never mask or
    raise over the original in-memory error state."""
    from app import collector_store, pending_status_cache

    monkeypatch.setattr(collector_store, "_DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(
        collector_store,
        "write_snapshot",
        MagicMock(side_effect=RuntimeError("disk full")),
    )
    monkeypatch.setattr(
        "app.fmg_helpers.make_client",
        MagicMock(side_effect=RuntimeError("boom")),
    )

    # Should not raise, despite both the refresh itself and the mirroring
    # write failing.
    pending_status_cache._run_refresh(app_ctx)

    assert pending_status_cache._state["status"] == "error"
    assert "boom" in pending_status_cache._state["error"]


def test_run_refresh_error_path_writes_snapshot(monkeypatch, tmp_path, app_ctx):
    from app import collector_store, pending_status_cache

    monkeypatch.setattr(collector_store, "_DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(
        "app.fmg_helpers.make_client",
        MagicMock(side_effect=RuntimeError("boom")),
    )

    pending_status_cache._run_refresh(app_ctx)

    snapshot = collector_store.read_snapshot("pending_status_summary")
    assert snapshot is not None
    assert snapshot["status"] == "error"
    assert "boom" in snapshot["error"]
