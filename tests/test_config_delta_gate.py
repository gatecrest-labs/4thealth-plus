"""Config-Delta gate decisions (Phase 3, Task 1)."""

from datetime import UTC, datetime, timedelta

import pytest

from app import config_delta_gate as gate
from app import inventory_store
from app.config import Config


def _now():
    return datetime.now(UTC).isoformat()


def _old(seconds):
    return (datetime.now(UTC) - timedelta(seconds=seconds)).isoformat()


@pytest.fixture(autouse=True)
def _on(monkeypatch):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", True)
    monkeypatch.setattr(Config, "CONFIG_DELTA_GATING", True)
    monkeypatch.setattr(Config, "INVENTORY_REFRESH_SECS", 300)
    monkeypatch.setattr(Config, "INVENTORY_MAX_AGE_SECS", 900)
    monkeypatch.setattr(Config, "CONFIG_DELTA_FULL_SWEEP_HOURS", 24)


MAX_AGE = 600.0


@pytest.mark.parametrize(
    "conf,db,pkg",
    [
        ("outofsync", "nomod", "nomod"),
        ("insync", "modified", "nomod"),
        ("insync", "nomod", "modified"),
    ],
)
def test_pending_in_any_signal_previews(conf, db, pkg):
    assert gate.decide_device(conf, db, pkg, 10.0, MAX_AGE) == (True, "pending")


def test_in_sync_everything_is_skipped():
    assert gate.decide_device("insync", "nomod", "nomod", 10.0, MAX_AGE) == (
        False,
        "in_sync",
    )


@pytest.mark.parametrize("bad", ["unknown", "", None])
@pytest.mark.parametrize("field", [0, 1, 2])
def test_unknown_or_empty_or_missing_signals_preview(field, bad):
    vals = ["insync", "nomod", "nomod"]
    vals[field] = bad
    preview, reason = gate.decide_device(*vals, 10.0, MAX_AGE)
    assert preview is True and reason == "unknown"


def test_stale_status_previews():
    assert gate.decide_device("insync", "nomod", "nomod", MAX_AGE + 1, MAX_AGE) == (
        True,
        "stale",
    )


def test_age_none_previews():
    assert gate.decide_device("insync", "nomod", "nomod", None, MAX_AGE) == (
        True,
        "stale",
    )


def test_gating_disabled_when_inventory_cache_off(monkeypatch):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)
    assert gate.gating_enabled() is False


def test_gating_disabled_by_env_off(monkeypatch):
    monkeypatch.setattr(Config, "CONFIG_DELTA_GATING", False)
    assert gate.gating_enabled() is False


def test_config_defaults():
    from app.config import _env_bool

    assert _env_bool("SURELY_UNSET_FLAG_XYZ", True) is True
    assert _env_bool("SURELY_UNSET_FLAG_XYZ", False) is False


def _populate(adom="A", collected=None):
    devs = [
        {
            "name": "ok",
            "ip": "1",
            "conf_status": 1,
            "db_status": 1,
            "vdom": [{"name": "root"}],
        },
        {
            "name": "conf",
            "ip": "2",
            "conf_status": 2,
            "db_status": 1,
            "vdom": [{"name": "root"}],
        },
        {
            "name": "pkg",
            "ip": "3",
            "conf_status": 1,
            "db_status": 1,
            "vdom": [{"name": "root"}],
        },
        {
            "name": "unk",
            "ip": "4",
            "conf_status": 0,
            "db_status": 1,
            "vdom": [{"name": "root"}],
        },
        {
            "name": "nopkg",
            "ip": "5",
            "conf_status": 1,
            "db_status": 1,
            "vdom": [{"name": "root"}],
        },
    ]
    pkg = [
        {"dev": "ok", "vdom": "root", "pkg": "p", "status": "installed"},
        {"dev": "conf", "vdom": "root", "pkg": "p", "status": "installed"},
        {"dev": "pkg", "vdom": "root", "pkg": "p", "status": "modified"},
        {"dev": "unk", "vdom": "root", "pkg": "p", "status": "installed"},
    ]
    inventory_store.replace_adom(adom, devs, pkg, collected or _now())
    return [{"name": d["name"], "ip": d["ip"]} for d in devs]


def test_select_devices_splits_and_records_status_age():
    devices = _populate()
    inventory_store.mark_full_sweep("A")  # not a full-sweep run
    res = gate.select_devices(object(), "A", devices)
    assert {d["name"] for d in res.gated} == {"ok"}
    assert {d["name"] for d in res.preview} == {"conf", "pkg", "unk", "nopkg"}
    assert res.full_sweep is False
    assert res.status_age_s is not None and res.status_age_s < 5


def test_device_missing_from_inventory_is_previewed():
    devices = _populate() + [{"name": "ghost", "ip": "9"}]
    inventory_store.mark_full_sweep("A")
    res = gate.select_devices(object(), "A", devices)
    assert "ghost" in {d["name"] for d in res.preview}


def test_stale_inventory_previews_everything():
    devices = _populate(collected=_old(5000))
    inventory_store.mark_full_sweep("A")
    res = gate.select_devices(object(), "A", devices)
    assert res.gated == [] and len(res.preview) == len(devices)


def test_full_sweep_due_previews_everything_until_marked_done():
    devices = _populate()
    res = gate.select_devices(object(), "A", devices)  # never swept
    assert res.full_sweep is True and res.gated == []
    assert (
        gate.select_devices(object(), "A", devices).full_sweep is True
    )  # not marked yet
    gate.mark_full_sweep_done("A")
    again = gate.select_devices(object(), "A", devices)
    assert again.full_sweep is False and {d["name"] for d in again.gated} == {"ok"}


def test_full_sweep_due_again_after_interval(monkeypatch):
    devices = _populate()
    gate.mark_full_sweep_done("A")
    monkeypatch.setattr(Config, "CONFIG_DELTA_FULL_SWEEP_HOURS", 0)  # always due
    assert gate.select_devices(object(), "A", devices).full_sweep is True


def test_gating_off_returns_everything_as_preview(monkeypatch):
    devices = _populate()
    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)
    res = gate.select_devices(object(), "A", devices)
    assert res.gated == [] and len(res.preview) == len(devices)


def test_store_unreadable_previews_everything(monkeypatch):
    devices = _populate()

    def broken(*a, **k):
        raise inventory_store.InventoryStoreError("io")

    monkeypatch.setattr(inventory_store, "read_meta", broken)
    res = gate.select_devices(object(), "A", devices)
    assert res.gated == [] and len(res.preview) == len(devices)
