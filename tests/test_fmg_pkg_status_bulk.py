"""Bulk package status and the shared device normalizers (Phase 2, Task 1)."""

import pytest

from app.fmg_client import (
    _CONF_STATUS_MAP,
    _DB_STATUS_MAP,
    FMGClient,
    normalize_sync_status,
    pkg_status_for,
)
from app.synthetic_fmg import SyntheticFMG


def _client(synth):
    c = FMGClient(host="fmg.example", token="t")
    c._post = synth.post
    return c


@pytest.mark.parametrize("conf", [0, 1, 2, 3, "1", "x", None, "missing"])
@pytest.mark.parametrize("db", [0, 1, 2, 9, "2", "x", None, "missing"])
def test_normalize_sync_status_matches_legacy_for_all_values(conf, db):
    dev = {"name": "d"}
    if conf != "missing":
        dev["conf_status"] = conf
    if db != "missing":
        dev["db_status"] = db
    out = normalize_sync_status([dev])[0]

    def legacy(raw, table):
        try:
            raw = int(raw)
        except (TypeError, ValueError):
            raw = 0
        return table.get(raw, "unknown")

    assert out["conf_status"] == legacy(dev.get("conf_status", 0), _CONF_STATUS_MAP)
    assert out["db_status"] == legacy(dev.get("db_status", 0), _DB_STATUS_MAP)


def test_normalize_returns_copies_and_skips_non_dicts():
    src = [{"name": "a", "conf_status": 1, "db_status": 2}, "junk", None]
    out = normalize_sync_status(src)
    assert len(out) == 1
    assert out[0] is not src[0]
    assert src[0]["conf_status"] == 1  # input not mutated
    assert out[0]["conf_status"] == "insync"


def _row(vdom, status, dev="d"):
    return {"dev": dev, "vdom": vdom, "pkg": "p", "status": status}


def test_pkg_status_for_modified_wins():
    rows = [_row("root", "installed"), _row("v2", "modified")]
    assert pkg_status_for(rows, "d", ["root", "v2"]) == "modified"


def test_pkg_status_for_conflict_counts_as_modified():
    assert pkg_status_for([_row("root", "conflict")], "d", ["root"]) == "modified"


def test_pkg_status_for_nomod_when_installed():
    assert pkg_status_for([_row("root", "installed")], "d", ["root"]) == "nomod"


def test_pkg_status_for_empty_when_unassigned_or_missing():
    assert pkg_status_for([_row("root", "unassigned")], "d", ["root"]) == ""
    assert pkg_status_for([], "d", ["root"]) == ""
    assert pkg_status_for([_row("root", "installed", dev="other")], "d", ["root"]) == ""


def test_pkg_status_for_only_considers_listed_vdoms():
    rows = [_row("root", "installed"), _row("hidden", "modified")]
    assert pkg_status_for(rows, "d", ["root"]) == "nomod"


def test_bulk_matches_per_device_legacy_on_synthetic_fleet():
    synth = SyntheticFMG(adoms=2, devices=80, multi_vdom_fraction=0.5, seed=3)
    c = _client(synth)
    seen = set()
    for adom in [
        a["name"] for a in c.get_adoms() if not a["name"].lower().startswith("forti")
    ]:
        rows = c.get_adom_package_status(adom)
        for d in c.get_devices(adom):
            vdoms = [v["name"] for v in d.get("vdom") or []] or ["root"]
            legacy = c.get_device_pkg_status(adom, d["name"], vdoms)
            seen.add(legacy)
            assert pkg_status_for(rows, d["name"], vdoms) == legacy, d["name"]
    assert {"modified", "nomod"} <= seen  # the fleet exercises both outcomes


def test_get_adom_package_status_one_call_per_adom():
    synth = SyntheticFMG(adoms=1, devices=50)
    c = _client(synth)
    adom = next(
        a["name"] for a in c.get_adoms() if not a["name"].lower().startswith("forti")
    )
    synth.calls.clear()
    rows = c.get_adom_package_status(adom)
    assert sum(synth.calls.values()) == 1
    assert rows and {"dev", "vdom", "status"} <= set(rows[0])
