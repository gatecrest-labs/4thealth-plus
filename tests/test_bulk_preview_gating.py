"""Scheduled Config-Delta previews gated on cached status (Phase 3, Task 2)."""

import inspect
import time
from unittest.mock import patch

import pytest

from app import config_delta_gate, inventory, inventory_cache, package_change_alerts
from app.config import Config
from app.fmg_client import FMGClient, pkg_status_for
from app.routes import pending_changes_routes as pcr
from app.synthetic_fmg import SyntheticFMG


@pytest.fixture
def fleet(monkeypatch):
    synth = SyntheticFMG(adoms=1, devices=40, multi_vdom_fraction=0.3, seed=7)
    client = FMGClient(host="fmg.example", token="t")
    client._post = synth.post
    monkeypatch.setattr(Config, "INVENTORY_REFRESH_SECS", 300)
    monkeypatch.setattr(Config, "INVENTORY_MAX_AGE_SECS", 900)
    monkeypatch.setattr(Config, "CONFIG_DELTA_GATING", True)
    monkeypatch.setattr(Config, "CONFIG_DELTA_FULL_SWEEP_HOURS", 24)
    monkeypatch.setattr(Config, "INVENTORY_CACHE", True)
    inventory_cache.refresh_once(client)
    adom = next(
        a["name"]
        for a in client.get_adoms()
        if not a["name"].lower().startswith("forti")
    )
    monkeypatch.setattr("app.fmg_helpers.make_client", lambda: client)
    monkeypatch.setattr(pcr, "make_client", lambda: client)
    previews = []

    def fake_preview(self, adom_, device):
        previews.append(device)
        return ""

    monkeypatch.setattr(FMGClient, "get_install_preview", fake_preview)
    return synth, client, adom, previews


def _expected_pending(client, adom):
    """Devices an honest gate must still preview: anything not clean in all three signals."""
    rows = client.get_adom_package_status(adom)
    out = set()
    for d in client.get_devices_with_sync_status(adom):
        vdoms = [v["name"] for v in d.get("vdom") or []] or ["root"]
        pkg = pkg_status_for(rows, d["name"], vdoms)
        if not (
            d["conf_status"] == "insync"
            and d["db_status"] == "nomod"
            and pkg == "nomod"
        ):
            out.add(d["name"])
    return out


def test_flag_off_previews_every_device(monkeypatch, fleet):
    synth, client, adom, previews = fleet  # noqa: RUF059
    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)
    res = pcr.bulk_preview_adom(adom, max_workers=1)
    assert len(previews) == 40 and len(res) == 40
    assert not any(r.get("gated") for r in res)


def test_gating_on_previews_only_pending_devices(fleet):
    synth, client, adom, previews = fleet  # noqa: RUF059
    config_delta_gate.mark_full_sweep_done(adom)
    expected = _expected_pending(client, adom)
    assert 0 < len(expected) < 40  # the fleet exercises both outcomes
    res = pcr.bulk_preview_adom(adom, max_workers=1)
    assert set(previews) == expected
    assert len(res) == 40


def test_gated_devices_appear_in_results_with_marker(fleet):
    synth, client, adom, previews = fleet  # noqa: RUF059
    config_delta_gate.mark_full_sweep_done(adom)
    res = pcr.bulk_preview_adom(adom, max_workers=1)
    gated = [r for r in res if r.get("gated")]
    assert gated and all(
        r["status"] == "no_changes" and r["error"] is None for r in gated
    )
    assert all(isinstance(r["cached_as_of"], str) and r["device"] for r in gated)
    assert {r["device"] for r in res} == {d["name"] for d in client.get_devices(adom)}


def test_unknown_status_device_is_previewed(fleet):
    synth, client, adom, previews = fleet  # noqa: RUF059
    config_delta_gate.mark_full_sweep_done(adom)
    from app import inventory_store

    devs = inventory_store.read_devices(adom)
    clean = next(d for d in devs if d["name"] not in _expected_pending(client, adom))
    clean["conf_status"] = 0  # unknown
    inventory_store.replace_adom(
        adom,
        devs,
        None,
        __import__("datetime").datetime.now(__import__("datetime").UTC).isoformat(),
    )
    pcr.bulk_preview_adom(adom, max_workers=1)
    assert clean["name"] in previews


def test_full_sweep_previews_all_once_then_gates(fleet):
    synth, client, adom, previews = fleet  # noqa: RUF059
    res = pcr.bulk_preview_adom(adom, max_workers=1)  # never swept
    assert len(previews) == 40 and res.full_sweep is True
    previews.clear()
    res2 = pcr.bulk_preview_adom(adom, max_workers=1)
    assert len(previews) < 40 and res2.full_sweep is False


def test_budget_exhaustion_marks_remaining_devices_as_errors_not_clean(
    monkeypatch, fleet
):
    synth, client, adom, previews = fleet  # noqa: RUF059
    monkeypatch.setattr(Config, "CONFIG_DELTA_GATING", False)

    def slow(self, adom_, device):
        time.sleep(0.05)
        previews.append(device)
        return ""

    monkeypatch.setattr(FMGClient, "get_install_preview", slow)
    res = pcr.bulk_preview_adom(adom, max_workers=1, budget_seconds=0.12)
    skipped = [r for r in res if r["status"] == "error"]
    assert skipped and len(res) == 40
    assert all("time budget" in r["error"] for r in skipped)
    assert len(previews) + len(skipped) == 40
    # an incomplete full sweep must not be recorded as done
    from app import inventory_store

    assert inventory_store.last_full_sweep_age_seconds(adom) is None


def test_default_budget_applies_only_when_gating_is_enabled(monkeypatch, fleet):
    synth, client, adom, previews = fleet  # noqa: RUF059
    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)
    monkeypatch.setattr(
        Config, "CONFIG_DELTA_JOB_BUDGET_SECS", 1
    )  # would bite if applied

    def slow(self, adom_, device):
        time.sleep(0.04)
        return ""

    monkeypatch.setattr(FMGClient, "get_install_preview", slow)
    res = pcr.bulk_preview_adom(adom, max_workers=1)
    assert not any(r["status"] == "error" for r in res)


def test_alerts_treat_gated_as_readable_and_budget_errors_as_unknown(fleet):
    synth, client, adom, previews = fleet  # noqa: RUF059
    results = [
        {"device": "a", "status": "no_changes", "gated": True},
        {
            "device": "b",
            "status": "error",
            "error": "time budget exhausted before this device was previewed",
        },
    ]
    assert package_change_alerts.has_unreadable_targets([("a", "p")], results) is False
    assert (
        package_change_alerts.has_unreadable_targets([("a", "p"), ("b", "p")], results)
        is True
    )


def test_scheduler_gate_counts_helper():
    from app import config_diff_scheduler as sched

    results = pcr.PreviewResults(
        [
            {"device": "a", "status": "no_changes", "gated": True},
            {"device": "b", "status": "ok"},
            {
                "device": "c",
                "status": "error",
                "error": "time budget exhausted before this device was previewed",
            },
            {"device": "d", "status": "error", "error": "boom"},
        ]
    )
    results.full_sweep = True
    assert sched._gate_counts(results) == {
        "devices_previewed": 2,
        "devices_gated": 1,
        "devices_budget_skipped": 1,
        "full_sweep": True,
    }


def test_only_bulk_preview_uses_the_gate_single_device_click_stays_live():
    src = inspect.getsource(pcr)
    assert src.count("select_devices(") == 1
    assert "select_devices(" in inspect.getsource(pcr.bulk_preview_adom)


class _Guard(FMGClient):
    def __init__(self, synth):
        super().__init__(host="fmg.example", token="t")
        self.inventory_calls = []

        def post(body, timeout=None):
            url = body["params"][0]["url"]
            if (
                url == "/dvmdb/adom"
                or (url.startswith("/dvmdb/adom/") and url.endswith("/device"))
                or "_package/status" in url
            ):
                self.inventory_calls.append(url)
                raise AssertionError(url)
            return synth.post(body, timeout)

        self._post = post


def test_adom_list_and_cold_device_list_from_store_with_zero_inventory_calls(
    monkeypatch, fleet
):
    synth, client, adom, _ = fleet  # noqa: RUF059
    guard = _Guard(synth)
    monkeypatch.setattr(pcr, "make_client", lambda: guard)
    from app import pending_status_cache

    pending_status_cache._cache.clear()
    app = __import__("app").create_app()
    c = app.test_client()
    with c.session_transaction() as sess:
        sess["user"] = "admin"
        sess["role"] = "admin"
        sess["_csrf_token"] = "t"
        sess["login_at"] = int(time.time())
    with patch(
        "app.auth._load_users",
        return_value={"admin": {"password_hash": "x", "role": "admin"}},
    ):
        r1 = c.get("/api/pending-changes/adoms")
        r2 = c.get(f"/api/pending-changes/adoms/{adom}/devices")
    assert r1.status_code == 200 and r2.status_code == 200, (
        r1.get_data(),
        r2.get_data(),
    )
    assert guard.inventory_calls == []
    assert len(r2.get_json()) == 40
    assert inventory.counters()["fallbacks"] == 0
