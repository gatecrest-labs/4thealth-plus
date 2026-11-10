"""Consumers read the inventory store when INVENTORY_CACHE is on (Phase 2, Tasks 5-7)."""

import copy

import pytest

from app import inventory, inventory_cache
from app.config import Config
from app.fmg_client import FMGClient
from app.synthetic_fmg import SyntheticFMG


def _is_inventory_url(url: str, *, block_pkg: bool = False) -> bool:
    parts = url.split("/")
    if url == "/dvmdb/adom":
        return True
    if parts[:3] == ["", "dvmdb", "adom"] and len(parts) == 5 and parts[4] == "device":
        return True
    return bool(
        block_pkg
        and parts[:3] == ["", "pm", "config"]
        and "_package" in parts
        and "status" in parts
    )


class _NoDvmdb(FMGClient):
    """Fails the test on any inventory call (ADOM list, device list, and with
    ``block_pkg`` the package-status reads); everything else goes to *synth*.

    ``forwarded`` lists the other URLs it was asked for (policy package reads
    that stay live until Phase 4, revisions, per-device proxy calls).
    """

    def __init__(self, synth, block_pkg=False):
        super().__init__(host="fmg.example", token="t")
        self.attempts: list[str] = []
        self.forwarded: list[str] = []

        def post(body, timeout=None):
            url = body["params"][0]["url"]
            if _is_inventory_url(url, block_pkg=block_pkg):
                self.attempts.append(url)
                raise AssertionError(f"unexpected inventory FMG call: {url}")
            self.forwarded.append(url)
            return synth.post(body, timeout)

        self._post = post


def _synth_client(synth):
    c = FMGClient(host="fmg.example", token="t")
    c._post = synth.post
    return c


def _strip(obj):
    """Drop timestamps/durations so two runs of the same sweep compare equal."""
    if isinstance(obj, dict):
        return {
            k: _strip(v)
            for k, v in obj.items()
            if not any(
                t in k for t in ("updated", "elapsed", "_at", "seconds", "since")
            )
        }
    if isinstance(obj, list):
        return [_strip(v) for v in obj]
    return obj


@pytest.fixture
def fleet(monkeypatch):
    synth = SyntheticFMG(adoms=3, devices=90, multi_vdom_fraction=0.4, seed=11)
    real = _synth_client(synth)
    monkeypatch.setattr(Config, "INVENTORY_MAX_AGE_SECS", 900)
    monkeypatch.setattr(Config, "INVENTORY_CACHE", True)
    inventory_cache.refresh_once(real)  # populate the store
    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)
    inventory.reset_counters()
    return synth, real


def _use_client(monkeypatch, client):
    monkeypatch.setattr("app.fmg_helpers.make_client", lambda: client)


def _run(monkeypatch, runner, getter, *, flag, client):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", flag)
    _use_client(monkeypatch, client)
    runner()
    return copy.deepcopy(_strip(getter()))


def _app():
    from app import create_app

    return create_app()


def _cases():
    from app import adom_cache, map_cache, summary_job, versions_cache

    app = _app()
    return {
        "versions_cache": (
            lambda: versions_cache._run_job(app),
            versions_cache.get_cached,
        ),
        "map_cache": (lambda: map_cache._run_job(app), map_cache.get_cached),
        "summary_job": (lambda: summary_job._run_job(app), summary_job.get_summary),
        "adom_cache": (lambda: adom_cache._run_refresh(app), adom_cache.get_adom_names),
    }


@pytest.mark.parametrize(
    "name", ["versions_cache", "map_cache", "summary_job", "adom_cache"]
)
def test_background_cache_same_output_from_store_with_zero_fmg_calls(
    monkeypatch, fleet, name
):
    synth, real = fleet
    runner, getter = _cases()[name]
    legacy = _run(monkeypatch, runner, getter, flag=False, client=real)
    no_fmg = _NoDvmdb(synth)
    cached = _run(monkeypatch, runner, getter, flag=True, client=no_fmg)
    assert no_fmg.attempts == []
    if name != "summary_job":  # summary still reads policy packages (Phase 4)
        assert no_fmg.forwarded == []
    assert cached == legacy
    assert legacy  # the comparison is not trivially empty


@pytest.mark.parametrize(
    "name", ["versions_cache", "map_cache", "summary_job", "adom_cache"]
)
def test_background_cache_flag_off_still_calls_fmg(monkeypatch, fleet, name):
    synth, real = fleet
    runner, getter = _cases()[name]
    synth.calls.clear()
    _run(monkeypatch, runner, getter, flag=False, client=real)
    assert sum(synth.calls.values()) > 0


# ---- Task 6: the sweeps that dominate the baseline ----
@pytest.fixture
def stores(monkeypatch, tmp_path):
    monkeypatch.setattr("app.device_backup_cache._STORE_PATH", tmp_path / "backup.json")
    monkeypatch.setattr(
        "app.license_status_cache._STORE_PATH", tmp_path / "license.json"
    )
    # The exec-summary sweep does live infra-target fetches; keep tests off the network.
    monkeypatch.setattr(Config, "INFRA_TARGETS", [])


def _sweep_cases():
    from app import (
        device_backup_cache,
        executive_summary_cache,
        license_status_cache,
        pending_status_cache,
    )

    app = _app()
    return {
        "pending_status": (
            lambda: pending_status_cache._run_refresh(app),
            pending_status_cache.get_all_cached_devices,
            True,
        ),
        "exec_summary_devices": (
            lambda: executive_summary_cache._run_device_sweep(app),
            executive_summary_cache.get_summary,
            False,
        ),
        "device_backup": (
            lambda: device_backup_cache._run_sweep(app),
            device_backup_cache.get_latest,
            False,
        ),
        "license_status": (
            lambda: license_status_cache._run_sweep(app),
            license_status_cache.get_latest,
            False,
        ),
    }


@pytest.fixture
def small_fleet(monkeypatch):
    synth = SyntheticFMG(adoms=2, devices=24, multi_vdom_fraction=0.5, seed=21)
    real = _synth_client(synth)
    monkeypatch.setattr(Config, "INVENTORY_MAX_AGE_SECS", 900)
    monkeypatch.setattr(Config, "INVENTORY_CACHE", True)
    inventory_cache.refresh_once(real)
    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)
    inventory.reset_counters()
    return synth, real


@pytest.mark.parametrize(
    "name",
    ["pending_status", "exec_summary_devices", "device_backup", "license_status"],
)
def test_sweep_same_output_from_store(monkeypatch, stores, small_fleet, name):
    synth, real = small_fleet
    runner, getter, block_pkg = _sweep_cases()[name]
    legacy = _run(monkeypatch, runner, getter, flag=False, client=real)
    guard = _NoDvmdb(synth, block_pkg=block_pkg)
    cached = _run(monkeypatch, runner, getter, flag=True, client=guard)
    assert guard.attempts == []
    assert cached == legacy
    assert legacy


def test_pending_status_flag_on_makes_zero_fmg_calls(monkeypatch, small_fleet):
    synth, _ = small_fleet
    from app import pending_status_cache

    guard = _NoDvmdb(synth, block_pkg=True)
    monkeypatch.setattr(Config, "INVENTORY_CACHE", True)
    _use_client(monkeypatch, guard)
    pending_status_cache._run_refresh(_app())
    assert guard.forwarded == [] and guard.attempts == []


def test_pending_status_flag_off_still_uses_per_device_calls(monkeypatch, small_fleet):
    synth, real = small_fleet
    from app import pending_status_cache

    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)
    _use_client(monkeypatch, real)
    synth.calls.clear()
    pending_status_cache._run_refresh(_app())
    per_device = [k for k in synth.calls if "_package/status" in k]
    assert per_device and sum(synth.calls[k] for k in per_device) > 10


def test_backup_and_license_keep_their_own_calls(monkeypatch, stores, small_fleet):
    synth, _ = small_fleet
    runner_b, _g, _ = _sweep_cases()["device_backup"]
    runner_l, _g2, _ = _sweep_cases()["license_status"]
    guard = _NoDvmdb(synth)
    monkeypatch.setattr(Config, "INVENTORY_CACHE", True)
    _use_client(monkeypatch, guard)
    runner_b()
    assert any(u.endswith("/revision") for u in guard.forwarded)
    guard.forwarded.clear()
    runner_l()
    assert any(u == "/sys/proxy/json" for u in guard.forwarded)
