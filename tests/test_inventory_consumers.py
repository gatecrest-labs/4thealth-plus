"""Consumers read the inventory store when INVENTORY_CACHE is on (Phase 2, Tasks 5-7)."""

import copy

import pytest

from app import inventory, inventory_cache
from app.config import Config
from app.fmg_client import FMGClient
from app.synthetic_fmg import SyntheticFMG


class _NoDvmdb(FMGClient):
    """Fails the test on any inventory (``/dvmdb/``) call; other calls go to *synth*.

    ``forwarded`` lists the non-inventory URLs it was asked for (e.g. the policy
    package reads that stay live until the policy store lands in Phase 4).
    """

    def __init__(self, synth):
        super().__init__(host="fmg.example", token="t")
        self.attempts: list[str] = []
        self.forwarded: list[str] = []

        def post(body, timeout=None):
            url = body["params"][0]["url"]
            if url.startswith("/dvmdb/"):
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
