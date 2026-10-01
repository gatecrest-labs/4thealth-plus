"""Tests for HA/standalone bucketing in summary_job._run_job()."""

import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest

import app.summary_job as sj


def _make_client_mock(adom_names, devices_by_adom):
    """Return a make_client replacement yielding a client with controlled data."""
    client = MagicMock()
    client.get_adoms.return_value = [{"name": n} for n in adom_names]
    client.get_devices.side_effect = lambda adom: devices_by_adom.get(adom, [])
    client.get_policy_packages.return_value = []

    @contextmanager
    def _ctx():
        yield client

    return _ctx


@pytest.fixture
def run_job(monkeypatch):
    """Run _run_job against fake FMG data and return get_summary()."""
    monkeypatch.setattr(
        sj,
        "_store",
        {
            "firewalls_total": None,
            "rules_total": None,
            "ha_clusters": None,
            "standalones": None,
            "last_updated": None,
            "status": "pending",
            "error": None,
        },
    )
    monkeypatch.setattr("app.collector_store.write_snapshot", lambda *a, **kw: None)

    def _run(adom_names, devices_by_adom):
        monkeypatch.setattr(
            "app.fmg_helpers.make_client",
            _make_client_mock(adom_names, devices_by_adom),
        )
        sj._run_job(app=None)
        return sj.get_summary()

    return _run


@pytest.mark.parametrize("ha_mode", [1, 2, "1", "2"])
def test_ha_modes_counted_as_cluster(run_job, ha_mode):
    result = run_job(["ADOM1"], {"ADOM1": [{"name": "fw1", "ha_mode": ha_mode}]})
    assert result["ha_clusters"] == 1
    assert result["standalones"] == 0


@pytest.mark.parametrize(
    "device",
    [
        {"name": "fw1", "ha_mode": 0},
        {"name": "fw1", "ha_mode": None},
        {"name": "fw1", "ha_mode": ""},
        {"name": "fw1", "ha_mode": "garbage"},
        {"name": "fw1"},  # no ha_mode key at all
    ],
)
def test_non_ha_counted_as_standalone(run_job, device):
    result = run_job(["ADOM1"], {"ADOM1": [device]})
    assert result["ha_clusters"] == 0
    assert result["standalones"] == 1


def test_mixed_devices_across_adoms(run_job):
    result = run_job(
        ["ADOM1", "ADOM2"],
        {
            "ADOM1": [{"name": "fw1", "ha_mode": 1}, {"name": "fw2", "ha_mode": 2}],
            "ADOM2": [{"name": "fw3", "ha_mode": 0}],
        },
    )
    assert result["ha_clusters"] == 2
    assert result["standalones"] == 1
    assert result["firewalls_total"] == 3


def test_clusters_plus_standalones_equals_total(run_job):
    result = run_job(
        ["ADOM1"],
        {
            "ADOM1": [
                {"name": "fw1", "ha_mode": 1},
                {"name": "fw2", "ha_mode": 0},
                {"name": "fw3"},
            ]
        },
    )
    assert result["ha_clusters"] + result["standalones"] == result["firewalls_total"]
