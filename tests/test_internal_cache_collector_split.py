"""Collector/web split coverage for the internal-dashboard-only caches that
were left out of the executive-summary-focused SQLite migration:
summary_job (Dashboard's "Managed Firewalls / Policy Rules" section),
versions_cache (Device Version tab), adom_cache, and map_cache. Each must
read through to the collector's persisted SQLite snapshot when this
process's own in-memory copy is still at its "pending" default — e.g. a
freshly started web worker in the split deployment."""
import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

import pytest


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    from app import collector_store

    monkeypatch.setattr(collector_store, "_DB_PATH", tmp_path / "shared.db")
    yield


def test_summary_job_reads_through_when_local_is_pending(monkeypatch):
    from app import collector_store, summary_job

    monkeypatch.setattr(
        summary_job,
        "_store",
        {"firewalls_total": None, "rules_total": None, "last_updated": None, "status": "pending", "error": None},
    )

    collector_store.write_snapshot(
        "summary_job",
        {"firewalls_total": 42, "rules_total": 999, "status": "ok", "last_updated": "2026-09-12T00:00:00+00:00"},
    )

    result = summary_job.get_summary()

    assert result["firewalls_total"] == 42
    assert result["rules_total"] == 999
    assert result["status"] == "ok"


def test_summary_job_local_value_wins_once_own_run_completes(monkeypatch):
    from app import collector_store, summary_job

    monkeypatch.setattr(
        summary_job,
        "_store",
        {"firewalls_total": 7, "rules_total": 100, "last_updated": None, "status": "ok", "error": None},
    )

    collector_store.write_snapshot(
        "summary_job", {"firewalls_total": 999, "rules_total": 999, "status": "ok"}
    )

    result = summary_job.get_summary()

    assert result["firewalls_total"] == 7


def test_versions_cache_reads_through_when_local_is_pending(monkeypatch):
    from app import collector_store, versions_cache

    monkeypatch.setattr(
        versions_cache,
        "_store",
        {"devices": [], "last_updated": None, "status": "pending", "error": None},
    )

    devices = [{"name": "fw1", "version": "v7.4.5", "adom": "root", "status": "green"}]
    collector_store.write_snapshot("versions_cache", {"devices": devices, "status": "ok"})

    result = versions_cache.get_cached()

    assert result["devices"] == devices
    assert result["status"] == "ok"


def test_adom_cache_reads_through_when_local_is_pending(monkeypatch):
    from app import adom_cache, collector_store

    monkeypatch.setattr(
        adom_cache,
        "_state",
        {"adoms": [], "last_updated": None, "status": "pending", "error": None},
    )

    collector_store.write_snapshot("adom_cache", {"adoms": ["East", "West"], "status": "ok"})

    assert adom_cache.get_cached()["adoms"] == ["East", "West"]
    assert adom_cache.get_adom_names() == ["East", "West"]


def test_map_cache_reads_through_when_local_is_pending(monkeypatch):
    from app import collector_store, map_cache

    monkeypatch.setattr(
        map_cache,
        "_store",
        {"devices": [], "last_updated": None, "status": "pending", "error": None, "adom_progress": {}},
    )

    devices = [{"name": "fw1", "adom": "root", "lat": 1.0, "lon": 2.0}]
    collector_store.write_snapshot("map_cache", {"devices": devices, "status": "ok"})

    assert map_cache.get_cached()["devices"] == devices
