"""Integration coverage for the collector/web split: a web worker that
has never run its own sweep must serve whatever the collector last
wrote to SQLite, and two independent readers must agree."""
import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

from unittest.mock import patch

import pytest

from app import create_app


@pytest.fixture
def client():
    app = create_app(test_config={"TESTING": True})
    with app.test_client() as c:
        yield c


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    from app import collector_store

    monkeypatch.setattr(collector_store, "_DB_PATH", tmp_path / "shared.db")
    yield


def test_route_reads_from_sqlite_when_in_memory_cache_is_empty(client):
    """Simulates a freshly started web worker under the split deployment:
    executive_summary_cache._store is still at its pending defaults, but
    the collector already wrote a device-sweep snapshot."""
    from app import collector_store, executive_summary_cache

    with executive_summary_cache._lock:
        assert executive_summary_cache._store["device_sweep_status"] == "pending"

    collector_store.write_snapshot(
        "executive_summary_device",
        {
            "firewall_online_count": 7,
            "firewalls_total": 10,
            "adom_count": 2,
            "device_sweep_status": "ok",
            "device_sweep_collected_at": "2026-09-12T00:00:00+00:00",
        },
    )

    with (
        patch("app.routes.external_api_routes.get_setting", return_value=True),
        patch(
            "app.routes.external_api_routes.validate_token",
            return_value={"id": "tok1", "name": "4tExecutive"},
        ),
    ):
        resp = client.get(
            "/external/api/executive/summary",
            headers={"Authorization": "Bearer test-token"},
        )
    body = resp.get_json()

    assert body["firewall_online_count"] == 7
    assert body["firewalls_total"] == 10
    assert body["adom_count"] == 2


def test_two_independent_readers_agree_after_one_collector_write(tmp_path, monkeypatch):
    """Simulates two separate app instances/processes (e.g. two Gunicorn
    workers) both reading get_summary() after one write — since neither
    has run its own sweep, both must read the same SQLite snapshot."""
    from app import collector_store, executive_summary_cache

    collector_store.write_snapshot(
        "executive_summary_device",
        {"firewall_online_count": 3, "device_sweep_status": "ok"},
    )

    with executive_summary_cache._lock:
        executive_summary_cache._store["device_sweep_status"] = "pending"

    reader_one = executive_summary_cache.get_summary()

    with executive_summary_cache._lock:
        executive_summary_cache._store["device_sweep_status"] = "pending"

    reader_two = executive_summary_cache.get_summary()

    assert reader_one["firewall_online_count"] == 3
    assert reader_two["firewall_online_count"] == 3
