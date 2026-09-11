"""Unit tests for app.infra_health_cache — SNMP polling and cache."""

import os
import time
from unittest.mock import AsyncMock, MagicMock, patch

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

import pytest

from app import infra_health_cache as cache_mod


@pytest.fixture(autouse=True)
def _reset_cache():
    """Each test starts with a clean in-memory cache."""
    with cache_mod._lock:
        cache_mod._cache.clear()
    yield
    with cache_mod._lock:
        cache_mod._cache.clear()


@pytest.fixture
def snmp_targets(monkeypatch):
    monkeypatch.setattr(
        cache_mod.Config,
        "INFRA_TARGETS",
        [
            {"label": "FMG-01", "host": "10.0.0.1", "type": "FortiManager"},
            {"label": "FAZ-01", "host": "10.0.0.2", "type": "FortiAnalyzer"},
            {"label": "FAC-01", "host": "10.0.0.3", "type": "FortiAuthenticator"},
            {"label": "FCT-01", "host": "10.0.0.4", "type": "FortiCollector"},
        ],
    )
    monkeypatch.setattr(cache_mod.Config, "SNMP_ENABLED", True)


async def _fake_snmp_get(host, oids, creds):
    """FortiManager queries 3 OIDs (cpu, mem_used, mem_total); other SNMP-polled
    types query 2 (cpu, mem). mem_total=100 makes mem_used read directly as %."""
    if len(oids) == 3:
        return [12.5, 34.0, 100.0]
    return [12.5, 34.0]


def test_poll_all_targets_populates_cache_for_supported_types(snmp_targets):
    with patch.object(cache_mod, "_snmp_get", new=_fake_snmp_get):
        cache_mod.poll_all_targets()

    assert cache_mod.get_cached("10.0.0.1") == {
        "cpu": 12.5,
        "mem": 34.0,
        "snmp_status": "ok",
        "last_updated": cache_mod.get_cached("10.0.0.1")["last_updated"],
    }
    assert cache_mod.get_cached("10.0.0.2")["snmp_status"] == "ok"
    assert cache_mod.get_cached("10.0.0.3")["snmp_status"] == "ok"


def test_poll_all_targets_skips_unsupported_type(snmp_targets):
    with patch.object(
        cache_mod, "_snmp_get", new=AsyncMock(return_value=[1.0, 2.0])
    ):
        cache_mod.poll_all_targets()

    assert cache_mod.get_cached("10.0.0.4") is None


def test_poll_all_targets_marks_timeout(snmp_targets):
    with patch.object(
        cache_mod,
        "_snmp_get",
        new=AsyncMock(side_effect=cache_mod.SnmpTimeout("no response")),
    ):
        cache_mod.poll_all_targets()

    entry = cache_mod.get_cached("10.0.0.1")
    assert entry["snmp_status"] == "timeout"
    assert entry["cpu"] is None
    assert entry["mem"] is None


def test_poll_all_targets_marks_error_on_other_exceptions(snmp_targets):
    with patch.object(
        cache_mod, "_snmp_get", new=AsyncMock(side_effect=RuntimeError("boom"))
    ):
        cache_mod.poll_all_targets()

    entry = cache_mod.get_cached("10.0.0.1")
    assert entry["snmp_status"] == "error"
    assert entry["cpu"] is None


def test_poll_all_targets_noop_when_snmp_disabled(snmp_targets, monkeypatch):
    monkeypatch.setattr(cache_mod.Config, "SNMP_ENABLED", False)
    with patch.object(
        cache_mod, "_snmp_get", new=AsyncMock(return_value=[1.0, 2.0])
    ) as mocked:
        cache_mod.poll_all_targets()
    mocked.assert_not_called()
    assert cache_mod.get_cached("10.0.0.1") is None


def test_get_cached_returns_copy_not_reference(snmp_targets):
    async def _fake(host, oids, creds):
        return [5.0, 6.0, 100.0] if len(oids) == 3 else [5.0, 6.0]

    with patch.object(cache_mod, "_snmp_get", new=_fake):
        cache_mod.poll_all_targets()

    entry = cache_mod.get_cached("10.0.0.1")
    entry["cpu"] = 999
    assert cache_mod.get_cached("10.0.0.1")["cpu"] == 5.0


def test_resolve_snmp_creds_per_device_override(monkeypatch):
    monkeypatch.setattr(cache_mod.Config, "SNMP_USER", "default-user")
    monkeypatch.setattr(cache_mod.Config, "SNMP_AUTH_KEY", "default-auth")
    monkeypatch.setattr(cache_mod.Config, "SNMP_PRIV_KEY", "default-priv")
    monkeypatch.setattr(cache_mod.Config, "SNMP_AUTH_PROTOCOL", "SHA")
    monkeypatch.setattr(cache_mod.Config, "SNMP_PRIV_PROTOCOL", "AES")

    target = {"host": "10.0.0.9", "type": "FortiAuthenticator", "snmp_user": "override-user"}
    creds = cache_mod._resolve_snmp_creds(target)

    assert creds["user"] == "override-user"
    assert creds["auth_key"] == "default-auth"  # not overridden, falls back
    assert creds["priv_key"] == "default-priv"


def test_poll_all_targets_skips_target_missing_host(snmp_targets, monkeypatch):
    """Target missing 'host' key should be skipped without raising; other targets still polled."""
    monkeypatch.setattr(
        cache_mod.Config,
        "INFRA_TARGETS",
        [
            {"label": "Bad Entry", "type": "FortiManager"},  # no "host" key
            {"label": "FMG-01", "host": "10.0.0.1", "type": "FortiManager"},
        ],
    )
    async def _fake(host, oids, creds):
        return [1.0, 2.0, 100.0] if len(oids) == 3 else [1.0, 2.0]

    with patch.object(cache_mod, "_snmp_get", new=_fake):
        cache_mod.poll_all_targets()  # must not raise

    # Good target was polled successfully
    assert cache_mod.get_cached("10.0.0.1")["snmp_status"] == "ok"


def test_fetch_meta_parses_hostname_ha_role_and_disk_pct():
    fake_client = MagicMock()
    fake_client.__enter__ = MagicMock(return_value=fake_client)
    fake_client.__exit__ = MagicMock(return_value=False)
    fake_client.get_system_status.return_value = {
        "Hostname": "fmg1.local",
        "HA Role": "master",
        "disk info": {"used": "20", "total": "100"},
    }

    with patch("app.fmg_client.FMGClient", return_value=fake_client):
        meta = cache_mod.fetch_meta({"host": "10.0.0.1", "type": "FortiManager"})

    assert meta == {"hostname": "fmg1.local", "ha_role": "master", "disk_pct": 20.0, "api_ok": True}


def test_fetch_meta_handles_list_response():
    fake_client = MagicMock()
    fake_client.__enter__ = MagicMock(return_value=fake_client)
    fake_client.__exit__ = MagicMock(return_value=False)
    fake_client.get_system_status.return_value = [{"hostname": "faz1.local", "ha_role": "n/a"}]

    with patch("app.fmg_client.FMGClient", return_value=fake_client):
        meta = cache_mod.fetch_meta({"host": "10.0.0.2", "type": "FortiAnalyzer"})

    assert meta["hostname"] == "faz1.local"
    assert meta["disk_pct"] is None


def test_fetch_meta_unreachable_returns_all_none_and_api_ok_false():
    with patch("app.fmg_client.FMGClient", side_effect=RuntimeError("connection refused")):
        meta = cache_mod.fetch_meta({"host": "10.0.0.1", "type": "FortiManager"})

    assert meta == {"hostname": None, "ha_role": None, "disk_pct": None, "api_ok": False}


def test_fetch_meta_never_returns_zero_disk_for_unreachable_target():
    # Regression guard: an unreachable target must read as "no data", never
    # as a healthy 0% disk usage.
    with patch("app.fmg_client.FMGClient", side_effect=RuntimeError("boom")):
        meta = cache_mod.fetch_meta({"host": "10.0.0.1", "type": "FortiManager"})
    assert meta["disk_pct"] is None


def test_fetch_meta_malformed_disk_info_returns_none_not_crash():
    fake_client = MagicMock()
    fake_client.__enter__ = MagicMock(return_value=fake_client)
    fake_client.__exit__ = MagicMock(return_value=False)
    fake_client.get_system_status.return_value = {"disk info": {"used": "n/a", "total": "n/a"}}

    with patch("app.fmg_client.FMGClient", return_value=fake_client):
        meta = cache_mod.fetch_meta({"host": "10.0.0.1", "type": "FortiManager"})

    assert meta["disk_pct"] is None
    assert meta["api_ok"] is True


def test_poll_now_does_not_block_caller(snmp_targets):
    """poll_now() must return immediately even if the underlying poll is slow,
    and the poll must still complete in the background."""

    async def _slow_snmp_get(host, oids, creds):
        time.sleep(0.3)
        return [7.0, 8.0, 100.0] if len(oids) == 3 else [7.0, 8.0]

    with patch.object(cache_mod, "_snmp_get", new=_slow_snmp_get):
        start = time.monotonic()
        cache_mod.poll_now()
        elapsed = time.monotonic() - start

        # Returning to the caller should take a tiny fraction of the 0.3s poll time.
        assert elapsed < 0.1

        # Poll for the cache to be populated in the background, with a timeout
        # to avoid flakiness instead of a fixed sleep.
        deadline = time.monotonic() + 2.0
        entry = None
        while time.monotonic() < deadline:
            entry = cache_mod.get_cached("10.0.0.1")
            if entry is not None:
                break
            time.sleep(0.02)

    assert entry is not None
    assert entry["snmp_status"] == "ok"
    assert entry["cpu"] == 7.0
