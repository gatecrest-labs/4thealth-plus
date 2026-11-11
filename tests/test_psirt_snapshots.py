"""PSIRT workaround checks read device snapshots (Phase 5, Task 6)."""
# ruff: noqa: RUF059

import json
import time
from unittest.mock import patch

import pytest

from app import audit_data, snapshot_cache
from app.config import Config
from app.fmg_client import FMGClient
from app.psirt_adapter import SnapshotFMGAdapter
from app.synthetic_fmg import SyntheticFMG

_USERS = {"admin": {"password_hash": "$2b$12$placeholder", "role": "admin"}}

ADVISORY = {
    "advisory_id": "FG-IR-26-001",
    "cve_ids": ["CVE-2026-0001"],
    "fortinet_severity": "high",
    "cvss_score": 8.1,
    "description": "x",
    "affected_ranges": [
        {
            "product": "FortiOS",
            "min_version": "7.0.0",
            "max_version": "7.6.99",
            "fixed_version": "7.7.0",
        }
    ],
    "workaround_text": "Restrict management access using trusted hosts",
    "exploited_in_wild_text": "",
}


class Guard(FMGClient):
    def __init__(self, synth):
        super().__init__(host="fmg.example", token="t")
        self.proxy_reads = 0

        def post(body, timeout=None):
            if body["params"][0].get("url") == "/sys/proxy/json":
                self.proxy_reads += 1
                raise AssertionError("unexpected live device read")
            return synth.post(body, timeout)

        self._post = post


@pytest.fixture
def rig(monkeypatch):
    for k, v in (
        ("INVENTORY_CACHE", False),
        ("AUDIT_SNAPSHOTS", False),
        ("AUDIT_SNAPSHOT_WINDOW_DAYS", 7),
        ("AUDIT_SNAPSHOT_MAX_AGE_HOURS", 0),
    ):
        monkeypatch.setattr(Config, k, v)
    monkeypatch.setattr(Config, "PSIRT_ENRICHMENT_ENABLED", False)
    snapshot_cache._revision_flags.clear()
    audit_data.reset_counters()
    synth = SyntheticFMG(adoms=1, devices=4, seed=3)
    real = FMGClient(host="fmg.example", token="t")
    real._post = synth.post
    adom = next(
        a["name"] for a in real.get_adoms() if not a["name"].lower().startswith("forti")
    )
    names = sorted(d["name"] for d in real.get_devices(adom))
    for n in names:
        snapshot_cache.capture_device(real, adom, n)
    return synth, real, adom, names


@pytest.fixture
def http(tmp_path, monkeypatch):
    from app import create_app, psirt_store

    monkeypatch.setattr(psirt_store, "_DB_PATH", tmp_path / "psirt.db")
    app = create_app()
    with app.test_client() as c, patch("app.auth._load_users", return_value=_USERS):
        with c.session_transaction() as sess:
            sess["user"] = "admin"
            sess["role"] = "admin"
            sess["_csrf_token"] = "t"
            sess["login_at"] = int(time.time())
        yield c


def _use(monkeypatch, client):
    monkeypatch.setattr("app.routes.psirt_routes.make_client", lambda: client)
    monkeypatch.setattr("app.fmg_helpers.make_client", lambda: client)


def _post(c, url, payload):
    return c.post(
        url,
        data=json.dumps(payload),
        content_type="application/json",
        headers={"X-CSRF-Token": "t"},
    )


def _findings(body):
    return sorted(body["findings"], key=lambda f: f["device"])


def test_assess_with_snapshots_equals_live_assessment_zero_proxy_calls(
    monkeypatch, rig, http
):
    synth, real, adom, names = rig
    _use(monkeypatch, real)
    live = _post(
        http, "/api/audit-review/psirt/assess", {"adom": adom, "advisory": ADVISORY}
    ).get_json()
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", True)
    guard = Guard(synth)
    _use(monkeypatch, guard)
    snap = _post(
        http, "/api/audit-review/psirt/assess", {"adom": adom, "advisory": ADVISORY}
    ).get_json()
    assert guard.proxy_reads == 0
    strip = lambda fs: [
        {k: v for k, v in f.items() if k not in ("data_as_of", "source")} for f in fs
    ]
    assert strip(_findings(snap)) == _findings(live) and live["findings"]
    assert {f["workaround_status"] for f in live["findings"]} - {
        "manual_verification_required"
    }


def test_workaround_check_sees_snapshot_interfaces_and_admins(monkeypatch, rig):
    synth, real, adom, names = rig
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", True)
    from app.psirt.workaround_checks import check_workaround

    adapter = SnapshotFMGAdapter(Guard(synth))
    live = SnapshotFMGAdapter(real, live=True)
    for n in names:
        for key in ("configure_trusted_hosts", "disable_http_https_admin_access"):
            assert check_workaround(key, adapter, adom, n) == check_workaround(
                key, live, adom, n
            )


def test_provenance_attached_to_device_results_and_report(monkeypatch, rig, http):
    synth, real, adom, names = rig
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", True)
    _use(monkeypatch, Guard(synth))
    body = _post(
        http, "/api/audit-review/psirt/assess", {"adom": adom, "advisory": ADVISORY}
    ).get_json()
    checked = [f for f in body["findings"] if f["in_range"]]
    assert checked and all(
        f["source"] == "snapshot" and f["data_as_of"] for f in checked
    )
    html = _post(http, "/api/audit-review/psirt/report", {"assessment": body}).get_data(
        as_text=True
    )
    assert "Data as of" in html
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", False)
    plain = {
        **body,
        "findings": [
            {k: v for k, v in f.items() if k not in ("data_as_of", "source")}
            for f in body["findings"]
        ],
    }
    assert "Data as of" not in _post(
        http, "/api/audit-review/psirt/report", {"assessment": plain}
    ).get_data(as_text=True)


def test_single_device_route_carries_provenance(monkeypatch, rig, http):
    synth, real, adom, names = rig
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", True)
    guard = Guard(synth)
    _use(monkeypatch, guard)
    body = _post(
        http,
        "/api/audit-review/psirt/assess/device",
        {"adom": adom, "device": names[0], "advisory": ADVISORY},
    ).get_json()
    assert guard.proxy_reads == 0
    assert body["finding"]["source"] == "snapshot" and body["finding"]["data_as_of"]


def test_live_flag_bypasses_snapshots(monkeypatch, rig, http):
    synth, real, adom, names = rig
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", True)
    _use(monkeypatch, real)
    synth.proxy_calls.clear()
    body = _post(
        http,
        "/api/audit-review/psirt/assess",
        {"adom": adom, "advisory": ADVISORY, "live": True},
    ).get_json()
    assert sum(synth.proxy_calls.values()) > 0
    assert {f["source"] for f in body["findings"] if f["in_range"]} == {"live"}


def test_unknown_adapter_method_raises(rig):
    synth, real, adom, names = rig
    with pytest.raises(AttributeError):
        SnapshotFMGAdapter(real).get_device_policies  # noqa: B018


def test_adoms_and_devices_come_from_inventory_facade(monkeypatch, rig):
    synth, real, adom, names = rig
    from app import inventory_cache

    monkeypatch.setattr(Config, "INVENTORY_CACHE", True)
    inventory_cache.refresh_once(real)
    guard = Guard(synth)
    calls = []
    orig = guard._post
    guard._post = lambda body, timeout=None: (
        calls.append(body["params"][0].get("url")),
        orig(body, timeout),
    )[1]
    adapter = SnapshotFMGAdapter(guard)
    assert [a["name"] for a in adapter.get_adoms() if a["name"] == adom] == [adom]
    assert sorted(d["name"] for d in adapter.get_devices(adom)) == names
    assert not [u for u in calls if u and "/dvmdb/" in u]


def test_star_adom_assessment_respects_adom_access(monkeypatch, rig, http):
    synth, real, adom, names = rig
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", True)
    _use(monkeypatch, Guard(synth))
    monkeypatch.setattr("app.groups.get_allowed_adoms", lambda *a, **k: [])
    assert (
        _post(
            http, "/api/audit-review/psirt/assess", {"adom": "*", "advisory": ADVISORY}
        ).status_code
        == 403
    )
    monkeypatch.setattr("app.groups.get_allowed_adoms", lambda *a, **k: [adom])
    body = _post(
        http, "/api/audit-review/psirt/assess", {"adom": "*", "advisory": ADVISORY}
    ).get_json()
    assert {f["adom"] for f in body["findings"]} == {adom}


def test_flag_off_unchanged(monkeypatch, rig, http):
    synth, real, adom, names = rig
    _use(monkeypatch, real)

    def nope(*a, **k):
        raise AssertionError("snapshot store touched with the flag off")

    monkeypatch.setattr("app.snapshot_store.get_keys", nope)
    body = _post(
        http, "/api/audit-review/psirt/assess", {"adom": adom, "advisory": ADVISORY}
    ).get_json()
    assert body["findings"] and all(
        "source" not in f and "data_as_of" not in f for f in body["findings"]
    )
