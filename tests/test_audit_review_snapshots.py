"""Device Review reads device snapshots; provenance and Live toggle (Phase 5, Task 5)."""
# ruff: noqa: RUF059

import csv
import io
import json
import time
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from app import audit_data, inventory, inventory_cache, snapshot_cache, snapshot_store
from app import device_review_scheduler as drs
from app.config import Config
from app.fmg_client import FMGClient
from app.routes import audit_review_routes as routes
from app.synthetic_fmg import SyntheticFMG

_USERS = {"admin": {"password_hash": "$2b$12$placeholder", "role": "admin"}}


class GuardClient(FMGClient):
    """Allows inventory reads; fails the test on any per-device (proxy) read, counting them."""

    def __init__(self, synth, block_device_get=False):
        super().__init__(host="fmg.example", token="t")
        self.proxy_reads = 0
        self.device_gets = 0

        def post(body, timeout=None):
            url = body["params"][0].get("url", "")
            if url == "/sys/proxy/json":
                self.proxy_reads += 1
                raise AssertionError("unexpected live device read")
            if (
                block_device_get
                and "/device/" in url
                and url.startswith("/dvmdb/adom/")
            ):
                self.device_gets += 1
                raise AssertionError(f"unexpected single device read: {url}")
            return synth.post(body, timeout)

        self._post = post


@pytest.fixture
def rig(monkeypatch):
    monkeypatch.setattr(Config, "INVENTORY_CACHE", False)
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", False)
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOT_WINDOW_DAYS", 7)
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOT_MAX_AGE_HOURS", 0)
    snapshot_cache._revision_flags.clear()
    audit_data.reset_counters()
    synth = SyntheticFMG(adoms=1, devices=5, seed=9)
    real = FMGClient(host="fmg.example", token="t")
    real._post = synth.post
    adom = next(
        a["name"] for a in real.get_adoms() if not a["name"].lower().startswith("forti")
    )
    names = sorted(d["name"] for d in real.get_devices(adom))
    for n in names:
        snapshot_cache.capture_device(real, adom, n)
    return synth, real, adom, names


def _use(monkeypatch, client):
    monkeypatch.setattr("app.routes.audit_review_routes.make_client", lambda: client)
    monkeypatch.setattr("app.fmg_helpers.make_client", lambda: client)


@pytest.fixture
def http():
    from app import create_app

    app = create_app()
    with app.test_client() as c, patch("app.auth._load_users", return_value=_USERS):
        with c.session_transaction() as sess:
            sess["user"] = "admin"
            sess["role"] = "admin"
            sess["_csrf_token"] = "t"
            sess["login_at"] = int(time.time())
        yield c


def _post(c, url, payload):
    return c.post(
        url,
        data=json.dumps(payload),
        content_type="application/json",
        headers={"X-CSRF-Token": "t"},
    )


def _strip(rows):
    return [
        {k: v for k, v in r.items() if k not in ("collected_at", "source")}
        for r in rows
    ]


def _run_one(c, adom, device, **extra):
    return _post(
        c,
        "/api/audit-review/run/device",
        {"adom": adom, "device": device, "check_params": {}, **extra},
    )


def test_per_device_rows_equal_live_rows_plus_provenance(monkeypatch, rig, http):
    synth, real, adom, names = rig
    _use(monkeypatch, real)
    live = _run_one(http, adom, names[0]).get_json()
    assert "collected_at" not in live["rows"][0] and "source" not in live["rows"][0]
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", True)
    guard = GuardClient(synth)
    _use(monkeypatch, guard)
    snap = _run_one(http, adom, names[0]).get_json()
    assert guard.proxy_reads == 0
    assert (
        _strip(snap["rows"]) == live["rows"] and len(live["rows"]) > 20
    )  # all checks incl. interface rows
    assert all(r["source"] in ("snapshot", "inventory") for r in snap["rows"])
    assert any(r["source"] == "snapshot" and r["collected_at"] for r in snap["rows"])
    assert snap["source"] == "snapshot" and snap["collected_at"]


def test_bulk_run_zero_proxy_calls_and_equal_rows(monkeypatch, rig, http):
    synth, real, adom, names = rig
    _use(monkeypatch, real)
    live = _post(
        http, "/api/audit-review/run", {"adom": adom, "devices": [], "check_params": {}}
    ).get_json()
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", True)
    guard = GuardClient(synth)
    _use(monkeypatch, guard)
    snap = _post(
        http, "/api/audit-review/run", {"adom": adom, "devices": [], "check_params": {}}
    ).get_json()
    assert guard.proxy_reads == 0
    key = lambda rows: sorted(json.dumps(r, sort_keys=True) for r in rows)
    assert key(_strip(snap["rows"])) == key(live["rows"]) and live["rows"]


def test_live_true_fetches_current_config_and_labels_rows_live(monkeypatch, rig, http):
    synth, real, adom, names = rig
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", True)
    _use(monkeypatch, real)
    snapshot_store.put_keys(
        adom, names[0], {"ntp": {"ntpsync": "disable", "marker": "stale"}}
    )
    stale = _run_one(http, adom, names[0], checks=["ntp_config"]).get_json()
    live = _run_one(http, adom, names[0], checks=["ntp_config"], live=True).get_json()
    assert stale["source"] == "snapshot" and live["source"] == "live"
    assert all(r["source"] == "live" for r in live["rows"])
    assert (
        stale["rows"] != _strip(live["rows"])
        or stale["rows"][0]["detail"] != live["rows"][0]["detail"]
    )
    assert (
        snapshot_store.get_keys(adom, names[0], {"ntp"})["ntp"]["value"]["marker"]
        == "stale"
    )  # nothing written


def test_each_row_reports_the_age_of_its_own_data(monkeypatch, rig, http):
    synth, real, adom, names = rig
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", True)
    guard = GuardClient(synth)
    _use(monkeypatch, guard)
    dev = names[0]
    snapshot_store._set_collected_at_for_test(
        adom, dev, "ntp", (datetime.now(UTC) - timedelta(hours=30)).isoformat()
    )
    snapshot_store._set_collected_at_for_test(
        adom, dev, "ipsec_phase1", (datetime.now(UTC) - timedelta(hours=50)).isoformat()
    )

    def stamp(key):
        return snapshot_store.get_keys(adom, dev, {key})[key]["collected_at"]

    def rows_for(check):
        return _run_one(http, adom, dev, checks=[check]).get_json()["rows"]

    assert {r["collected_at"] for r in rows_for("ntp_config")} == {stamp("ntp")}
    assert {r["collected_at"] for r in rows_for("trusted_hosts")} == {stamp("admins")}
    # a check built from two keys reports the OLDEST of them (phase1 was aged to 50 h)
    assert (
        {r["collected_at"] for r in rows_for("vpn_weak_crypto")}
        == {min(stamp("ipsec_phase1"), stamp("ipsec_phase2"))}
        == {stamp("ipsec_phase1")}
    )
    firmware = rows_for("firmware_version")
    assert firmware and all(r["source"] == "inventory" for r in firmware)


def test_stale_snapshot_key_makes_its_rows_live(monkeypatch, rig, http):
    synth, real, adom, names = rig
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", True)
    _use(monkeypatch, real)
    dev = names[0]
    snapshot_store._set_collected_at_for_test(
        adom, dev, "ntp", (datetime.now(UTC) - timedelta(hours=200)).isoformat()
    )
    assert {
        r["source"]
        for r in _run_one(http, adom, dev, checks=["ntp_config"]).get_json()["rows"]
    } == {"live"}
    assert {
        r["source"]
        for r in _run_one(http, adom, dev, checks=["trusted_hosts"]).get_json()["rows"]
    } == {"snapshot"}


def test_scheduled_bulk_uses_snapshots_and_the_email_states_the_data_age(
    monkeypatch, rig
):
    synth, real, adom, names = rig
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", True)
    guard = GuardClient(synth)
    _use(monkeypatch, guard)
    snapshot_store._set_collected_at_for_test(
        adom, names[0], "ntp", (datetime.now(UTC) - timedelta(hours=75)).isoformat()
    )
    results = routes.bulk_device_review_adom(adom, [], {})
    assert guard.proxy_reads == 0 and len(results) == 5
    summary = drs._build_summary_html(adom, results, "2026-11-11T00:00:00Z", [])
    assert "Data as of" in summary and "3 days" in summary
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", False)
    plain = drs._build_summary_html(
        adom, routes.bulk_device_review_adom(adom, [], {}), "2026-11-11T00:00:00Z", []
    )
    assert "Data as of" not in plain


def test_exports_include_data_as_of_columns(monkeypatch, rig):
    synth, real, adom, names = rig
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", True)
    _use(monkeypatch, GuardClient(synth))
    results = routes.bulk_device_review_adom(adom, ["ntp_config"], {})
    csv_att = drs._build_attachment_dr(adom, "csv", results, "2026-11-11T00:00:00Z", [])
    rows = list(csv.reader(io.StringIO(csv_att["data"].decode())))
    header = next(r for r in rows if r and r[0] == "Device")
    assert "Data as of" in header and "Source" in header
    json_att = drs._build_attachment_dr(
        adom, "json", results, "2026-11-11T00:00:00Z", []
    )
    assert "collected_at" in json.loads(json_att["data"])["rows"][0]
    html_att = drs._build_attachment_dr(
        adom, "pdf", results, "2026-11-11T00:00:00Z", []
    )
    assert "Data as of" in html_att["data"].decode()
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", False)
    plain = routes.bulk_device_review_adom(adom, ["ntp_config"], {})
    assert (
        "Data as of"
        not in drs._build_attachment_dr(adom, "pdf", plain, "2026-11-11T00:00:00Z", [])[
            "data"
        ].decode()
    )


def test_restricted_user_403_other_adom_with_snapshots_on(monkeypatch, rig, http):
    synth, real, adom, names = rig
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", True)
    guard = GuardClient(synth)
    _use(monkeypatch, guard)
    monkeypatch.setattr(
        "app.routes.audit_review_routes.check_adom_access",
        lambda a: ({"error": "no"}, 403) if a != adom else None,
    )
    assert _run_one(http, "Other", names[0]).status_code == 403
    assert _run_one(http, adom, names[0]).status_code == 200


def test_flag_off_rows_have_no_new_fields_and_fmg_is_called_as_before(
    monkeypatch, rig, http
):
    synth, real, adom, names = rig
    _use(monkeypatch, real)

    def nope(*a, **k):
        raise AssertionError("snapshot store touched with the flag off")

    monkeypatch.setattr(snapshot_store, "get_keys", nope)
    synth.proxy_calls.clear()
    body = _run_one(http, adom, names[0]).get_json()
    assert sum(synth.proxy_calls.values()) > 5
    assert "source" not in body and all(
        "source" not in r and "collected_at" not in r for r in body["rows"]
    )


def test_device_meta_comes_from_the_inventory_not_a_live_get_device(
    monkeypatch, rig, http
):
    synth, real, adom, names = rig
    monkeypatch.setattr(Config, "INVENTORY_CACHE", True)
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", True)
    inventory_cache.refresh_once(real)
    guard = GuardClient(synth, block_device_get=True)
    _use(monkeypatch, guard)
    resp = _run_one(
        http,
        adom,
        names[0],
        checks=["firmware_version"],
        check_params={"firmware_version": {"min_version": "7.0.0"}},
    )
    assert resp.status_code == 200 and guard.device_gets == 0 and guard.proxy_reads == 0
    assert inventory.device(guard, adom, names[0])["name"] == names[0]


def test_page_shows_live_toggle_and_data_as_of_column_only_when_enabled(
    monkeypatch, rig, http
):
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", True)
    on = http.get("/audit-review").get_data(as_text=True)
    assert 'id="drLive"' in on and "Data as of" in on and "_auditSnapshots = true" in on
    monkeypatch.setattr(Config, "AUDIT_SNAPSHOTS", False)
    off = http.get("/audit-review").get_data(as_text=True)
    assert 'id="drLive"' not in off and "_auditSnapshots" not in off
