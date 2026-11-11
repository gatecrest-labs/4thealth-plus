"""Per-package hygiene result store (Phase 3, Task 4)."""

import threading
from datetime import UTC, datetime, timedelta

import pytest

from app import hygiene_pkg_store as hps
from app.config import Config


@pytest.fixture(autouse=True)
def _ttl(monkeypatch):
    monkeypatch.setattr(Config, "HYGIENE_PACKAGE_TTL_HOURS", 6)


def _put(adom="A", pkg="P", **kw):
    args = {
        "fingerprint": "f1",
        "policy_count": 3,
        "score_findings": 2,
        "findings": [{"check": "unnamed", "policy_id": 1}],
        "addr_refs": ["a", "b"],
        "svc_refs": ["HTTPS"],
    }
    args.update(kw)
    hps.put(adom, pkg, **args)


def test_round_trip_including_findings_and_ref_sets():
    _put()
    got = hps.get("A", "P")
    assert got["fingerprint"] == "f1" and got["policy_count"] == 3
    assert got["score_findings"] == 2
    assert got["findings"] == [{"check": "unnamed", "policy_id": 1}]
    assert got["addr_refs"] == {"a", "b"} and got["svc_refs"] == {"HTTPS"}
    assert 0 <= got["age_seconds"] < 5


def test_get_none_when_absent():
    assert hps.get("A", "nope") is None


def test_put_replaces_previous_entry():
    _put(fingerprint="old", policy_count=1)
    _put(fingerprint="new", policy_count=9)
    got = hps.get("A", "P")
    assert got["fingerprint"] == "new" and got["policy_count"] == 9


def test_fingerprint_is_key_order_independent_and_change_sensitive():
    a = [{"policyid": 1, "name": "x", "srcaddr": ["a"]}]
    b = [{"srcaddr": ["a"], "name": "x", "policyid": 1}]
    assert hps.fingerprint(a) == hps.fingerprint(b)
    assert hps.fingerprint(a) != hps.fingerprint(
        [{"policyid": 1, "name": "y", "srcaddr": ["a"]}]
    )
    assert hps.fingerprint(a) != hps.fingerprint(a + a)


def test_effective_ttl_is_stable_and_within_bounds():
    base = 6 * 3600.0
    values = [hps.effective_ttl_seconds("A", f"pkg-{i}") for i in range(1000)]
    assert all(0.75 * base <= v <= 1.25 * base for v in values)
    assert values == [hps.effective_ttl_seconds("A", f"pkg-{i}") for i in range(1000)]
    assert max(values) - min(values) > 0.4 * base  # actually spread across the range


def test_touch_resets_age_keeps_content():
    old = datetime.now(UTC) - timedelta(seconds=5000)
    _put()
    hps._set_fetched_at_for_test("A", "P", old.isoformat())
    assert hps.get("A", "P")["age_seconds"] > 4900
    hps.touch("A", "P")
    got = hps.get("A", "P")
    assert got["age_seconds"] < 5 and got["findings"] == [
        {"check": "unnamed", "policy_id": 1}
    ]


def test_delete_missing_removes_only_unlisted():
    _put(pkg="keep")
    _put(pkg="drop")
    _put(adom="B", pkg="other-adom")
    assert hps.delete_missing("A", {"keep"}) == 1
    assert hps.get("A", "keep") and hps.get("A", "drop") is None
    assert hps.get("B", "other-adom")  # other ADOMs untouched


def test_unreadable_store_raises_store_error(monkeypatch):
    import sqlite3

    from app import collector_store

    def boom():
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(collector_store, "_connect", boom)
    with pytest.raises(hps.HygienePkgStoreError):
        hps.get("A", "P")


def test_reads_do_not_wait_for_write_lock():
    from app import collector_store

    _put()
    done = threading.Event()

    def reader():
        hps.get("A", "P")
        done.set()

    with collector_store._lock:
        t = threading.Thread(target=reader, daemon=True)
        t.start()
        assert done.wait(2.0)
    t.join()


def test_coexists_with_inventory_tables_in_one_database():
    from app import inventory_store

    inventory_store.replace_adom(
        "A", [{"name": "d"}], None, datetime.now(UTC).isoformat()
    )
    _put()
    assert inventory_store.read_devices("A")
    assert hps.get("A", "P")
