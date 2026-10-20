import csv
import io
import json

import pytest

import app.nat_report_scheduler as nrs


def _job_data(**overrides):
    base = {
        "name": "NAT",
        "adom": "TestADOM",
        "days_of_week": ["MON"],
        "time": "04:00",
        "format": "csv",
        "email": "a@example.com",
        "enabled": False,
    }
    base.update(overrides)
    return base


def _rule(pid, dst=(), pool=(), name=""):
    return {
        "policyid": pid,
        "name": name or f"r{pid}",
        "status": "enable",
        "action": "accept",
        "srcaddr": ["all"],
        "dstaddr": list(dst),
        "service": ["HTTPS"],
        "poolname": list(pool),
    }


def _pkg(name, rules, scope=()):
    return {
        "package": name,
        "package_name": name,
        "scope_members": list(scope),
        "rules": rules,
        "error": None,
    }


def _data():
    vip = nrs._norm_vip(
        {
            "name": "vip-web",
            "extip": ["203.0.113.10"],
            "mappedip": [{"range": "10.0.0.5"}],
        }
    )
    dev_vip = nrs._norm_vip(
        {
            "name": "vip-dev",
            "extip": "203.0.113.20",
            "mappedip": "10.0.0.6",
            "_source_device": "fw-a",
            "_source_vdom": "root",
        }
    )
    unused = nrs._norm_vip({"name": "vip-unused", "extip": "203.0.113.30"})
    pool = nrs._norm_pool(
        {"name": "pool-out", "startip": "198.51.100.1", "endip": "198.51.100.5"}
    )
    return {
        "vips": [vip, dev_vip, unused],
        "pools": [pool],
        "packages": [
            _pkg(
                "pkgA",
                [
                    _rule(1, dst=["grp-dmz"]),
                    _rule(2, dst=["vip-dev"], pool=["pool-out"]),
                ],
                scope=[{"name": "fw-a", "vdom": "root"}],
            ),
            _pkg(
                "pkgB",
                [_rule(3, dst=["vip-dev"])],
                scope=[{"name": "fw-b", "vdom": "root"}],
            ),
        ],
    }


GROUPS = {"grp-dmz": {"type": "group", "detail": "", "members": ["vip-web", "other"]}}


def test_rows_identify_type_and_match_through_groups():
    rows = nrs.build_nat_rows(_data(), GROUPS)
    web = [r for r in rows if r["name"] == "vip-web"]
    assert [(r["nat_type"], r["package"], r["policyid"]) for r in web] == [
        ("VIP", "pkgA", 1)
    ]
    assert web[0]["nat_ip"] == "203.0.113.10" and web[0]["mapped_ip"] == "10.0.0.5"
    pool = [r for r in rows if r["name"] == "pool-out"]
    assert [(r["nat_type"], r["policyid"]) for r in pool] == [("IP Pool", 2)]
    assert pool[0]["nat_ip"] == "198.51.100.1-198.51.100.5"


def test_device_vip_only_matches_packages_in_scope():
    rows = [r for r in nrs.build_nat_rows(_data(), GROUPS) if r["name"] == "vip-dev"]
    assert [(r["package"], r["policyid"]) for r in rows] == [("pkgA", 2)]


def test_unused_object_gets_blank_row():
    rows = [r for r in nrs.build_nat_rows(_data(), GROUPS) if r["name"] == "vip-unused"]
    assert len(rows) == 1 and rows[0]["package"] == "" and rows[0]["policyid"] == ""
    assert nrs._summary(nrs.build_nat_rows(_data(), GROUPS))["unused"] == 1


def test_errored_package_is_skipped():
    d = _data()
    d["packages"][0]["error"] = "boom"
    assert not [r for r in nrs.build_nat_rows(d, GROUPS) if r["package"] == "pkgA"]


@pytest.mark.parametrize(
    "fmt,ext", [("csv", "csv"), ("json", "json"), ("html", "html")]
)
def test_attachment_formats(fmt, ext):
    rows = nrs.build_nat_rows(_data(), GROUPS)
    name, blob = nrs.build_attachment("My ADOM", rows, [], fmt, "2026-10-19T01:00:00Z")
    assert name == f"nat_report_My_ADOM_2026-10-19.{ext}"
    text = blob.decode()
    assert "IP Pool" in text and "VIP" in text
    if fmt == "json":
        assert json.loads(text)["summary"]["pools"] == 1
    if fmt == "csv":
        body = [
            row
            for row in csv.reader(io.StringIO(text))
            if row and not row[0].startswith("#")
        ]
        assert body[0] == nrs.CSV_COLUMNS


def test_crud_and_validation(tmp_path, monkeypatch):
    monkeypatch.setattr(nrs, "_JOBS_PATH", tmp_path / "jobs.json")
    job = nrs.create_job(_job_data())
    assert nrs.update_job(job["id"], _job_data(format="json"))["format"] == "json"
    with pytest.raises(ValueError):
        nrs.create_job(_job_data(format="pdf"))
    with pytest.raises(ValueError):
        nrs.create_job(_job_data(days_of_week=[]))
    nrs.delete_job(job["id"])
    assert nrs.get_all_jobs() == []
    with pytest.raises(KeyError):
        nrs.delete_job("nope")


def _run(tmp_path, monkeypatch, collect):
    monkeypatch.setattr(nrs, "_JOBS_PATH", tmp_path / "jobs.json")
    sent = []
    monkeypatch.setattr(nrs, "_collect", collect)
    monkeypatch.setattr(nrs, "_group_members", lambda adom: GROUPS)
    monkeypatch.setattr(nrs, "_send_email", lambda *a: sent.append(a))
    job = nrs.create_job(_job_data())
    nrs._execute_job(job["id"])
    return nrs.get_all_jobs()[0]["runs"][0], sent


def test_execute_job_success_records_run_and_emails(tmp_path, monkeypatch):
    run, sent = _run(tmp_path, monkeypatch, lambda adom: _data())
    assert run["status"] == "ok" and run["emails_sent"] == 1
    assert run["nat_objects"] == 4 and run["unused"] == 1
    assert len(sent) == 1 and sent[0][3][0]["filename"].endswith(".csv")


def test_execute_job_failure_records_error(tmp_path, monkeypatch):
    def boom(adom):
        raise RuntimeError("fmg down")

    run, sent = _run(tmp_path, monkeypatch, boom)
    assert run["status"] == "error" and "fmg down" in run["errors"][0] and not sent


def test_scan_stats_and_report_show_what_was_scanned():
    data = _data()
    stats = nrs.scan_stats(data)
    assert stats == {"packages_total": 2, "packages_ok": 2, "rules_scanned": 3}
    rows = nrs.build_nat_rows(data, GROUPS)
    _, html = nrs.build_attachment("A", rows, [], "html", "2026-10-19T00:00:00Z", stats)
    assert "2 of 2" in html.decode()
    _, js = nrs.build_attachment("A", rows, [], "json", "2026-10-19T00:00:00Z", stats)
    assert json.loads(js)["summary"]["rules_scanned"] == 3


def test_execute_job_errors_when_no_packages(tmp_path, monkeypatch):
    run, sent = _run(
        tmp_path, monkeypatch, lambda adom: {"vips": [], "pools": [], "packages": []}
    )
    assert run["status"] == "error" and "No policy packages" in run["errors"][0]
    assert not sent
