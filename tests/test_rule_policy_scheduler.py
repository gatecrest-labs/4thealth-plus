import json

import pytest

import app.rule_policy_scheduler as sched


@pytest.fixture(autouse=True)
def tmp_jobs(tmp_path, monkeypatch):
    p = tmp_path / "rule_policy_jobs.json"
    monkeypatch.setattr(sched, "_JOBS_PATH", p)
    yield p


def _valid_weekly():
    return {
        "name": "Test",
        "adom": "Corp",
        "packages": [],
        "schedule_type": "weekly",
        "days_of_week": ["MON"],
        "monthly_position": "beginning",
        "time": "02:00",
        "format": "html",
        "batch_size": 10,
        "email": "a@b.com",
        "enabled": True,
    }


def test_validate_rejects_missing_email():
    d = _valid_weekly()
    d["email"] = ""
    with pytest.raises(ValueError, match="email"):
        sched._validate_job_fields(d)


def test_validate_rejects_missing_adom():
    d = _valid_weekly()
    d["adom"] = "  "
    with pytest.raises(ValueError, match="adom"):
        sched._validate_job_fields(d)


def test_validate_rejects_invalid_schedule_type():
    d = _valid_weekly()
    d["schedule_type"] = "hourly"
    with pytest.raises(ValueError, match="schedule_type"):
        sched._validate_job_fields(d)


def test_validate_weekly_requires_days():
    d = _valid_weekly()
    d["days_of_week"] = []
    with pytest.raises(ValueError, match="days_of_week"):
        sched._validate_job_fields(d)


def test_validate_weekly_rejects_invalid_day():
    d = _valid_weekly()
    d["days_of_week"] = ["XYZ"]
    with pytest.raises(ValueError, match="XYZ"):
        sched._validate_job_fields(d)


def test_validate_monthly_requires_valid_position():
    d = _valid_weekly()
    d["schedule_type"] = "monthly"
    d["monthly_position"] = "middle"
    with pytest.raises(ValueError, match="monthly_position"):
        sched._validate_job_fields(d)


def test_validate_daily_no_days_required():
    d = _valid_weekly()
    d["schedule_type"] = "daily"
    d["days_of_week"] = []
    sched._validate_job_fields(d)  # must not raise


def test_validate_rejects_bad_time():
    d = _valid_weekly()
    d["time"] = "25:00"
    with pytest.raises(ValueError, match="time"):
        sched._validate_job_fields(d)


def test_validate_rejects_batch_size_out_of_range():
    d = _valid_weekly()
    d["batch_size"] = 99
    with pytest.raises(ValueError, match="batch_size"):
        sched._validate_job_fields(d)


def test_create_job_assigns_id():
    job = sched.create_job(_valid_weekly())
    assert "id" in job and len(job["id"]) == 36


def test_create_job_persists():
    sched.create_job(_valid_weekly())
    jobs = sched.get_all_jobs()
    assert len(jobs) == 1


def test_update_job_merges_fields():
    job = sched.create_job(_valid_weekly())
    updated = sched.update_job(job["id"], {**_valid_weekly(), "name": "Updated"})
    assert updated["name"] == "Updated"
    assert sched.get_all_jobs()[0]["name"] == "Updated"


def test_update_job_raises_on_missing():
    with pytest.raises(KeyError):
        sched.update_job("nonexistent", _valid_weekly())


def test_delete_job_removes_entry():
    job = sched.create_job(_valid_weekly())
    sched.delete_job(job["id"])
    assert sched.get_all_jobs() == []


def test_delete_job_raises_on_missing():
    with pytest.raises(KeyError):
        sched.delete_job("nonexistent")


# ── Group expansion tests ─────────────────────────────────────────────────────


def _simple_addr_catalog():
    return {
        "WebServers": {"type": "group", "detail": "2 members", "members": ["10.1.1.10/32", "10.1.1.11/32"]},
        "10.1.1.10/32": {"type": "ipmask", "detail": "10.1.1.10/32", "members": None},
        "10.1.1.11/32": {"type": "ipmask", "detail": "10.1.1.11/32", "members": None},
        "AllHosts": {"type": "group", "detail": "1 members", "members": ["WebServers"]},
    }


def test_build_addr_catalog_creates_leaf_entries():
    from app.rule_policy_scheduler import _build_addr_catalog
    addr_objects = [{"name": "Host1", "type": "ipmask", "subnet": "10.0.0.1 255.255.255.255"}]
    addr_groups = [{"name": "G1", "member": [{"name": "Host1"}]}]
    catalog = _build_addr_catalog(addr_objects, addr_groups)
    assert "Host1" in catalog
    assert catalog["Host1"]["members"] is None
    assert "G1" in catalog
    assert catalog["G1"]["members"] == ["Host1"]


def test_build_svc_catalog_creates_service_entries():
    from app.rule_policy_scheduler import _build_svc_catalog
    svc_objects = [{"name": "HTTP", "tcp-portrange": "80"}]
    svc_groups = [{"name": "Web-SG", "member": [{"name": "HTTP"}]}]
    catalog = _build_svc_catalog(svc_objects, svc_groups)
    assert "HTTP" in catalog
    assert catalog["HTTP"]["members"] is None
    assert "tcp/80" in catalog["HTTP"]["detail"]
    assert catalog["Web-SG"]["members"] == ["HTTP"]


def test_expand_group_returns_leaf_members():
    from app.rule_policy_scheduler import _expand_group
    catalog = _simple_addr_catalog()
    result = _expand_group("WebServers", catalog)
    assert len(result) == 2
    assert all(r["leaf"] and not r["cycle"] for r in result)
    names = {r["name"] for r in result}
    assert names == {"10.1.1.10/32", "10.1.1.11/32"}


def test_expand_group_handles_nested():
    from app.rule_policy_scheduler import _expand_group
    catalog = _simple_addr_catalog()
    result = _expand_group("AllHosts", catalog)
    assert len(result) == 2
    assert all(r["leaf"] for r in result)


def test_expand_group_detects_circular():
    from app.rule_policy_scheduler import _expand_group
    catalog = {
        "GA": {"type": "group", "detail": "", "members": ["GB"]},
        "GB": {"type": "group", "detail": "", "members": ["GA"]},
    }
    result = _expand_group("GA", catalog)
    assert any(r["cycle"] and r["reason"] == "circular" for r in result)


def test_expand_group_caps_max_depth():
    from app.rule_policy_scheduler import MAX_GROUP_DEPTH, _expand_group
    # Build chain of 10 nested groups (exceeds MAX_GROUP_DEPTH=8)
    catalog = {f"G{i}": {"type": "group", "detail": "", "members": [f"G{i+1}"]} for i in range(10)}
    catalog["G10"] = {"type": "ipmask", "detail": "1.1.1.1/32", "members": None}
    result = _expand_group("G0", catalog)
    # The node at depth MAX_GROUP_DEPTH (G8) must be the one capped, not a deeper one
    capped = [r for r in result if r["cycle"] and r["reason"] == "max_depth"]
    assert len(capped) == 1
    assert capped[0]["name"] == f"G{MAX_GROUP_DEPTH}"


def test_expand_group_diamond_no_false_cycle():
    from app.rule_policy_scheduler import _expand_group
    # Diamond: Root → A,B; A → Leaf; B → Leaf (same Leaf)
    catalog = {
        "Root": {"type": "group", "detail": "", "members": ["A", "B"]},
        "A": {"type": "group", "detail": "", "members": ["Leaf"]},
        "B": {"type": "group", "detail": "", "members": ["Leaf"]},
        "Leaf": {"type": "ipmask", "detail": "10.0.0.1/32", "members": None},
    }
    result = _expand_group("Root", catalog)
    # Leaf appears twice (once via A, once via B) but no cycle entry
    assert all(not r["cycle"] for r in result)
    assert len(result) == 2


def test_collect_groups_only_includes_groups():
    from app.rule_policy_scheduler import _collect_groups_from_rules
    addr_catalog = {
        "WebGrp": {"type": "group", "detail": "", "members": ["10.0.0.1/32"]},
        "10.0.0.1/32": {"type": "ipmask", "detail": "10.0.0.1/32", "members": None},
        "PlainHost": {"type": "ipmask", "detail": "10.0.0.2/32", "members": None},
    }
    svc_catalog = {}
    rules = [
        {"srcaddr": ["WebGrp"], "dstaddr": ["PlainHost"], "service": []},
    ]
    result = _collect_groups_from_rules(rules, addr_catalog, svc_catalog)
    assert "WebGrp" in result["addr"]
    assert "PlainHost" not in result["addr"]  # leaf, not a group


# ── Data fetch tests ──────────────────────────────────────────────────────────


def _make_rule(policyid=1, name="R1", logtraffic="all", hitcount=5):
    return {
        "policyid": policyid,
        "name": name,
        "status": "enable",
        "action": "accept",
        "nat": "disable",
        "logtraffic": logtraffic,
        "_hitcount": hitcount,
        "comments": "",
        "srcintf": [{"name": "port1"}],
        "dstintf": [{"name": "port2"}],
        "srcaddr": [{"name": "all"}],
        "dstaddr": [{"name": "all"}],
        "service": [{"name": "ALL"}],
    }


class _FakePkgClient:
    def __init__(self, rules=None, raise_on_policies=False):
        self._rules = rules if rules is not None else [_make_rule(1), _make_rule(2)]
        self._raise = raise_on_policies

    def get_policies(self, adom, pkg_path):
        if self._raise:
            raise RuntimeError("FMG timeout")
        return self._rules

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass


class _FakeBulkClient:
    def __init__(self, pkgs=None):
        self._pkgs = pkgs or [
            {"name": "pkg1", "path": "pkg1", "type": "pkg", "scope member": []},
            {"name": "pkg2", "path": "pkg2", "type": "pkg", "scope member": []},
        ]

    def get_policy_packages(self, adom):
        return self._pkgs

    def get_address_objects(self, adom, scope="all"):
        return []

    def get_address_groups(self, adom, scope="all"):
        return []

    def get_vip_objects(self, adom):
        return []

    def get_service_objects(self, adom, scope="all"):
        return []

    def get_service_groups(self, adom, scope="all"):
        return []

    def get_policies(self, adom, pkg_path):
        return []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass


def test_policy_for_pkg_success(monkeypatch):
    from app.rule_policy_scheduler import _policy_for_pkg
    fake = _FakePkgClient(rules=[_make_rule(1), _make_rule(2)])
    monkeypatch.setattr("app.rule_policy_scheduler._make_client", lambda: fake)
    pkg = {"name": "Corp", "path": "Corp", "scope member": []}
    catalogs = {"addr_catalog": {}, "svc_catalog": {}}
    result = _policy_for_pkg("ADOM", pkg, catalogs, False)
    assert result["error"] is None
    assert result["total_rules"] == 3  # 2 real rules + 1 implicit deny
    assert len(result["rules"]) == 3
    r0 = result["rules"][0]
    assert r0["policyid"] == 1
    assert isinstance(r0["srcintf"], list)
    assert isinstance(r0["srcaddr"], list)
    assert isinstance(r0["service"], list)
    implicit = result["rules"][-1]
    assert implicit.get("implicit") is True
    assert implicit["action"] == "deny"
    assert implicit["policyid"] == "implicit"


def test_policy_for_pkg_error(monkeypatch):
    from app.rule_policy_scheduler import _policy_for_pkg
    fake = _FakePkgClient(raise_on_policies=True)
    monkeypatch.setattr("app.rule_policy_scheduler._make_client", lambda: fake)
    pkg = {"name": "Corp", "path": "Corp", "scope member": []}
    catalogs = {"addr_catalog": {}, "svc_catalog": {}}
    result = _policy_for_pkg("ADOM", pkg, catalogs, False)
    assert result["error"] is not None
    assert "FMG timeout" in result["error"]
    assert result["rules"] == []


def test_bulk_policy_adom_all_packages(monkeypatch):
    from app.rule_policy_scheduler import bulk_policy_adom
    fake = _FakeBulkClient()
    monkeypatch.setattr("app.rule_policy_scheduler._make_client", lambda: fake)
    out = bulk_policy_adom("ADOM", [], False, False, 1)
    results = out["results"]
    skipped = out["skipped"]
    assert len(results) == 2
    assert skipped == []
    assert out["adom"] == "ADOM"
    assert "generated_at" in out


def test_bulk_policy_adom_filter_packages(monkeypatch):
    from app.rule_policy_scheduler import bulk_policy_adom
    fake = _FakeBulkClient()
    monkeypatch.setattr("app.rule_policy_scheduler._make_client", lambda: fake)
    out = bulk_policy_adom("ADOM", ["pkg1"], False, False, 1)
    results = out["results"]
    skipped = out["skipped"]
    assert len(results) == 1
    assert results[0]["package"] == "pkg1"
    assert skipped == []


def test_bulk_policy_adom_skipped(monkeypatch):
    from app.rule_policy_scheduler import bulk_policy_adom
    fake = _FakeBulkClient()
    monkeypatch.setattr("app.rule_policy_scheduler._make_client", lambda: fake)
    out = bulk_policy_adom("ADOM", ["pkg1", "missing"], False, False, 1)
    results = out["results"]
    skipped = out["skipped"]
    assert len(results) == 1
    assert len(skipped) == 1
    assert "missing" in skipped[0]


# ── Report builder tests ──────────────────────────────────────────────────────


def _sample_result():
    return {
        "package": "Corp/Policy", "package_name": "Policy", "device": "FW-01",
        "scope_members": [{"name": "FW-01", "vdom": "root"}],
        "rules": [
            {
                "seq": 1, "policyid": 1, "name": "Allow-Web", "status": "enable",
                "srcintf": ["port1"], "dstintf": ["port2"],
                "srcaddr": ["CorpUsers"], "dstaddr": ["WebServers"],
                "service": ["HTTP-SG"],
                "action": "accept", "nat": "enable", "logtraffic": "all",
                "hit_count": 42, "hit_count_source": "cached",
                "comments": "Allow web",
            },
            {
                "seq": 2, "policyid": 2, "name": "Stealth", "status": "disable",
                "srcintf": ["any"], "dstintf": ["any"],
                "srcaddr": ["all"], "dstaddr": ["all"], "service": ["ALL"],
                "action": "deny", "nat": "disable", "logtraffic": "disable",
                "hit_count": None, "hit_count_source": "disabled",
                "comments": "",
            },
        ],
        "group_details": {
            "addr": {
                "CorpUsers": [{"name": "10.0.0.0/8", "leaf": True, "cycle": False, "detail": "10.0.0.0/8"}],
            },
            "svc": {
                "HTTP-SG": [{"name": "HTTP", "leaf": True, "cycle": False, "detail": "tcp/80"}],
            },
        },
        "pulled_at": "2026-09-18T02:00:00Z",
        "total_rules": 2,
        "error": None,
        "hit_count_note": "FMG-cached (may be stale)",
    }


def test_build_attachment_html_contains_rule_rows():
    from app.rule_policy_scheduler import _build_attachment_rp
    files = _build_attachment_rp(_sample_result(), {}, "html")
    assert len(files) == 1
    fname, data = files[0]
    assert fname.endswith(".html")
    html = data.decode()
    assert "Allow-Web" in html
    assert "Rule Details" in html
    assert "Group Details" in html


def test_build_attachment_html_greyed_hit_count_disabled():
    from app.rule_policy_scheduler import _build_attachment_rp
    _, data = _build_attachment_rp(_sample_result(), {}, "html")[0]
    html = data.decode()
    assert "Disabled" in html  # hit_count_source=disabled rendered as "Disabled"


def test_build_attachment_csv_returns_two_files():
    from app.rule_policy_scheduler import _build_attachment_rp
    files = _build_attachment_rp(_sample_result(), {}, "csv")
    assert len(files) == 2
    fnames = {f[0] for f in files}
    assert any("rules" in n or n.endswith(("_rules.csv", ".csv")) for n in fnames)
    assert any("groups" in n for n in fnames)


def test_build_attachment_csv_rules_has_correct_columns():
    from app.rule_policy_scheduler import _build_attachment_rp
    files = _build_attachment_rp(_sample_result(), {}, "csv")
    rules_file = next(f for f in files if "group" not in f[0])
    import csv as _csv
    import io as _io
    rows = list(_csv.reader(_io.StringIO(rules_file[1].decode())))
    header_row = next(r for r in rows if "Policy ID" in r or "policyid" in r or "Seq" in r)
    assert any("Hit" in c or "hit" in c for c in header_row)


def test_build_attachment_json_has_required_keys():
    from app.rule_policy_scheduler import _build_attachment_rp
    files = _build_attachment_rp(_sample_result(), {}, "json")
    assert len(files) == 1
    payload = json.loads(files[0][1])
    assert "rules" in payload
    assert "group_details" in payload
    assert "package_name" in payload


def test_build_summary_html_shows_counts():
    from app.rule_policy_scheduler import _build_summary_html
    results = [_sample_result()]
    html = _build_summary_html("Corp", results, ["MissingPkg"], "2026-09-18T02:00:00Z")
    assert "Corp" in html
    assert "MissingPkg" in html
    assert "2 rules" in html or "total_rules" in html or "2" in html


def test_make_zip_contains_all_files():
    import io as _io
    import zipfile as _zipfile

    from app.rule_policy_scheduler import _make_zip
    attachments = [
        ("file1.html", b"<html>test1</html>"),
        ("file2.csv", b"col1,col2\nval1,val2"),
    ]
    data = _make_zip(attachments)
    assert len(data) > 0
    with _zipfile.ZipFile(_io.BytesIO(data)) as zf:
        names = zf.namelist()
    assert "file1.html" in names
    assert "file2.csv" in names


# ── APScheduler trigger tests ─────────────────────────────────────────────────


def test_make_trigger_daily():
    from apscheduler.triggers.cron import CronTrigger

    from app.rule_policy_scheduler import _make_trigger
    job = {**_valid_weekly(), "schedule_type": "daily", "time": "03:30"}
    trigger = _make_trigger(job)
    assert isinstance(trigger, CronTrigger)
    fields = {f.name: str(f) for f in trigger.fields}
    assert fields["hour"] == "3"
    assert fields["minute"] == "30"
    assert fields["day_of_week"] == "*"


def test_make_trigger_weekly():
    from apscheduler.triggers.cron import CronTrigger

    from app.rule_policy_scheduler import _make_trigger
    job = {**_valid_weekly(), "schedule_type": "weekly", "days_of_week": ["MON", "FRI"], "time": "02:00"}
    trigger = _make_trigger(job)
    assert isinstance(trigger, CronTrigger)
    fields = {f.name: str(f) for f in trigger.fields}
    assert "mon" in fields["day_of_week"]
    assert "fri" in fields["day_of_week"]


def test_make_trigger_monthly_end():
    from apscheduler.triggers.cron import CronTrigger

    from app.rule_policy_scheduler import _make_trigger
    job = {**_valid_weekly(), "schedule_type": "monthly", "monthly_position": "end", "time": "01:00"}
    trigger = _make_trigger(job)
    assert isinstance(trigger, CronTrigger)
    fields = {f.name: str(f) for f in trigger.fields}
    assert fields["day"] == "last"


def test_make_trigger_monthly_beginning():
    from app.rule_policy_scheduler import _make_trigger
    job = {"schedule_type": "monthly", "monthly_position": "beginning", "time": "03:00"}
    t = _make_trigger(job)
    assert t is not None


def test_execute_job_records_run(monkeypatch, tmp_jobs):
    fake_bulk_result = {
        "adom": "Corp",
        "results": [],
        "skipped": [],
        "generated_at": "2026-09-18T02:00:00Z",
    }
    monkeypatch.setattr(sched, "_bulk_policy_adom", lambda *a, **kw: fake_bulk_result)
    monkeypatch.setattr(sched, "_build_all_attachments", lambda *a, **kw: [])
    monkeypatch.setattr(sched, "_make_zip", lambda *a: b"")
    monkeypatch.setattr(sched, "_send_email", lambda *a, **kw: None)

    job = sched.create_job(_valid_weekly())
    sched._execute_job(job["id"])

    jobs = sched.get_all_jobs()
    assert len(jobs) == 1
    runs = jobs[0].get("runs", [])
    assert len(runs) == 1
    assert runs[0]["status"] == "ok"
    assert runs[0]["emails_sent"] >= 1


def test_execute_job_not_found(tmp_jobs):
    # Should not raise; no run should be recorded because the job doesn't exist
    sched._execute_job("nonexistent")
    jobs = sched.get_all_jobs()
    assert jobs == []
