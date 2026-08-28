import csv
import io
import json
import datetime
import pytest
from unittest.mock import patch, MagicMock


@pytest.fixture
def jobs_path(tmp_path, monkeypatch):
    p = tmp_path / "device_review_jobs.json"
    monkeypatch.setattr("app.device_review_scheduler._JOBS_PATH", p)
    return p


def test_get_all_jobs_empty(jobs_path):
    from app import device_review_scheduler as sched
    assert sched.get_all_jobs() == []


def test_create_job_assigns_id(jobs_path):
    from app import device_review_scheduler as sched
    job = sched.create_job({
        "name": "Test Job",
        "adom": "TEST",
        "days_of_week": ["MON"],
        "time": "06:00",
        "checks": [],
        "check_params": {},
        "format": "pdf",
        "email": "x@x.com",
        "enabled": True,
    })
    assert "id" in job
    assert len(sched.get_all_jobs()) == 1


def test_create_job_persists_all_fields(jobs_path):
    from app import device_review_scheduler as sched
    job = sched.create_job({
        "name": "CIS Audit",
        "adom": "Enterprise",
        "days_of_week": ["MON", "FRI"],
        "time": "02:00",
        "checks": ["ntp_config", "trusted_hosts"],
        "check_params": {"ntp_config": {"expected_servers": "10.1.1.1"}},
        "format": "csv",
        "email": "alice@corp.com, bob@corp.com",
        "enabled": True,
    })
    stored = sched.get_all_jobs()[0]
    assert stored["name"] == "CIS Audit"
    assert stored["checks"] == ["ntp_config", "trusted_hosts"]
    assert stored["check_params"] == {"ntp_config": {"expected_servers": "10.1.1.1"}}
    assert stored["email"] == "alice@corp.com, bob@corp.com"
    assert stored["days_of_week"] == ["MON", "FRI"]


def test_update_job(jobs_path):
    from app import device_review_scheduler as sched
    job = sched.create_job({
        "name": "Old Name", "adom": "TEST", "days_of_week": ["MON"],
        "time": "06:00", "checks": [], "check_params": {},
        "format": "pdf", "email": "x@x.com", "enabled": True,
    })
    updated = sched.update_job(job["id"], {**job, "email": "new@x.com", "name": "New Name"})
    assert updated["email"] == "new@x.com"
    assert updated["name"] == "New Name"
    assert sched.get_all_jobs()[0]["email"] == "new@x.com"


def test_delete_job(jobs_path):
    from app import device_review_scheduler as sched
    job = sched.create_job({
        "name": "Test", "adom": "TEST", "days_of_week": ["MON"],
        "time": "06:00", "checks": [], "check_params": {},
        "format": "pdf", "email": "x@x.com", "enabled": True,
    })
    sched.delete_job(job["id"])
    assert sched.get_all_jobs() == []


def test_delete_job_unknown_raises(jobs_path):
    from app import device_review_scheduler as sched
    with pytest.raises(KeyError):
        sched.delete_job("nonexistent-id")


def test_validate_empty_days(jobs_path):
    from app import device_review_scheduler as sched
    with pytest.raises(ValueError, match="days_of_week"):
        sched.create_job({
            "name": "T", "adom": "TEST", "days_of_week": [], "time": "06:00",
            "checks": [], "check_params": {}, "format": "pdf",
            "email": "x@x.com", "enabled": True,
        })


def test_validate_invalid_day_code(jobs_path):
    from app import device_review_scheduler as sched
    with pytest.raises(ValueError, match="days_of_week"):
        sched.create_job({
            "name": "T", "adom": "TEST", "days_of_week": ["MONDAY"], "time": "06:00",
            "checks": [], "check_params": {}, "format": "pdf",
            "email": "x@x.com", "enabled": True,
        })


def test_validate_bad_time_format(jobs_path):
    from app import device_review_scheduler as sched
    with pytest.raises(ValueError, match="time"):
        sched.create_job({
            "name": "T", "adom": "TEST", "days_of_week": ["MON"], "time": "6am",
            "checks": [], "check_params": {}, "format": "pdf",
            "email": "x@x.com", "enabled": True,
        })


def test_is_job_running_false_initially(jobs_path):
    from app import device_review_scheduler as sched
    assert sched.is_job_running("any-id") is False


def test_prune_old_runs(jobs_path):
    from app import device_review_scheduler as sched
    old_ts = (datetime.datetime.utcnow() - datetime.timedelta(days=40)).isoformat() + "Z"
    recent_ts = datetime.datetime.utcnow().isoformat() + "Z"
    job = sched.create_job({
        "name": "T", "adom": "TEST", "days_of_week": ["MON"], "time": "06:00",
        "checks": [], "check_params": {}, "format": "pdf",
        "email": "x@x.com", "enabled": True,
    })
    jobs = json.loads(jobs_path.read_text())
    jobs[0]["runs"] = [
        {"ran_at": old_ts, "status": "ok", "devices_total": 1, "devices_reviewed": 1,
         "total_findings": 5, "fail_count": 1},
        {"ran_at": recent_ts, "status": "ok", "devices_total": 2, "devices_reviewed": 2,
         "total_findings": 3, "fail_count": 0},
    ]
    jobs_path.write_text(json.dumps(jobs))
    sched._prune_runs(job["id"], retention_days=30)
    remaining = sched.get_all_jobs()[0]["runs"]
    assert len(remaining) == 1
    assert remaining[0]["ran_at"] == recent_ts


def test_execute_job_sends_email(jobs_path, monkeypatch):
    from app import device_review_scheduler as sched

    fake_meta = [
        {"key": "trusted_hosts", "name": "Trusted Hosts on Admin Accounts (CIS)",
         "description": "Check trusted hosts"},
    ]
    monkeypatch.setattr("app.device_review_scheduler._CHECKS_META", fake_meta)

    job = sched.create_job({
        "name": "T", "adom": "CorpADOM", "days_of_week": ["MON"], "time": "06:00",
        "checks": ["trusted_hosts"], "check_params": {},
        "format": "pdf", "email": "test@corp.com", "enabled": True,
    })

    fake_results = [
        {"device": "fw-01", "ip": "10.0.0.1",
         "rows": [{"device": "fw-01", "check": "Trusted Hosts on Admin Accounts (CIS)",
                   "result": "PASS", "interface": "system", "vdom": "root",
                   "ip": "", "detail": "All admins have trusted hosts",
                   "protocols": [], "has_insecure": False, "has_secure": False}],
         "error": None},
    ]

    sent = {}

    def fake_bulk(adom, checks, check_params, max_workers=4):
        return fake_results

    def fake_send(to, subject, body_html, attachments):
        sent["to"] = to
        sent["subject"] = subject
        sent["attachments"] = attachments

    monkeypatch.setattr(
        "app.device_review_scheduler._bulk_device_review_adom", fake_bulk
    )
    monkeypatch.setattr("app.device_review_scheduler._send_email", fake_send)

    sched._execute_job(job["id"])

    assert sent["to"] == "test@corp.com"
    assert "CorpADOM" in sent["subject"]
    assert len(sent["attachments"]) == 1


def test_execute_job_check_summary_in_email_body(jobs_path, monkeypatch):
    """_execute_job passes check_summary to the email body builder."""
    import app.device_review_scheduler as sched

    fake_meta = [
        {"key": "trusted_hosts", "name": "Trusted Hosts on Admin Accounts (CIS)",
         "description": "Check trusted hosts"},
    ]
    monkeypatch.setattr("app.device_review_scheduler._CHECKS_META", fake_meta)

    job = sched.create_job({
        "name": "T", "adom": "CorpADOM", "days_of_week": ["MON"], "time": "06:00",
        "checks": ["trusted_hosts"], "check_params": {},
        "format": "pdf", "email": "test@corp.com", "enabled": True,
    })

    fake_results = [
        {"device": "fw-01", "ip": "10.0.0.1",
         "rows": [{"device": "fw-01",
                   "check": "Trusted Hosts on Admin Accounts (CIS)",
                   "result": "PASS", "interface": "system", "vdom": "root",
                   "ip": "", "detail": "ok", "protocols": [],
                   "has_insecure": False, "has_secure": False}],
         "error": None},
    ]

    sent = {}

    monkeypatch.setattr(
        "app.device_review_scheduler._bulk_device_review_adom",
        lambda *a, **kw: fake_results,
    )
    monkeypatch.setattr(
        "app.device_review_scheduler._send_email",
        lambda to, subject, body_html, attachments: sent.update({"body": body_html}),
    )

    sched._execute_job(job["id"])

    assert "Check Summary" in sent["body"]
    assert "Trusted Hosts on Admin Accounts (CIS)" in sent["body"]
    assert "Check trusted hosts" in sent["body"]


def test_execute_job_persists_device_review_rollup(jobs_path, monkeypatch, tmp_path):
    from app import device_review_scheduler as sched
    import app.device_review_rollup as dr_rollup

    monkeypatch.setattr(dr_rollup, "_ROLLUP_PATH", tmp_path / "device_review_rollup.json")

    fake_meta = [
        {"key": "default_admin", "name": "Default 'admin' Account (CIS)",
         "description": "Check default admin account"},
    ]
    monkeypatch.setattr("app.device_review_scheduler._CHECKS_META", fake_meta)

    job = sched.create_job({
        "name": "T", "adom": "Customer1", "days_of_week": ["MON"], "time": "06:00",
        "checks": [], "check_params": {},
        "format": "pdf", "email": "test@corp.com", "enabled": True,
    })
    fake_results = [
        {"device": "fw-01", "ip": "10.0.0.1", "error": None, "rows": [
            {"device": "fw-01", "interface": "", "vdom": "root", "ip": "10.0.0.1",
             "type": "system", "status": "", "check": "Default 'admin' Account (CIS)",
             "result": "FAIL", "detail": "", "protocols": [], "has_insecure": False, "has_secure": False},
        ]},
    ]
    monkeypatch.setattr(
        "app.device_review_scheduler._bulk_device_review_adom",
        lambda adom, checks, check_params, max_workers=4: fake_results,
    )
    monkeypatch.setattr(
        "app.device_review_scheduler._send_email",
        lambda to, subject, body_html, attachments: None,
    )

    sched._execute_job(job["id"])

    latest = dr_rollup.get_latest()
    assert latest is not None
    assert latest["devices_reviewed"] == 1
    assert latest["devices_with_failures"] == 1


def test_execute_job_appends_run_record(jobs_path, monkeypatch):
    from app import device_review_scheduler as sched

    job = sched.create_job({
        "name": "T", "adom": "CorpADOM", "days_of_week": ["MON"], "time": "06:00",
        "checks": [], "check_params": {}, "format": "pdf",
        "email": "test@corp.com", "enabled": True,
    })

    monkeypatch.setattr(
        "app.device_review_scheduler._bulk_device_review_adom",
        lambda *a, **kw: [],
    )
    monkeypatch.setattr(
        "app.device_review_scheduler._send_email",
        lambda *a, **kw: None,
    )

    sched._execute_job(job["id"])

    runs = sched.get_all_jobs()[0]["runs"]
    assert len(runs) == 1
    assert runs[0]["status"] == "ok"
    assert "ran_at" in runs[0]


def test_build_attachment_json(jobs_path):
    from app import device_review_scheduler as sched
    rows = [{"device": "fw-01", "check": "NTP", "result": "PASS",
             "interface": "system", "vdom": "root", "ip": "", "detail": "ok",
             "protocols": [], "has_insecure": False, "has_secure": False}]
    results = [{"device": "fw-01", "ip": "10.0.0.1", "rows": rows, "error": None}]
    att = sched._build_attachment_dr("Corp", "json", results, "2026-08-01T00:00:00Z", [])
    data = json.loads(att["data"])
    assert data["adom"] == "Corp"
    assert data["exported_at"] == "2026-08-01T00:00:00Z"
    assert len(data["rows"]) == 1


def test_build_attachment_csv(jobs_path):
    from app import device_review_scheduler as sched
    rows = [{"device": "fw-01", "check": "NTP", "result": "PASS",
             "interface": "system", "vdom": "root", "ip": "", "detail": "ok",
             "protocols": [], "has_insecure": False, "has_secure": False}]
    results = [{"device": "fw-01", "ip": "10.0.0.1", "rows": rows, "error": None}]
    att = sched._build_attachment_dr("Corp", "csv", results, "2026-08-01T00:00:00Z", [])
    text = att["data"].decode()
    assert "Corp" in text
    assert "fw-01" in text
    assert "PASS" in text


def test_build_attachment_pdf_html(jobs_path):
    from app import device_review_scheduler as sched
    rows = [{"device": "fw-01", "check": "NTP", "result": "FAIL",
             "interface": "system", "vdom": "root", "ip": "", "detail": "No NTP",
             "protocols": [], "has_insecure": False, "has_secure": False}]
    results = [{"device": "fw-01", "ip": "10.0.0.1", "rows": rows, "error": None}]
    att = sched._build_attachment_dr("Corp", "pdf", results, "2026-08-01T00:00:00Z", [])
    html = att["data"].decode()
    assert "Corp" in html
    assert "4THealth+" in html
    assert "fw-01" in html


# ── _build_host_summary_html ──────────────────────────────────────────────────

def _make_results(device_rows: dict[str, list[dict]]) -> list[dict]:
    """Helper: build a results list from {device: [rows]} dict."""
    return [
        {"device": dev, "rows": rows}
        for dev, rows in device_rows.items()
    ]


def test_host_summary_html_columns():
    """All seven result columns appear in the output."""
    from app.device_review_scheduler import _build_host_summary_html
    results = _make_results({"FW1": [
        {"result": "PASS", "check": "NTP"},
        {"result": "FAIL", "check": "NTP"},
        {"result": "INSECURE", "check": "Interface Protocols"},
        {"result": "WARN", "check": "Interface Protocols"},
        {"result": "CONFIG_MISSING", "check": "NTP"},
        {"result": "INFO", "check": "Interface Protocols"},
    ]})
    html = _build_host_summary_html(results)
    for col in ("PASS", "FAIL", "INSECURE", "WARN", "CONFIG_MISSING", "INFO", "Total"):
        assert col in html


def test_host_summary_html_counts_correct():
    """Row counts match the input data."""
    from app.device_review_scheduler import _build_host_summary_html
    results = _make_results({"FW1": [
        {"result": "PASS"}, {"result": "PASS"}, {"result": "FAIL"},
    ]})
    html = _build_host_summary_html(results)
    assert "FW1" in html
    # Total = 3
    assert ">3<" in html


def test_host_summary_html_totals_row():
    """A Totals footer row is present."""
    from app.device_review_scheduler import _build_host_summary_html
    results = _make_results({
        "FW1": [{"result": "PASS"}, {"result": "FAIL"}],
        "FW2": [{"result": "PASS"}],
    })
    html = _build_host_summary_html(results)
    assert "Totals" in html
    assert ">2<" in html   # PASS total across both devices
    assert ">1<" in html   # FAIL total
    assert ">3<" in html   # grand total


def test_host_summary_html_sorted_devices():
    """Devices are listed alphabetically."""
    from app.device_review_scheduler import _build_host_summary_html
    results = _make_results({
        "ZFW": [{"result": "PASS"}],
        "AFW": [{"result": "PASS"}],
    })
    html = _build_host_summary_html(results)
    assert html.index("AFW") < html.index("ZFW")


def test_host_summary_html_error_device():
    """Devices with errors show (error) annotation."""
    from app.device_review_scheduler import _build_host_summary_html
    results = [{"device": "FW1", "rows": [], "error": "timeout"}]
    html = _build_host_summary_html(results)
    assert "error" in html.lower()
    assert "FW1" in html


def test_build_summary_html_includes_host_section():
    """_build_summary_html output contains both check summary and host summary sections."""
    from app.device_review_scheduler import _build_summary_html
    results = _make_results({"FW1": [
        {"result": "PASS", "check": "NTP Configuration"},
    ]})
    html = _build_summary_html("TESTADOM", results, "2026-08-03T01:00:00Z", [])
    assert "Host Summary" in html
    assert "Check Summary" in html


# ── Attachment host summaries ─────────────────────────────────────────────────

def _make_results_with_rows() -> list[dict]:
    return [
        {"device": "FW1", "rows": [
            {"result": "PASS", "check": "NTP Configuration", "interface": "system",
             "vdom": "root", "ip": "", "detail": "ok", "protocols": []},
            {"result": "WARN", "check": "Interface Protocols", "interface": "mgmt",
             "vdom": "root", "ip": "10.0.0.1/24", "detail": "", "protocols": [{"name": "ping", "secure": None}]},
        ]},
        {"device": "FW2", "rows": [
            {"result": "FAIL", "check": "NTP Configuration", "interface": "system",
             "vdom": "root", "ip": "", "detail": "no ntp", "protocols": []},
        ]},
    ]


def test_json_attachment_has_host_summary():
    """JSON attachment includes 'host_summary' key before 'rows'."""
    from app.device_review_scheduler import _build_attachment_dr
    att = _build_attachment_dr("TESTADOM", "json", _make_results_with_rows(), "2026-08-03T01:00:00Z", [])
    data = json.loads(att["data"])
    assert "host_summary" in data
    assert isinstance(data["host_summary"], list)
    assert len(data["host_summary"]) == 2
    fw1 = next(h for h in data["host_summary"] if h["device"] == "FW1")
    assert fw1["counts"]["PASS"] == 1
    assert fw1["counts"]["WARN"] == 1
    assert fw1["total"] == 2


def test_json_attachment_host_summary_before_rows():
    """'host_summary' key appears before 'rows' in JSON output."""
    from app.device_review_scheduler import _build_attachment_dr
    att = _build_attachment_dr("TESTADOM", "json", _make_results_with_rows(), "2026-08-03T01:00:00Z", [])
    raw = att["data"].decode()
    assert raw.index("host_summary") < raw.index('"rows"')


def test_csv_attachment_has_host_summary_comments():
    """CSV attachment includes host summary comment lines before data rows."""
    from app.device_review_scheduler import _build_attachment_dr
    att = _build_attachment_dr("TESTADOM", "csv", _make_results_with_rows(), "2026-08-03T01:00:00Z", [])
    text = att["data"].decode()
    assert "# Host Summary" in text
    assert "FW1" in text
    assert "FW2" in text


def test_html_attachment_has_host_summary_table():
    """HTML attachment includes 'Host Summary' heading and table before findings."""
    from app.device_review_scheduler import _build_attachment_dr
    att = _build_attachment_dr("TESTADOM", "pdf", _make_results_with_rows(), "2026-08-03T01:00:00Z", [])
    html = att["data"].decode()
    assert "Host Summary" in html
    assert html.index("Host Summary") < html.index("Findings")


# ── _build_check_summary ──────────────────────────────────────────────────────

def test_check_summary_counts_all_result_types(monkeypatch):
    """Each result type gets its own count; no collapsing."""
    import app.device_review_scheduler as sched
    fake_meta = [
        {"key": "ntp_config", "name": "NTP Configuration", "description": "Check NTP servers"},
        {"key": "syslog_config", "name": "Syslog Configuration", "description": "Check syslog"},
    ]
    monkeypatch.setattr("app.device_review_scheduler._CHECKS_META", fake_meta)
    results = [{"device": "FW1", "rows": [
        {"check": "NTP Configuration", "result": "PASS"},
        {"check": "NTP Configuration", "result": "FAIL"},
        {"check": "NTP Configuration", "result": "INSECURE"},
        {"check": "NTP Configuration", "result": "WARN"},
        {"check": "NTP Configuration", "result": "CONFIG_MISSING"},
        {"check": "NTP Configuration", "result": "INFO"},
        {"check": "Syslog Configuration", "result": "PASS"},
    ]}]
    summary = sched._build_check_summary(results, [])
    ntp = next(c for c in summary if c["key"] == "ntp_config")
    assert ntp["PASS"] == 1
    assert ntp["FAIL"] == 1
    assert ntp["INSECURE"] == 1
    assert ntp["WARN"] == 1
    assert ntp["CONFIG_MISSING"] == 1
    assert ntp["INFO"] == 1
    syslog = next(c for c in summary if c["key"] == "syslog_config")
    assert syslog["PASS"] == 1


def test_check_summary_filters_to_checks_ran(monkeypatch):
    """Only checks in checks_ran appear when checks_ran is non-empty."""
    import app.device_review_scheduler as sched
    fake_meta = [
        {"key": "ntp_config", "name": "NTP Configuration", "description": "Check NTP"},
        {"key": "syslog_config", "name": "Syslog Configuration", "description": "Check syslog"},
    ]
    monkeypatch.setattr("app.device_review_scheduler._CHECKS_META", fake_meta)
    results = [{"device": "FW1", "rows": [
        {"check": "NTP Configuration", "result": "PASS"},
        {"check": "Syslog Configuration", "result": "FAIL"},
    ]}]
    summary = sched._build_check_summary(results, ["ntp_config"])
    assert len(summary) == 1
    assert summary[0]["key"] == "ntp_config"


def test_check_summary_empty_checks_ran_means_all(monkeypatch):
    """Empty checks_ran includes all checks from CHECKS_META."""
    import app.device_review_scheduler as sched
    fake_meta = [
        {"key": "ntp_config", "name": "NTP Configuration", "description": "Check NTP"},
        {"key": "syslog_config", "name": "Syslog Configuration", "description": "Check syslog"},
    ]
    monkeypatch.setattr("app.device_review_scheduler._CHECKS_META", fake_meta)
    results = []
    summary = sched._build_check_summary(results, [])
    assert len(summary) == 2


def test_check_summary_zero_counts_for_unmatched_check(monkeypatch):
    """A check that ran but produced no rows still appears with all-zero counts."""
    import app.device_review_scheduler as sched
    fake_meta = [
        {"key": "ntp_config", "name": "NTP Configuration", "description": "Check NTP"},
    ]
    monkeypatch.setattr("app.device_review_scheduler._CHECKS_META", fake_meta)
    results = [{"device": "FW1", "rows": []}]
    summary = sched._build_check_summary(results, ["ntp_config"])
    assert summary[0]["PASS"] == 0
    assert summary[0]["FAIL"] == 0


def test_check_summary_preserves_checks_meta_order(monkeypatch):
    """Output order matches CHECKS_META declaration order, not row order."""
    import app.device_review_scheduler as sched
    fake_meta = [
        {"key": "aaa", "name": "AAA Check", "description": "first"},
        {"key": "bbb", "name": "BBB Check", "description": "second"},
        {"key": "ccc", "name": "CCC Check", "description": "third"},
    ]
    monkeypatch.setattr("app.device_review_scheduler._CHECKS_META", fake_meta)
    results = [{"device": "FW1", "rows": [
        {"check": "CCC Check", "result": "PASS"},
        {"check": "AAA Check", "result": "PASS"},
    ]}]
    summary = sched._build_check_summary(results, [])
    assert [c["key"] for c in summary] == ["aaa", "bbb", "ccc"]


# ── _build_summary_html check summary section ─────────────────────────────────

def _make_check_summary_fixture():
    return [
        {"key": "ntp_config", "name": "NTP Configuration", "description": "Check NTP servers",
         "PASS": 3, "INFO": 0, "WARN": 1, "CONFIG_MISSING": 0, "FAIL": 1, "INSECURE": 0},
        {"key": "interface_protocols", "name": "Interface Protocols", "description": "Cleartext check",
         "PASS": 0, "INFO": 2, "WARN": 0, "CONFIG_MISSING": 0, "FAIL": 0, "INSECURE": 1},
    ]


def test_summary_html_check_summary_above_host_summary():
    """Check Summary section appears before Host Summary in email body."""
    from app.device_review_scheduler import _build_summary_html
    results = [{"device": "FW1", "rows": [{"result": "PASS", "check": "NTP Configuration"}]}]
    html = _build_summary_html("ADOM", results, "2026-08-04T00:00:00Z", _make_check_summary_fixture())
    assert "Check Summary" in html
    assert "Host Summary" in html
    assert html.index("Check Summary") < html.index("Host Summary")


def test_summary_html_check_summary_has_6_columns():
    """Check summary table has all 6 result-type columns in correct order."""
    from app.device_review_scheduler import _build_summary_html
    results = []
    html = _build_summary_html("ADOM", results, "2026-08-04T00:00:00Z", _make_check_summary_fixture())
    cols = ("PASS", "INFO", "WARN", "CONFIG_MISSING", "FAIL", "INSECURE")
    # All columns present
    for col in cols:
        assert col in html
    # Columns in correct order: PASS | INFO | WARN | CONFIG_MISSING | FAIL | INSECURE
    for a, b in zip(cols, cols[1:]):
        assert html.index(a) < html.index(b), f"{a} should appear before {b}"


def test_summary_html_check_summary_shows_description():
    """Check summary table includes the check description."""
    from app.device_review_scheduler import _build_summary_html
    results = []
    html = _build_summary_html("ADOM", results, "2026-08-04T00:00:00Z", _make_check_summary_fixture())
    assert "Check NTP servers" in html
    assert "Cleartext check" in html


def test_summary_html_check_summary_shows_counts():
    """Check summary table renders non-zero counts."""
    from app.device_review_scheduler import _build_summary_html
    results = []
    html = _build_summary_html("ADOM", results, "2026-08-04T00:00:00Z", _make_check_summary_fixture())
    # NTP row: PASS=3, WARN=1, FAIL=1
    assert ">3<" in html
    # Interface Protocols: INSECURE=1, INFO=2
    assert ">2<" in html
    assert ">1<" in html


# ── Attachment check summary ───────────────────────────────────────────────────

def _make_check_summary_for_attachments():
    return [
        {"key": "ntp_config", "name": "NTP Configuration", "description": "Check NTP",
         "PASS": 2, "INFO": 0, "WARN": 1, "CONFIG_MISSING": 0, "FAIL": 1, "INSECURE": 0},
    ]


def test_json_attachment_has_check_summary_before_host_summary():
    """JSON attachment includes 'check_summary' key before 'host_summary'."""
    from app.device_review_scheduler import _build_attachment_dr
    att = _build_attachment_dr(
        "TESTADOM", "json", _make_results_with_rows(), "2026-08-04T00:00:00Z",
        _make_check_summary_for_attachments()
    )
    data = json.loads(att["data"])
    assert "check_summary" in data
    raw = att["data"].decode()
    assert raw.index("check_summary") < raw.index('"host_summary"')


def test_json_attachment_check_summary_structure():
    """check_summary entries have name, description, and all 6 result counts."""
    from app.device_review_scheduler import _build_attachment_dr
    att = _build_attachment_dr(
        "TESTADOM", "json", [], "2026-08-04T00:00:00Z",
        _make_check_summary_for_attachments()
    )
    data = json.loads(att["data"])
    entry = data["check_summary"][0]
    assert entry["name"] == "NTP Configuration"
    assert entry["description"] == "Check NTP"
    for col in ("PASS", "INFO", "WARN", "CONFIG_MISSING", "FAIL", "INSECURE"):
        assert col in entry


def test_csv_attachment_has_check_summary_before_host_summary():
    """CSV attachment has # Check Summary comment block before # Host Summary."""
    from app.device_review_scheduler import _build_attachment_dr
    att = _build_attachment_dr(
        "TESTADOM", "csv", _make_results_with_rows(), "2026-08-04T00:00:00Z",
        _make_check_summary_for_attachments()
    )
    text = att["data"].decode()
    assert "# Check Summary" in text
    assert "# Host Summary" in text
    assert text.index("# Check Summary") < text.index("# Host Summary")


def test_csv_attachment_check_summary_contains_check_name():
    """CSV check summary comment rows include the check name."""
    from app.device_review_scheduler import _build_attachment_dr
    att = _build_attachment_dr(
        "TESTADOM", "csv", [], "2026-08-04T00:00:00Z",
        _make_check_summary_for_attachments()
    )
    text = att["data"].decode()
    assert "NTP Configuration" in text


def test_html_attachment_has_check_summary_before_host_summary():
    """HTML attachment has Check Summary heading before Host Summary heading."""
    from app.device_review_scheduler import _build_attachment_dr
    att = _build_attachment_dr(
        "TESTADOM", "pdf", _make_results_with_rows(), "2026-08-04T00:00:00Z",
        _make_check_summary_for_attachments()
    )
    html = att["data"].decode()
    assert "Check Summary" in html
    assert "Host Summary" in html
    assert html.index("Check Summary") < html.index("Host Summary")


def test_html_attachment_check_summary_shows_description():
    """HTML attachment check summary table includes check description text."""
    from app.device_review_scheduler import _build_attachment_dr
    att = _build_attachment_dr(
        "TESTADOM", "pdf", [], "2026-08-04T00:00:00Z",
        _make_check_summary_for_attachments()
    )
    html = att["data"].decode()
    assert "Check NTP" in html


def test_findings_rows_have_data_attributes():
    """Each findings <tr> has data-result and data-device attributes."""
    from app.device_review_scheduler import _build_pdf_html_dr
    results = [
        {"device": "fw-01", "rows": [
            {"device": "fw-01", "check": "NTP", "result": "FAIL",
             "interface": "system", "vdom": "root", "ip": "", "detail": "no ntp",
             "protocols": [], "has_insecure": False, "has_secure": False},
        ], "error": None},
        {"device": "fw-02", "rows": [
            {"device": "fw-02", "check": "Interface Protocols", "result": "INSECURE",
             "interface": "mgmt", "vdom": "root", "ip": "10.0.0.1/24", "detail": "",
             "protocols": [{"name": "http", "secure": False}],
             "has_insecure": True, "has_secure": False},
        ], "error": None},
    ]
    html = _build_pdf_html_dr("Corp", results, "2026-08-06T00:00:00Z", [])
    assert 'data-result="FAIL"' in html
    assert 'data-result="INSECURE"' in html
    assert 'data-device="fw-01"' in html
    assert 'data-device="fw-02"' in html


# ── _REPORT_CSS and _REPORT_JS constants ──────────────────────────────────

def test_report_css_constant_exists():
    """_REPORT_CSS module constant is a non-empty string."""
    import app.device_review_scheduler as sched
    assert isinstance(sched._REPORT_CSS, str)
    assert len(sched._REPORT_CSS) > 0


def test_report_js_constant_exists():
    """_REPORT_JS module constant is a non-empty string."""
    import app.device_review_scheduler as sched
    assert isinstance(sched._REPORT_JS, str)
    assert len(sched._REPORT_JS) > 0


def test_report_js_defines_filter_function():
    """_REPORT_JS contains the filterFindings function definition."""
    import app.device_review_scheduler as sched
    assert "filterFindings" in sched._REPORT_JS


def test_report_js_handles_all_result_filter():
    """_REPORT_JS contains logic to handle the ALL result filter."""
    import app.device_review_scheduler as sched
    assert "ALL" in sched._REPORT_JS


def _make_multi_host_results():
    return [
        {"device": "fw-alpha", "rows": [
            {"device": "fw-alpha", "check": "NTP", "result": "FAIL",
             "interface": "system", "vdom": "root", "ip": "", "detail": "no ntp",
             "protocols": [], "has_insecure": False, "has_secure": False},
            {"device": "fw-alpha", "check": "Interface Protocols", "result": "PASS",
             "interface": "mgmt", "vdom": "root", "ip": "10.0.0.1/24", "detail": "",
             "protocols": [], "has_insecure": False, "has_secure": True},
        ], "error": None},
        {"device": "fw-beta", "rows": [
            {"device": "fw-beta", "check": "NTP", "result": "INSECURE",
             "interface": "system", "vdom": "root", "ip": "", "detail": "bad ntp",
             "protocols": [], "has_insecure": True, "has_secure": False},
        ], "error": None},
    ]


def test_html_report_has_filter_bar():
    """HTML report contains the filter bar div."""
    from app.device_review_scheduler import _build_pdf_html_dr
    html = _build_pdf_html_dr("Corp", _make_multi_host_results(), "2026-08-06T00:00:00Z", [])
    assert 'id="dr-filter-bar"' in html


def test_html_report_filter_bar_has_result_buttons():
    """Filter bar contains a button for each result type plus ALL."""
    from app.device_review_scheduler import _build_pdf_html_dr
    html = _build_pdf_html_dr("Corp", _make_multi_host_results(), "2026-08-06T00:00:00Z", [])
    for result in ("ALL", "FAIL", "INSECURE", "WARN", "CONFIG_MISSING", "PASS", "INFO"):
        assert f'data-result="{result}"' in html


def test_html_report_filter_bar_has_host_dropdown():
    """Filter bar contains a host dropdown with device names as options."""
    from app.device_review_scheduler import _build_pdf_html_dr
    html = _build_pdf_html_dr("Corp", _make_multi_host_results(), "2026-08-06T00:00:00Z", [])
    assert 'id="dr-host-select"' in html
    assert 'value="fw-alpha"' in html
    assert 'value="fw-beta"' in html


def test_html_report_filter_bar_has_all_hosts_option():
    """Host dropdown includes an 'All Hosts' default option."""
    from app.device_review_scheduler import _build_pdf_html_dr
    html = _build_pdf_html_dr("Corp", _make_multi_host_results(), "2026-08-06T00:00:00Z", [])
    assert "All Hosts" in html


def test_html_report_findings_tbody_has_id():
    """Findings tbody has id='dr-findings-tbody' for JS targeting."""
    from app.device_review_scheduler import _build_pdf_html_dr
    html = _build_pdf_html_dr("Corp", _make_multi_host_results(), "2026-08-06T00:00:00Z", [])
    assert 'id="dr-findings-tbody"' in html


def test_html_report_has_row_count_span():
    """HTML report contains the row count indicator span."""
    from app.device_review_scheduler import _build_pdf_html_dr
    html = _build_pdf_html_dr("Corp", _make_multi_host_results(), "2026-08-06T00:00:00Z", [])
    assert 'id="dr-row-count"' in html


def test_html_report_filter_bar_before_findings():
    """Filter bar appears in the HTML before the Findings table."""
    from app.device_review_scheduler import _build_pdf_html_dr
    html = _build_pdf_html_dr("Corp", _make_multi_host_results(), "2026-08-06T00:00:00Z", [])
    assert html.index('id="dr-filter-bar"') < html.index(">Findings<")


def test_html_report_css_injected():
    """_REPORT_CSS content is present in the <style> block."""
    from app.device_review_scheduler import _build_pdf_html_dr, _REPORT_CSS
    html = _build_pdf_html_dr("Corp", _make_multi_host_results(), "2026-08-06T00:00:00Z", [])
    assert "dr-filter-bar" in html
    assert "dr-result-btn" in html


def test_html_report_js_injected():
    """_REPORT_JS content is present in the output HTML."""
    from app.device_review_scheduler import _build_pdf_html_dr
    html = _build_pdf_html_dr("Corp", _make_multi_host_results(), "2026-08-06T00:00:00Z", [])
    assert "filterFindings" in html


def test_html_report_host_options_sorted_alphabetically():
    """Host dropdown options are sorted alphabetically."""
    from app.device_review_scheduler import _build_pdf_html_dr
    html = _build_pdf_html_dr("Corp", _make_multi_host_results(), "2026-08-06T00:00:00Z", [])
    assert html.index('value="fw-alpha"') < html.index('value="fw-beta"')


def test_html_report_no_duplicate_host_options():
    """Each device appears exactly once in the host dropdown even if it has multiple rows."""
    from app.device_review_scheduler import _build_pdf_html_dr
    # fw-alpha has 2 rows — should still appear once in the dropdown
    html = _build_pdf_html_dr("Corp", _make_multi_host_results(), "2026-08-06T00:00:00Z", [])
    assert html.count('value="fw-alpha"') == 1


def test_html_report_device_names_are_escaped():
    """Device names with HTML metacharacters are escaped in dropdown options and data attributes."""
    from app.device_review_scheduler import _build_pdf_html_dr
    results = [
        {"device": 'fw-<evil>"&test', "rows": [
            {"device": 'fw-<evil>"&test', "check": "NTP", "result": "FAIL",
             "interface": "system", "vdom": "root", "ip": "", "detail": "bad",
             "protocols": [], "has_insecure": True, "has_secure": False},
        ], "error": None},
    ]
    html = _build_pdf_html_dr("Corp", results, "2026-08-06T00:00:00Z", [])
    # Raw metacharacters must not appear in the output
    assert "<evil>" not in html
    assert '"&test' not in html
    # Escaped forms must be present
    assert "&lt;evil&gt;" in html
    assert "&amp;test" in html


def test_html_report_all_button_is_active_by_default():
    """The ALL result button has the 'active' class on initial render."""
    from app.device_review_scheduler import _build_pdf_html_dr
    html = _build_pdf_html_dr("Corp", [], "2026-08-06T00:00:00Z", [])
    assert 'class="dr-result-btn active" data-result="ALL"' in html


def test_filter_bar_absent_from_csv_and_json():
    """CSV and JSON attachments do not contain filter bar markup or JS."""
    from app.device_review_scheduler import _build_attachment_dr
    rows = [{"device": "fw-01", "check": "NTP", "result": "FAIL",
             "interface": "system", "vdom": "root", "ip": "", "detail": "bad",
             "protocols": [], "has_insecure": True, "has_secure": False}]
    results = [{"device": "fw-01", "ip": "10.0.0.1", "rows": rows, "error": None}]
    for fmt in ("csv", "json"):
        att = _build_attachment_dr("Corp", fmt, results, "2026-08-06T00:00:00Z", [])
        content = att["data"].decode()
        assert "dr-filter-bar" not in content, f"{fmt} should not contain filter bar"
        assert "filterFindings" not in content, f"{fmt} should not contain filter JS"


def test_execute_job_includes_ai_narrative_when_enabled(jobs_path, monkeypatch):
    import app.device_review_scheduler as sched

    fake_meta = [
        {"key": "trusted_hosts", "name": "Trusted Hosts on Admin Accounts (CIS)",
         "description": "Check trusted hosts"},
    ]
    monkeypatch.setattr("app.device_review_scheduler._CHECKS_META", fake_meta)

    job = sched.create_job({
        "name": "T", "adom": "CorpADOM", "days_of_week": ["MON"], "time": "06:00",
        "checks": ["trusted_hosts"], "check_params": {},
        "format": "pdf", "email": "test@corp.com", "enabled": True,
    })

    fake_results = [
        {"device": "fw-01", "ip": "10.0.0.1",
         "rows": [{"device": "fw-01", "check": "Trusted Hosts on Admin Accounts (CIS)",
                   "result": "FAIL", "interface": "system", "vdom": "root",
                   "ip": "", "detail": "no restriction", "protocols": [],
                   "has_insecure": False, "has_secure": False}],
         "error": None},
    ]

    sent = {}
    monkeypatch.setattr("app.device_review_scheduler._bulk_device_review_adom",
                         lambda *a, **kw: fake_results)
    monkeypatch.setattr("app.device_review_scheduler._send_email",
                         lambda to, subject, body_html, attachments: sent.update(
                             {"body": body_html, "attachments": attachments}))
    monkeypatch.setattr("app.app_settings.get_setting", lambda k, d=None: True)
    monkeypatch.setattr("app.device_review_ai.build_narrative",
                         lambda adom, cs, r: "One admin account needs a trusted-host restriction.")

    sched._execute_job(job["id"])

    assert "One admin account needs a trusted-host restriction." in sent["body"]
    pdf_bytes = sent["attachments"][0]["data"]
    assert b"One admin account needs a trusted-host restriction." in pdf_bytes


def test_execute_job_omits_narrative_when_disabled(jobs_path, monkeypatch):
    import app.device_review_scheduler as sched

    fake_meta = [{"key": "trusted_hosts", "name": "Trusted Hosts on Admin Accounts (CIS)",
                  "description": "d"}]
    monkeypatch.setattr("app.device_review_scheduler._CHECKS_META", fake_meta)
    job = sched.create_job({
        "name": "T", "adom": "CorpADOM", "days_of_week": ["MON"], "time": "06:00",
        "checks": ["trusted_hosts"], "check_params": {},
        "format": "pdf", "email": "test@corp.com", "enabled": True,
    })
    fake_results = [{"device": "fw-01", "ip": "", "rows": [], "error": None}]
    sent = {}
    monkeypatch.setattr("app.device_review_scheduler._bulk_device_review_adom",
                         lambda *a, **kw: fake_results)
    monkeypatch.setattr("app.device_review_scheduler._send_email",
                         lambda to, subject, body_html, attachments: sent.update({"body": body_html}))
    monkeypatch.setattr("app.app_settings.get_setting", lambda k, d=None: False)

    sched._execute_job(job["id"])

    assert "AI Summary" not in sent["body"]


def test_execute_job_narrative_failure_still_sends_email(jobs_path, monkeypatch):
    import app.device_review_scheduler as sched

    fake_meta = [{"key": "trusted_hosts", "name": "Trusted Hosts on Admin Accounts (CIS)",
                  "description": "d"}]
    monkeypatch.setattr("app.device_review_scheduler._CHECKS_META", fake_meta)
    job = sched.create_job({
        "name": "T", "adom": "CorpADOM", "days_of_week": ["MON"], "time": "06:00",
        "checks": ["trusted_hosts"], "check_params": {},
        "format": "pdf", "email": "test@corp.com", "enabled": True,
    })
    fake_results = [{"device": "fw-01", "ip": "", "rows": [], "error": None}]
    sent = {}
    monkeypatch.setattr("app.device_review_scheduler._bulk_device_review_adom",
                         lambda *a, **kw: fake_results)
    monkeypatch.setattr("app.device_review_scheduler._send_email",
                         lambda to, subject, body_html, attachments: sent.update({"body": body_html}))
    monkeypatch.setattr("app.app_settings.get_setting", lambda k, d=None: True)

    def _raise(adom, cs, r):
        raise RuntimeError("API down")

    monkeypatch.setattr("app.device_review_ai.build_narrative", _raise)

    sched._execute_job(job["id"])  # must not raise

    assert sent["body"]  # email still sent

    jobs = sched._load()
    job_after = next(j for j in jobs if j["id"] == job["id"])
    last_run = job_after.get("runs", [])[-1]
    assert last_run.get("ai_narrative_error") == "API down"


def test_execute_job_narrative_success_no_ai_narrative_error(jobs_path, monkeypatch):
    import app.device_review_scheduler as sched

    fake_meta = [{"key": "trusted_hosts", "name": "Trusted Hosts on Admin Accounts (CIS)",
                  "description": "d"}]
    monkeypatch.setattr("app.device_review_scheduler._CHECKS_META", fake_meta)
    job = sched.create_job({
        "name": "T", "adom": "CorpADOM", "days_of_week": ["MON"], "time": "06:00",
        "checks": ["trusted_hosts"], "check_params": {},
        "format": "pdf", "email": "test@corp.com", "enabled": True,
    })
    fake_results = [{"device": "fw-01", "ip": "", "rows": [], "error": None}]
    sent = {}
    monkeypatch.setattr("app.device_review_scheduler._bulk_device_review_adom",
                         lambda *a, **kw: fake_results)
    monkeypatch.setattr("app.device_review_scheduler._send_email",
                         lambda to, subject, body_html, attachments: sent.update({"body": body_html}))
    monkeypatch.setattr("app.app_settings.get_setting", lambda k, d=None: True)
    monkeypatch.setattr("app.device_review_ai.build_narrative", lambda adom, cs, r: "All good.")

    sched._execute_job(job["id"])

    jobs = sched._load()
    job_after = next(j for j in jobs if j["id"] == job["id"])
    last_run = job_after.get("runs", [])[-1]
    assert "ai_narrative_error" not in last_run


def test_execute_job_narrative_disabled_no_ai_narrative_error(jobs_path, monkeypatch):
    import app.device_review_scheduler as sched

    fake_meta = [{"key": "trusted_hosts", "name": "Trusted Hosts on Admin Accounts (CIS)",
                  "description": "d"}]
    monkeypatch.setattr("app.device_review_scheduler._CHECKS_META", fake_meta)
    job = sched.create_job({
        "name": "T", "adom": "CorpADOM", "days_of_week": ["MON"], "time": "06:00",
        "checks": ["trusted_hosts"], "check_params": {},
        "format": "pdf", "email": "test@corp.com", "enabled": True,
    })
    fake_results = [{"device": "fw-01", "ip": "", "rows": [], "error": None}]
    sent = {}
    monkeypatch.setattr("app.device_review_scheduler._bulk_device_review_adom",
                         lambda *a, **kw: fake_results)
    monkeypatch.setattr("app.device_review_scheduler._send_email",
                         lambda to, subject, body_html, attachments: sent.update({"body": body_html}))
    monkeypatch.setattr("app.app_settings.get_setting", lambda k, d=None: False)

    sched._execute_job(job["id"])

    jobs = sched._load()
    job_after = next(j for j in jobs if j["id"] == job["id"])
    last_run = job_after.get("runs", [])[-1]
    assert "ai_narrative_error" not in last_run
