import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock


@pytest.fixture
def jobs_path(tmp_path, monkeypatch):
    p = tmp_path / "config_diff_jobs.json"
    monkeypatch.setattr("app.config_diff_scheduler._JOBS_PATH", p)
    return p


def test_get_all_jobs_empty(jobs_path):
    from app import config_diff_scheduler as sched
    assert sched.get_all_jobs() == []


def test_create_job_assigns_id(jobs_path):
    from app import config_diff_scheduler as sched
    job = sched.create_job({
        "adom": "TEST", "days_of_week": ["MON"], "time": "06:00",
        "format": "pdf", "email": "x@x.com", "enabled": True
    })
    assert "id" in job
    assert len(sched.get_all_jobs()) == 1


def test_update_job(jobs_path):
    from app import config_diff_scheduler as sched
    job = sched.create_job({"adom": "TEST", "days_of_week": ["MON"], "time": "06:00",
                             "format": "pdf", "email": "x@x.com", "enabled": True})
    updated = sched.update_job(job["id"], {**job, "email": "new@x.com"})
    assert updated["email"] == "new@x.com"
    assert sched.get_all_jobs()[0]["email"] == "new@x.com"


def test_create_job_ai_summary_enabled_defaults_true(jobs_path):
    from app import config_diff_scheduler as sched
    job = sched.create_job({
        "adom": "TEST", "days_of_week": ["MON"], "time": "06:00",
        "format": "pdf", "email": "x@x.com", "enabled": True
    })
    assert job["ai_summary_enabled"] is True


def test_create_job_ai_summary_enabled_can_be_disabled(jobs_path):
    from app import config_diff_scheduler as sched
    job = sched.create_job({
        "adom": "TEST", "days_of_week": ["MON"], "time": "06:00",
        "format": "pdf", "email": "x@x.com", "enabled": True,
        "ai_summary_enabled": False,
    })
    assert job["ai_summary_enabled"] is False
    assert sched.get_all_jobs()[0]["ai_summary_enabled"] is False


def test_update_job_preserves_ai_summary_enabled_when_omitted(jobs_path):
    from app import config_diff_scheduler as sched
    job = sched.create_job({
        "adom": "TEST", "days_of_week": ["MON"], "time": "06:00",
        "format": "pdf", "email": "x@x.com", "enabled": True,
        "ai_summary_enabled": False,
    })
    payload = {k: v for k, v in job.items() if k != "ai_summary_enabled"}
    updated = sched.update_job(job["id"], {**payload, "email": "new@x.com"})
    assert updated["ai_summary_enabled"] is False


def test_delete_job(jobs_path):
    from app import config_diff_scheduler as sched
    job = sched.create_job({"adom": "TEST", "days_of_week": ["MON"], "time": "06:00",
                             "format": "pdf", "email": "x@x.com", "enabled": True})
    sched.delete_job(job["id"])
    assert sched.get_all_jobs() == []


def test_prune_old_runs(jobs_path):
    from app import config_diff_scheduler as sched
    import datetime
    old_ts = (datetime.datetime.utcnow() - datetime.timedelta(days=40)).isoformat() + "Z"
    recent_ts = datetime.datetime.utcnow().isoformat() + "Z"
    job = sched.create_job({"adom": "TEST", "days_of_week": ["MON"], "time": "06:00",
                             "format": "pdf", "email": "x@x.com", "enabled": True})
    jobs = json.loads(jobs_path.read_text())
    jobs[0]["runs"] = [
        {"ran_at": old_ts, "status": "ok", "devices_total": 1, "devices_with_changes": 0},
        {"ran_at": recent_ts, "status": "ok", "devices_total": 1, "devices_with_changes": 1},
    ]
    jobs_path.write_text(json.dumps(jobs))
    sched._prune_runs(job["id"], retention_days=30)
    remaining = sched.get_all_jobs()[0]["runs"]
    assert len(remaining) == 1
    assert remaining[0]["ran_at"] == recent_ts


def test_create_job_multi_day(jobs_path):
    from app import config_diff_scheduler as sched
    job = sched.create_job({
        "adom": "TEST", "days_of_week": ["MON", "THU"], "time": "06:00",
        "format": "pdf", "email": "x@x.com", "enabled": True
    })
    assert job["days_of_week"] == ["MON", "THU"]
    stored = sched.get_all_jobs()[0]
    assert stored["days_of_week"] == ["MON", "THU"]


def test_validate_empty_days(jobs_path):
    from app import config_diff_scheduler as sched
    with pytest.raises(ValueError, match="days_of_week"):
        sched.create_job({
            "adom": "TEST", "days_of_week": [], "time": "06:00",
            "format": "pdf", "email": "x@x.com", "enabled": True
        })


def test_validate_invalid_day_code(jobs_path):
    from app import config_diff_scheduler as sched
    with pytest.raises(ValueError, match="days_of_week"):
        sched.create_job({
            "adom": "TEST", "days_of_week": ["MONDAY"], "time": "06:00",
            "format": "pdf", "email": "x@x.com", "enabled": True
        })


def test_validate_single_day_still_works(jobs_path):
    from app import config_diff_scheduler as sched
    job = sched.create_job({
        "adom": "TEST", "days_of_week": ["FRI"], "time": "08:00",
        "format": "csv", "email": "x@x.com", "enabled": True
    })
    assert job["days_of_week"] == ["FRI"]


def test_register_multi_day_cron_string(jobs_path):
    from app import config_diff_scheduler as sched
    from unittest.mock import MagicMock, patch

    mock_scheduler = MagicMock()
    sched._scheduler = mock_scheduler
    try:
        with patch("apscheduler.triggers.cron.CronTrigger") as mock_trigger:
            sched.create_job({
                "adom": "TEST", "days_of_week": ["MON", "THU"], "time": "06:00",
                "format": "pdf", "email": "x@x.com", "enabled": True
            })
            mock_trigger.assert_called_once_with(day_of_week="mon,thu", hour=6, minute=0)
    finally:
        sched._scheduler = None


def test_build_pdf_html_contains_header_fields(jobs_path):
    from app import config_diff_scheduler as sched

    results = [
        {"device": "fw-01", "ip": "10.0.0.1", "status": "ok", "vdoms": []},
        {"device": "fw-02", "ip": "10.0.0.2", "status": "no_changes"},
    ]
    generated_at = "2026-07-24T10:30:00Z"
    html = sched._build_pdf_html("Corp", results, generated_at)

    assert "Corp" in html
    assert "2026-07-24" in html
    assert "10:30:00" in html
    assert "Devices scanned" in html
    assert "4THealth+ Config-Delta Scheduler" in html


def test_build_pdf_html_omits_pkg_pending_row_when_zero(jobs_path):
    from app import config_diff_scheduler as sched

    results = [{"device": "fw-01", "ip": "10.0.0.1", "status": "ok", "vdoms": []}]
    html = sched._build_pdf_html("Corp", results, "2026-07-24T00:00:00Z")

    assert "pkg_pending" not in html.lower()


def test_build_attachment_html_contains_header(jobs_path):
    from app import config_diff_scheduler as sched

    results = [{"device": "fw-01", "ip": "10.0.0.1", "status": "no_changes"}]
    att = sched._build_attachment("Corp", "pdf", results, "2026-07-24T00:00:00Z")

    html = att["data"].decode()
    assert "Corp" in html
    assert "4THealth+" in html


def test_build_attachment_json_has_exported_at(jobs_path):
    from app import config_diff_scheduler as sched

    results = [{"device": "fw-01", "ip": "10.0.0.1", "status": "no_changes"}]
    att = sched._build_attachment("Corp", "json", results, "2026-07-24T00:00:00Z")
    data = json.loads(att["data"])

    assert data["exported_at"] == "2026-07-24T00:00:00Z"
    assert data["adom"] == "Corp"


def test_build_attachment_csv_has_metadata_header(jobs_path):
    from app import config_diff_scheduler as sched

    results = [{"device": "fw-01", "ip": "10.0.0.1", "status": "no_changes"}]
    att = sched._build_attachment("Corp", "csv", results, "2026-07-24T00:00:00Z")
    text = att["data"].decode()

    assert "Corp" in text
    assert "2026-07-24" in text


def test_execute_job_includes_ai_narrative_when_enabled(jobs_path, monkeypatch):
    import app.config_diff_scheduler as sched

    job = sched.create_job({
        "name": "T", "adom": "CorpADOM", "days_of_week": ["MON"], "time": "06:00",
        "format": "pdf", "email": "test@corp.com", "enabled": True,
    })

    fake_results = [
        {"device": "fw-01", "ip": "10.0.0.1", "status": "ok", "pkg_status": "modified",
         "summary": {"firewall_policy": 1}, "vdoms": [{"name": "root", "changes": [
             {"type": "add", "line": "edit 1"}]}], "raw": "edit 1", "error": None},
    ]

    sent = {}
    monkeypatch.setattr(
        "app.routes.pending_changes_routes.bulk_preview_adom",
        lambda adom, max_workers=1: fake_results,
    )
    monkeypatch.setattr(
        "app.smtp_client.send_email",
        lambda to, subject, body_html, attachments: sent.update(
            {"body": body_html, "attachments": attachments}),
    )
    monkeypatch.setattr("app.app_settings.get_setting", lambda k, d=None: True)
    monkeypatch.setattr(
        "app.pending_changes_ai.build_diff_narrative",
        lambda adom, devices: "Adds one firewall policy on fw-01.",
    )

    sched._execute_job(job["id"])

    assert "Adds one firewall policy on fw-01." in sent["body"]


def test_execute_job_narrative_failure_still_sends_email(jobs_path, monkeypatch):
    import app.config_diff_scheduler as sched

    job = sched.create_job({
        "name": "T", "adom": "CorpADOM", "days_of_week": ["MON"], "time": "06:00",
        "format": "pdf", "email": "test@corp.com", "enabled": True,
    })
    fake_results = [
        {"device": "fw-01", "ip": "", "status": "ok", "pkg_status": "",
         "summary": {}, "vdoms": [{"name": "root", "changes": [
             {"type": "add", "line": "edit 1"}]}], "raw": "edit 1", "error": None},
    ]
    sent = {}
    monkeypatch.setattr(
        "app.routes.pending_changes_routes.bulk_preview_adom",
        lambda adom, max_workers=1: fake_results,
    )
    monkeypatch.setattr(
        "app.smtp_client.send_email",
        lambda to, subject, body_html, attachments: sent.update({"body": body_html}),
    )
    monkeypatch.setattr("app.app_settings.get_setting", lambda k, d=None: True)
    monkeypatch.setattr(
        "app.pending_changes_ai.build_diff_narrative",
        lambda adom, devices: (_ for _ in ()).throw(RuntimeError("API down")),
    )

    sched._execute_job(job["id"])  # must not raise

    assert sent["body"]
    assert "AI Summary" not in sent["body"]

    runs = sched.get_all_jobs()[0]["runs"]
    assert runs[-1]["ai_narrative_error"] == "API down"


def test_execute_job_no_changes_skips_ai_narrative(jobs_path, monkeypatch):
    """When no device has any actual changes, the scheduler must not call the
    LLM narrator at all, and no 'AI Summary' section is injected."""
    import app.config_diff_scheduler as sched

    job = sched.create_job({
        "name": "T", "adom": "CorpADOM", "days_of_week": ["MON"], "time": "06:00",
        "format": "pdf", "email": "test@corp.com", "enabled": True,
    })
    fake_results = [
        {"device": "fw-01", "ip": "", "status": "no_changes", "pkg_status": "",
         "summary": {}, "vdoms": [], "raw": "", "error": None},
        {"device": "fw-02", "ip": "", "status": "no_changes", "pkg_status": "",
         "summary": {}, "vdoms": [{"name": "root", "changes": []}], "raw": "", "error": None},
    ]
    sent = {}
    monkeypatch.setattr(
        "app.routes.pending_changes_routes.bulk_preview_adom",
        lambda adom, max_workers=1: fake_results,
    )
    monkeypatch.setattr(
        "app.smtp_client.send_email",
        lambda to, subject, body_html, attachments: sent.update({"body": body_html}),
    )
    monkeypatch.setattr("app.app_settings.get_setting", lambda k, d=None: True)
    called = {}
    monkeypatch.setattr(
        "app.pending_changes_ai.build_diff_narrative",
        lambda adom, devices: called.setdefault("called", True),
    )

    sched._execute_job(job["id"])

    assert "called" not in called
    assert "AI Summary" not in sent["body"]
    runs = sched.get_all_jobs()[0]["runs"]
    assert "ai_narrative_error" not in runs[-1]


def test_execute_job_ai_summary_disabled_skips_narrative_even_if_globally_enabled(
    jobs_path, monkeypatch
):
    """A job with ai_summary_enabled=False must never call the LLM narrator,
    even when the global ai_assist_enabled setting is on and there are
    changes to summarize."""
    import app.config_diff_scheduler as sched

    job = sched.create_job({
        "name": "T", "adom": "CorpADOM", "days_of_week": ["MON"], "time": "06:00",
        "format": "pdf", "email": "test@corp.com", "enabled": True,
        "ai_summary_enabled": False,
    })

    fake_results = [
        {"device": "fw-01", "ip": "10.0.0.1", "status": "ok", "pkg_status": "modified",
         "summary": {"firewall_policy": 1}, "vdoms": [{"name": "root", "changes": [
             {"type": "add", "line": "edit 1"}]}], "raw": "edit 1", "error": None},
    ]

    sent = {}
    monkeypatch.setattr(
        "app.routes.pending_changes_routes.bulk_preview_adom",
        lambda adom, max_workers=1: fake_results,
    )
    monkeypatch.setattr(
        "app.smtp_client.send_email",
        lambda to, subject, body_html, attachments: sent.update({"body": body_html}),
    )
    monkeypatch.setattr("app.app_settings.get_setting", lambda k, d=None: True)
    called = {}
    monkeypatch.setattr(
        "app.pending_changes_ai.build_diff_narrative",
        lambda adom, devices: called.setdefault("called", True),
    )

    sched._execute_job(job["id"])

    assert "called" not in called
    assert "AI Summary" not in sent["body"]
