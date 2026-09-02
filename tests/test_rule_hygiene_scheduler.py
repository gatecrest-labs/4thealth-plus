import datetime
import json

import pytest

import app.rule_hygiene_scheduler as rhs

# ── Fixtures ──────────────────────────────────────────────────────────────────


def _job_data(**overrides):
    base = {
        "name": "Test Job",
        "adom": "TestADOM",
        "days_of_week": ["MON"],
        "time": "03:00",
        "checks": [],
        "include_unused_objects": False,
        "batch_size": 20,
        "format": "html",
        "email": "test@example.com",
        "enabled": False,
    }
    base.update(overrides)
    return base


def _pkg_result(name="MyPkg", device="fw-01", n_findings=1, error=None):
    return {
        "package": name,
        "package_name": name,
        "device": device,
        "scope_members": [device] if device else [],
        "findings": [
            {
                "policy_id": "1",
                "policy_name": "allow-all",
                "seq": 1,
                "check": "unnamed",
                "detail": "No name",
            }
        ]
        * n_findings,
        "unused_objects": None,
        "policy_count": 10,
        "error": error,
    }


def _make_results(n, error_idx=None):
    return [
        _pkg_result(
            name=f"pkg{i}",
            device=f"fw-{i:02d}",
            error="timeout" if error_idx is not None and i == error_idx else None,
        )
        for i in range(n)
    ]


# ── CRUD tests ────────────────────────────────────────────────────────────────


def test_create_update_delete(tmp_path, monkeypatch):
    monkeypatch.setattr(rhs, "_JOBS_PATH", tmp_path / "jobs.json")

    job = rhs.create_job(_job_data())
    assert job["name"] == "Test Job"
    assert job["adom"] == "TestADOM"
    assert len(rhs.get_all_jobs()) == 1

    updated = rhs.update_job(job["id"], _job_data(name="Updated", time="04:00"))
    assert updated["name"] == "Updated"
    assert updated["time"] == "04:00"

    rhs.delete_job(job["id"])
    assert rhs.get_all_jobs() == []


def test_delete_not_found_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(rhs, "_JOBS_PATH", tmp_path / "jobs.json")
    with pytest.raises(KeyError):
        rhs.delete_job("nonexistent-id")


def test_update_not_found_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(rhs, "_JOBS_PATH", tmp_path / "jobs.json")
    with pytest.raises(KeyError):
        rhs.update_job("nonexistent-id", _job_data())


# ── Validation tests ──────────────────────────────────────────────────────────


def test_validate_bad_day_code(tmp_path, monkeypatch):
    monkeypatch.setattr(rhs, "_JOBS_PATH", tmp_path / "jobs.json")
    with pytest.raises(ValueError, match="invalid codes"):
        rhs.create_job(_job_data(days_of_week=["XXX"]))


def test_validate_empty_days(tmp_path, monkeypatch):
    monkeypatch.setattr(rhs, "_JOBS_PATH", tmp_path / "jobs.json")
    with pytest.raises(ValueError):
        rhs.create_job(_job_data(days_of_week=[]))


def test_validate_bad_time_format(tmp_path, monkeypatch):
    monkeypatch.setattr(rhs, "_JOBS_PATH", tmp_path / "jobs.json")
    with pytest.raises(ValueError, match="HH:MM"):
        rhs.create_job(_job_data(time="25:00"))


def test_validate_bad_time_letters(tmp_path, monkeypatch):
    monkeypatch.setattr(rhs, "_JOBS_PATH", tmp_path / "jobs.json")
    with pytest.raises(ValueError, match="HH:MM"):
        rhs.create_job(_job_data(time="ab:cd"))


def test_validate_batch_size_zero(tmp_path, monkeypatch):
    monkeypatch.setattr(rhs, "_JOBS_PATH", tmp_path / "jobs.json")
    with pytest.raises(ValueError, match="batch_size"):
        rhs.create_job(_job_data(batch_size=0))


def test_validate_batch_size_over_100(tmp_path, monkeypatch):
    monkeypatch.setattr(rhs, "_JOBS_PATH", tmp_path / "jobs.json")
    with pytest.raises(ValueError, match="batch_size"):
        rhs.create_job(_job_data(batch_size=101))


def test_valid_all_days(tmp_path, monkeypatch):
    monkeypatch.setattr(rhs, "_JOBS_PATH", tmp_path / "jobs.json")
    job = rhs.create_job(
        _job_data(days_of_week=["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"])
    )
    assert len(job["days_of_week"]) == 7


# ── Execution tests ───────────────────────────────────────────────────────────


def test_execute_single_batch(tmp_path, monkeypatch):
    monkeypatch.setattr(rhs, "_JOBS_PATH", tmp_path / "jobs.json")
    monkeypatch.setattr(rhs, "_bulk_hygiene_adom", lambda *a, **kw: _make_results(5))
    sent = []
    monkeypatch.setattr(rhs, "_send_email", lambda *a: sent.append(a))
    monkeypatch.setattr(
        "app.smtp_client.load_smtp_config", lambda: {"run_history_days": 30}
    )

    job = rhs.create_job(_job_data(batch_size=20))
    rhs._execute_job(job["id"])

    assert len(sent) == 1
    _, subject, _, attachments = sent[0]
    assert "Rule Hygiene" in subject
    assert "[Part" not in subject
    assert len(attachments) == 1
    assert attachments[0]["filename"].endswith(".zip")


def test_execute_multi_batch(tmp_path, monkeypatch):
    monkeypatch.setattr(rhs, "_JOBS_PATH", tmp_path / "jobs.json")
    monkeypatch.setattr(rhs, "_bulk_hygiene_adom", lambda *a, **kw: _make_results(45))
    sent = []
    monkeypatch.setattr(rhs, "_send_email", lambda *a: sent.append(a))
    monkeypatch.setattr(
        "app.smtp_client.load_smtp_config", lambda: {"run_history_days": 30}
    )

    job = rhs.create_job(_job_data(batch_size=20))
    rhs._execute_job(job["id"])

    assert len(sent) == 3  # ceil(45/20) = 3
    _, subject1, _, _ = sent[0]
    _, subject2, _, _ = sent[1]
    _, subject3, _, _ = sent[2]
    assert "[Part" not in subject1
    assert "[Part 2 of 3]" in subject2
    assert "[Part 3 of 3]" in subject3


def test_execute_no_packages(tmp_path, monkeypatch):
    monkeypatch.setattr(rhs, "_JOBS_PATH", tmp_path / "jobs.json")
    monkeypatch.setattr(rhs, "_bulk_hygiene_adom", lambda *a, **kw: [])
    sent = []
    monkeypatch.setattr(rhs, "_send_email", lambda *a: sent.append(a))
    monkeypatch.setattr(
        "app.smtp_client.load_smtp_config", lambda: {"run_history_days": 30}
    )

    job = rhs.create_job(_job_data())
    rhs._execute_job(job["id"])

    assert len(sent) == 1
    _, _, body_html, attachments = sent[0]
    assert "0" in body_html  # packages scanned: 0
    assert len(attachments) == 0


def test_scope_member_filename_single():
    result = _pkg_result(name="MyPkg", device="fw-01")
    filename, _ = rhs._build_attachment_rh(result, "html", "2026-09-01T03:00:00Z")
    assert filename == "fw-01-MyPkg-2026-09-01.html"


def test_scope_member_filename_multi():
    result = {
        "package": "MyPkg",
        "package_name": "MyPkg",
        "device": None,
        "scope_members": ["fw-01", "fw-02"],
        "findings": [],
        "unused_objects": None,
        "policy_count": 5,
        "error": None,
    }
    filename, _ = rhs._build_attachment_rh(result, "html", "2026-09-01T03:00:00Z")
    assert filename == "MyPkg-2026-09-01.html"


def test_scope_member_filename_no_scope():
    result = {
        "package": "MyPkg",
        "package_name": "MyPkg",
        "device": None,
        "scope_members": [],
        "findings": [],
        "unused_objects": None,
        "policy_count": 5,
        "error": None,
    }
    filename, _ = rhs._build_attachment_rh(result, "html", "2026-09-01T03:00:00Z")
    assert filename == "MyPkg-2026-09-01.html"


def test_unused_objects_flag_passed(tmp_path, monkeypatch):
    monkeypatch.setattr(rhs, "_JOBS_PATH", tmp_path / "jobs.json")
    calls = []

    def fake_bulk(adom, checks, include_unused_objects=False, max_workers=4):
        calls.append({"include_unused_objects": include_unused_objects})
        return _make_results(1)

    monkeypatch.setattr(rhs, "_bulk_hygiene_adom", fake_bulk)
    monkeypatch.setattr(rhs, "_send_email", lambda *a: None)
    monkeypatch.setattr(
        "app.smtp_client.load_smtp_config", lambda: {"run_history_days": 30}
    )

    job_off = rhs.create_job(_job_data(include_unused_objects=False))
    rhs._execute_job(job_off["id"])
    assert calls[-1]["include_unused_objects"] is False

    job_on = rhs.create_job(_job_data(include_unused_objects=True))
    rhs._execute_job(job_on["id"])
    assert calls[-1]["include_unused_objects"] is True


def test_lock_contention(tmp_path, monkeypatch):
    import threading

    monkeypatch.setattr(rhs, "_JOBS_PATH", tmp_path / "jobs.json")
    started = threading.Event()
    release = threading.Event()

    def slow_bulk(*a, **kw):
        started.set()
        release.wait(timeout=5)
        return _make_results(1)

    monkeypatch.setattr(rhs, "_bulk_hygiene_adom", slow_bulk)
    sent = []
    monkeypatch.setattr(rhs, "_send_email", lambda *a: sent.append(a))
    monkeypatch.setattr(
        "app.smtp_client.load_smtp_config", lambda: {"run_history_days": 30}
    )

    job = rhs.create_job(_job_data())
    t1 = threading.Thread(target=rhs._execute_job, args=[job["id"]])
    t1.start()
    started.wait(timeout=5)
    rhs._execute_job(job["id"])  # second call — should skip
    release.set()
    t1.join(timeout=10)

    assert len(sent) == 1  # only one email


def test_run_history_pruning(tmp_path, monkeypatch):
    monkeypatch.setattr(rhs, "_JOBS_PATH", tmp_path / "jobs.json")
    monkeypatch.setattr(rhs, "_bulk_hygiene_adom", lambda *a, **kw: _make_results(1))
    monkeypatch.setattr(rhs, "_send_email", lambda *a: None)
    monkeypatch.setattr(
        "app.smtp_client.load_smtp_config", lambda: {"run_history_days": 30}
    )

    job = rhs.create_job(_job_data())
    now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
    old_run = {
        "ran_at": (now - datetime.timedelta(days=40)).isoformat() + "Z",
        "status": "ok",
        "packages_total": 1,
        "packages_reviewed": 1,
        "total_findings": 0,
        "emails_sent": 1,
        "errors": [],
    }
    rhs._append_run(job["id"], old_run)
    rhs._execute_job(job["id"])

    updated = next(j for j in rhs.get_all_jobs() if j["id"] == job["id"])
    cutoff = (now - datetime.timedelta(days=31)).isoformat()
    assert all(r["ran_at"] > cutoff for r in updated["runs"])


def test_error_in_one_package(tmp_path, monkeypatch):
    monkeypatch.setattr(rhs, "_JOBS_PATH", tmp_path / "jobs.json")
    monkeypatch.setattr(
        rhs, "_bulk_hygiene_adom", lambda *a, **kw: _make_results(3, error_idx=1)
    )
    monkeypatch.setattr(rhs, "_send_email", lambda *a: None)
    monkeypatch.setattr(
        "app.smtp_client.load_smtp_config", lambda: {"run_history_days": 30}
    )

    job = rhs.create_job(_job_data())
    rhs._execute_job(job["id"])

    updated = next(j for j in rhs.get_all_jobs() if j["id"] == job["id"])
    last_run = updated["runs"][0]
    assert last_run["status"] == "ok"
    assert last_run["packages_total"] == 3
    assert len(last_run["errors"]) == 1


def test_format_csv():
    result = _pkg_result(name="MyPkg", device="fw-01", n_findings=2)
    filename, data = rhs._build_attachment_rh(result, "csv", "2026-09-01T03:00:00Z")
    assert filename == "fw-01-MyPkg-2026-09-01.csv"
    content = data.decode()
    assert "Policy ID" in content
    assert "unnamed" in content


def test_format_json():
    result = _pkg_result(name="MyPkg", device="fw-01", n_findings=1)
    filename, data = rhs._build_attachment_rh(result, "json", "2026-09-01T03:00:00Z")
    assert filename == "fw-01-MyPkg-2026-09-01.json"
    parsed = json.loads(data)
    assert parsed["report_type"] == "rule_hygiene"
    assert "findings" in parsed


def test_zip_contains_expected_files():
    results = [_pkg_result(name=f"pkg{i}", device=f"fw-{i:02d}") for i in range(3)]
    attachments = rhs._build_all_attachments(results, "html", "2026-09-01T03:00:00Z")
    zip_bytes = rhs._make_zip(attachments)
    import io
    import zipfile

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        names = zf.namelist()
    assert len(names) == 3
    assert all(n.endswith(".html") for n in names)


def test_checks_empty_means_all(tmp_path, monkeypatch):
    monkeypatch.setattr(rhs, "_JOBS_PATH", tmp_path / "jobs.json")
    calls = []

    def fake_bulk(adom, checks, include_unused_objects=False, max_workers=4):
        calls.append({"checks": checks})
        return _make_results(1)

    monkeypatch.setattr(rhs, "_bulk_hygiene_adom", fake_bulk)
    monkeypatch.setattr(rhs, "_send_email", lambda *a: None)
    monkeypatch.setattr(
        "app.smtp_client.load_smtp_config", lambda: {"run_history_days": 30}
    )

    job = rhs.create_job(_job_data(checks=[]))
    rhs._execute_job(job["id"])

    assert len(calls) == 1
    assert calls[0]["checks"] == []


def test_run_history_recorded(tmp_path, monkeypatch):
    monkeypatch.setattr(rhs, "_JOBS_PATH", tmp_path / "jobs.json")
    monkeypatch.setattr(rhs, "_bulk_hygiene_adom", lambda *a, **kw: _make_results(2))
    monkeypatch.setattr(rhs, "_send_email", lambda *a: None)
    monkeypatch.setattr(
        "app.smtp_client.load_smtp_config", lambda: {"run_history_days": 30}
    )

    job = rhs.create_job(_job_data())
    rhs._execute_job(job["id"])

    updated = next(j for j in rhs.get_all_jobs() if j["id"] == job["id"])
    assert len(updated["runs"]) == 1
    run = updated["runs"][0]
    assert run["status"] == "ok"
    assert run["packages_total"] == 2
    assert run["emails_sent"] == 1
