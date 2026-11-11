"""Job handlers equal the synchronous endpoints (Phase 6, Task 2)."""
# ruff: noqa: RUF059

import json
import time
from unittest.mock import patch

import pytest

from app import job_handlers
from app.config import Config
from app.fmg_client import FMGClient
from app.synthetic_fmg import SyntheticFMG

_USERS = {"admin": {"password_hash": "$2b$12$placeholder", "role": "admin"}}


@pytest.fixture
def rig(monkeypatch):
    for k, v in (
        ("INVENTORY_CACHE", False),
        ("AUDIT_SNAPSHOTS", False),
        ("POLICY_STORE", False),
    ):
        monkeypatch.setattr(Config, k, v)
    synth = SyntheticFMG(
        adoms=1, devices=4, packages_per_adom=2, rules_per_package=8, seed=5
    )
    real = FMGClient(host="fmg.example", token="t")
    real._post = synth.post
    for mod in (
        "app.routes.audit_review_routes.make_client",
        "app.routes.hygiene_routes.make_client",
        "app.fmg_helpers.make_client",
    ):
        monkeypatch.setattr(mod, lambda: real)
    adom = next(
        a["name"] for a in real.get_adoms() if not a["name"].lower().startswith("forti")
    )
    return real, adom


@pytest.fixture
def http():
    from app import create_app

    app = create_app()
    with app.test_client() as c, patch("app.auth._load_users", return_value=_USERS):
        with c.session_transaction() as sess:
            sess["user"], sess["role"], sess["_csrf_token"], sess["login_at"] = (
                "admin",
                "admin",
                "t",
                int(time.time()),
            )
        yield c


def _post(c, url, payload):
    return c.post(
        url,
        data=json.dumps(payload),
        content_type="application/json",
        headers={"X-CSRF-Token": "t"},
    )


def _stable(d):
    return {
        k: v
        for k, v in d.items()
        if k not in ("run_at", "data_as_of", "source", "collected_at")
    }


def test_prepare_validates():
    with pytest.raises(ValueError):
        job_handlers.prepare("nope", {"adom": "A"})
    with pytest.raises(ValueError):
        job_handlers.prepare("device_review", {})
    with pytest.raises(ValueError):
        job_handlers.prepare("device_review", {"adom": "A", "checks": ["bogus"]})
    with pytest.raises(ValueError):
        job_handlers.prepare("hygiene_run", {"adom": "A"})
    adom, req = job_handlers.prepare(
        "device_review", {"adom": " A ", "checks": ["ntp_config", "bogus"], "live": 1}
    )
    assert (
        adom == "A"
        and req["checks"] == ["ntp_config"]
        and req["live"] is True
        and req["devices"] == []
    )


def test_device_review_job_result_equals_endpoint_and_reports_progress(rig, http):
    real, adom = rig
    sync = _post(
        http, "/api/audit-review/run", {"adom": adom, "devices": [], "check_params": {}}
    ).get_json()
    _a, req = job_handlers.prepare("device_review", {"adom": adom})
    seen = []
    result, cancelled = job_handlers.run(
        "device_review", adom, req, lambda d, t, m: seen.append((d, t)), lambda: False
    )
    assert not cancelled and _stable(result) == _stable(sync)
    assert seen[-1] == (4, 4) and len(seen) == 4


def test_device_review_job_cancels_between_devices(rig):
    real, adom = rig
    _a, req = job_handlers.prepare("device_review", {"adom": adom})
    calls = {"n": 0}

    def should_cancel():
        calls["n"] += 1
        return calls["n"] > 2

    result, cancelled = job_handlers.run(
        "device_review", adom, req, lambda *a: None, should_cancel
    )
    assert cancelled and result["device_count"] == 2 and result["cancelled"] is True


def test_hygiene_job_result_equals_endpoint(rig, http):
    real, adom = rig
    pkg = http.get(f"/api/hygiene/adoms/{adom}/packages").get_json()
    first = pkg[0] if isinstance(pkg, list) else pkg["packages"][0]
    path = first.get("path") or first.get("name")
    sync = _post(http, "/api/hygiene/run", {"adom": adom, "path": path}).get_json()
    _a, req = job_handlers.prepare("hygiene_run", {"adom": adom, "path": path})
    result, cancelled = job_handlers.run(
        "hygiene_run", adom, req, lambda *a: None, lambda: False
    )
    assert (
        not cancelled
        and _stable(result) == _stable(sync)
        and result["policy_count"] > 0
    )
