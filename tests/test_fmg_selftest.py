import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

from app.fmg_client import FMGError, parse_fmg_version


class FakeClient:
    """Minimal stand-in for FMGClient: every method the self-test may call."""

    def __init__(
        self, *, adoms=None, devices=None, packages=None, raises=None, degrade=None
    ):
        self.adoms = adoms if adoms is not None else [{"name": "root"}]
        self.devices = devices if devices is not None else [{"name": "fw1"}]
        self.packages = (
            packages if packages is not None else [{"name": "pkg1", "path": "pkg1"}]
        )
        self.raises = raises or {}  # method name -> exception to raise
        self.degrade = degrade or {}  # op -> {"code":..} recorded as swallowed
        self.degraded = {}
        self.version = parse_fmg_version("v8.0.2-build0198 261006 (GA.F)")
        self.calls = []

    def _call(self, name, value):
        self.calls.append(name)
        if name in self.raises:
            raise self.raises[name]
        if name in self.degrade:
            self.degraded[name] = {"url": "/x", **self.degrade[name]}
            return {} if name != "get_audit_log" else []
        return value

    proxy_error = None  # set per-instance to simulate "No tunnel" etc.

    def get_device_proxy_error(self, adom, dev):
        return self._call("get_device_proxy_error", self.proxy_error)

    def get_system_status(self):
        return self._call("get_system_status", {"Version": "v8.0.2"})

    def get_adoms(self):
        return self._call("get_adoms", self.adoms)

    def get_performance(self):
        return self._call("get_performance", {"cpu": 1})

    def get_resource_usage(self):
        return self._call("get_resource_usage", {"cpu": 1})

    def get_audit_log(self, hours=24):
        return self._call("get_audit_log", [{"a": 1}])

    def get_devices(self, adom):
        return self._call("get_devices", self.devices)

    def get_devices_with_sync_status(self, adom):
        return self._call("get_devices_with_sync_status", self.devices)

    def get_adom_revisions(self, adom):
        return self._call("get_adom_revisions", [{"name": "fw1-rev"}])

    def get_policy_packages(self, adom):
        return self._call("get_policy_packages", self.packages)

    def get_policies(self, adom, pkg):
        return self._call("get_policies", [{"policyid": 1}])

    def get_address_objects(self, adom):
        return self._call("get_address_objects", [{"name": "a"}])

    def get_service_objects(self, adom):
        return self._call("get_service_objects", [{"name": "s"}])

    def get_vip_objects(self, adom):
        return self._call("get_vip_objects", [])

    def get_device_license_status(self, adom, dev):
        return self._call("get_device_license_status", {"forticare": {}})

    def get_device_system_global(self, adom, dev):
        return self._call("get_device_system_global", {"hostname": "x"})

    def get_device_interfaces(self, adom, dev):
        return self._call("get_device_interfaces", [{"name": "port1"}])


def _by_id(report):
    return {c["id"]: c for c in report["checks"]}


def test_all_ok_reports_version_sample_and_counts():
    from app.fmg_selftest import run_selftest

    r = run_selftest(FakeClient())
    assert r["fmg_version"] == "8.0.2"
    assert r["train"] == "8.0"
    assert r["sample"] == {"adom": "root", "device": "fw1", "package": "pkg1"}
    assert r["summary"]["error"] == 0 and r["summary"]["denied"] == 0
    assert r["summary"]["ok"] == len(r["checks"])
    assert all(isinstance(c["ms"], int) for c in r["checks"])


def test_permission_denied_exception_is_classified_denied_with_feature():
    from app.fmg_selftest import run_selftest

    fc = FakeClient(raises={"get_adom_revisions": FMGError("no perm", code=-11)})
    c = _by_id(run_selftest(fc))["adom_revisions"]
    assert c["status"] == "denied"
    assert c["code"] == -11
    assert c["feature"]  # human-readable impact is always present


def test_other_exception_is_error_with_message_and_does_not_stop_run():
    from app.fmg_selftest import run_selftest

    fc = FakeClient(raises={"get_address_objects": RuntimeError("boom")})
    r = run_selftest(fc)
    c = _by_id(r)["address_objects"]
    assert c["status"] == "error" and "boom" in c["message"]
    assert _by_id(r)["service_objects"]["status"] == "ok"


def test_swallowed_failure_recorded_in_degraded_is_surfaced_as_denied():
    from app.fmg_selftest import run_selftest

    fc = FakeClient(
        degrade={
            "get_performance": {"code": -11, "message": "No permission"},
            "get_audit_log": {"code": -11, "message": "No permission"},
        }
    )
    checks = _by_id(run_selftest(fc))
    assert checks["resource_performance"]["status"] == "denied"
    assert checks["audit_log"]["status"] == "denied"
    assert checks["resource_usage"]["status"] == "ok"


def test_swallowed_non_permission_failure_is_error():
    from app.fmg_selftest import run_selftest

    fc = FakeClient(degrade={"get_performance": {"code": None, "message": "timed out"}})
    c = _by_id(run_selftest(fc))["resource_performance"]
    assert c["status"] == "error" and "timed out" in c["message"]


def test_no_devices_skips_device_checks_instead_of_failing():
    from app.fmg_selftest import run_selftest

    r = run_selftest(FakeClient(devices=[]))
    checks = _by_id(r)
    assert r["sample"]["device"] is None
    assert checks["device_license"]["status"] == "skipped"
    assert checks["device_system_global"]["status"] == "skipped"
    assert r["summary"]["error"] == 0


def test_no_packages_skips_policy_check():
    from app.fmg_selftest import run_selftest

    r = run_selftest(FakeClient(packages=[]))
    assert _by_id(r)["policies"]["status"] == "skipped"


def test_forti_system_adoms_are_not_chosen_as_sample():
    from app.fmg_selftest import run_selftest

    r = run_selftest(
        FakeClient(
            adoms=[
                {"name": "FortiAnalyzer"},
                {"name": "forticarrier"},
                {"name": "Prod"},
            ]
        )
    )
    assert r["sample"]["adom"] == "Prod"


def test_never_runs_install_preview_or_writes():
    from app.fmg_selftest import run_selftest

    fc = FakeClient()
    run_selftest(fc)
    assert not any("preview" in c or "install" in c for c in fc.calls)


def test_total_failure_of_system_status_still_returns_a_report():
    from app.fmg_selftest import run_selftest

    fc = FakeClient(raises={"get_system_status": FMGError("down")})
    fc.version = None
    r = run_selftest(fc)
    assert r["fmg_version"] is None
    assert _by_id(r)["system_status"]["status"] == "error"


def test_reachable_device_reports_device_proxy_ok():
    from app.fmg_selftest import run_selftest

    c = _by_id(run_selftest(FakeClient()))["device_proxy"]
    assert c["status"] == "ok"


def test_unreachable_device_is_an_error_and_skips_dependent_proxy_checks():
    from app.fmg_selftest import run_selftest

    fc = FakeClient()
    fc.proxy_error = {"code": -1, "message": "fw1(169) error: No tunnel 80."}
    r = run_selftest(fc)
    checks = _by_id(r)
    assert checks["device_proxy"]["status"] == "error"
    assert "No tunnel" in checks["device_proxy"]["message"]
    for cid in ("device_license", "device_system_global", "device_interfaces"):
        assert checks[cid]["status"] == "skipped", cid
        assert "unreachable" in checks[cid]["message"].lower()
    # Dependent checks must not even be attempted against a device FMG can't reach.
    assert "get_device_license_status" not in fc.calls
    assert r["summary"]["error"] == 1
