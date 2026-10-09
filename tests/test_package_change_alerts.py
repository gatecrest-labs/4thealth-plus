import csv
import io
import json

import pytest

from app import package_change_alerts as pca


def _c(line, t="modify"):
    return {"type": t, "line": line}


POLICY_BLOCK = [
    _c("config firewall policy"),
    _c("    edit 5"),
    _c("        set action accept", "add"),
    _c("    next"),
    _c("end"),
]
IFACE_BLOCK = [
    _c("config system interface"),
    _c("    edit port1"),
    _c("        set alias x", "add"),
    _c("    next"),
    _c("end"),
]


def test_filter_keeps_policy_drops_interface():
    kept = pca.filter_policy_changes(POLICY_BLOCK + IFACE_BLOCK)
    assert kept == POLICY_BLOCK


def test_filter_only_unrelated_changes_is_empty():
    assert pca.filter_policy_changes(IFACE_BLOCK) == []


def test_filter_empty_input():
    assert pca.filter_policy_changes([]) == []


@pytest.mark.parametrize(
    "section",
    [
        "firewall policy",
        "firewall address",
        "firewall addrgrp",
        "firewall service custom",
        "firewall vip",
    ],
)
def test_filter_keeps_all_policy_related_sections(section):
    block = [
        _c(f"config {section}"),
        _c("    edit x"),
        _c("        set comment y", "add"),
        _c("    next"),
        _c("end"),
    ]
    assert pca.filter_policy_changes(block) == block


def test_filter_nested_config_does_not_end_section_early():
    block = [
        _c("config firewall policy"),
        _c("    edit 7"),
        _c("        config identity-based-policy"),
        _c("            edit 1"),
        _c("            next"),
        _c("        end"),
        _c("        set comment after-nested", "add"),
        _c("    next"),
        _c("end"),
    ]
    assert pca.filter_policy_changes(block + IFACE_BLOCK) == block


def test_filter_frame_only_section_is_empty():
    assert pca.filter_policy_changes([_c("config firewall policy"), _c("end")]) == []


def test_package_targets_expands_groups_and_keeps_vdom():
    packages = [
        {"name": "Pkg-A", "scope member": [{"name": "FW1", "vdom": "root"}]},
        {"name": "Pkg-B", "scope member": [{"name": "GRP", "vdom": ""}]},
        {"name": "Folder", "type": "folder"},
        {"name": "Pkg-C"},
    ]
    out = pca.package_targets(packages, {"GRP": ["FW2", "FW3"]})
    assert out["Pkg-A"] == [("FW1", "root")]
    assert out["Pkg-B"] == [("FW2", ""), ("FW3", "")]
    assert out["Pkg-C"] == []
    assert "Folder" not in out


def _result(device, status="ok", vdoms=None):
    return {"device": device, "status": status, "vdoms": vdoms or []}


def test_collect_package_diffs_filters_and_matches_vdom():
    results = [
        _result(
            "FW1",
            vdoms=[
                {"name": "root", "changes": POLICY_BLOCK + IFACE_BLOCK},
                {"name": "dmz", "changes": POLICY_BLOCK},
            ],
        ),
        _result("FW2", status="no_changes"),
    ]
    diffs = pca.collect_package_diffs([("FW1", "root"), ("FW2", "")], results)
    assert diffs == {"FW1": {"root": POLICY_BLOCK}}


def test_collect_package_diffs_empty_vdom_means_all_vdoms():
    results = [
        _result(
            "FW1",
            vdoms=[
                {"name": "root", "changes": POLICY_BLOCK},
                {"name": "dmz", "changes": POLICY_BLOCK},
            ],
        )
    ]
    diffs = pca.collect_package_diffs([("FW1", "")], results)
    assert set(diffs["FW1"]) == {"root", "dmz"}


def test_collect_package_diffs_ignores_unrelated_only_devices():
    results = [_result("FW1", vdoms=[{"name": "root", "changes": IFACE_BLOCK}])]
    assert pca.collect_package_diffs([("FW1", "root")], results) == {}


def test_has_unreadable_targets():
    results = [_result("FW1", status="error"), _result("FW2")]
    assert pca.has_unreadable_targets([("FW1", "")], results) is True
    assert pca.has_unreadable_targets([("FW2", "")], results) is False
    # a device absent from the preview results is unknown, not clean
    assert pca.has_unreadable_targets([("FW9", "")], results) is True


def test_diff_hash_is_stable_and_order_independent_across_devices():
    a = {"FW1": {"root": POLICY_BLOCK}, "FW2": {"root": POLICY_BLOCK}}
    b = {"FW2": {"root": POLICY_BLOCK}, "FW1": {"root": POLICY_BLOCK}}
    assert pca.diff_hash(a) == pca.diff_hash(b)
    changed = {"FW1": {"root": POLICY_BLOCK[:-1]}}
    assert pca.diff_hash(a) != pca.diff_hash(changed)


@pytest.fixture
def rules_path(tmp_path, monkeypatch):
    p = tmp_path / "package_change_alerts.json"
    monkeypatch.setattr(pca, "_RULES_PATH", p)
    return p


def _rule_data(**overrides):
    base = {
        "name": "Owners",
        "adom": "Corp",
        "packages": [],
        "email": "a@b.com",
        "format": "html",
        "enabled": True,
    }
    base.update(overrides)
    return base


def test_create_rule_defaults(rules_path):
    rule = pca.create_rule(_rule_data())
    assert rule["id"]
    assert rule["packages"] == []
    assert rule["sent"] == {}
    assert rule["runs"] == []
    assert pca.get_all_rules() == [rule]


@pytest.mark.parametrize(
    "field,value,match",
    [
        ("name", "  ", "name"),
        ("adom", "", "adom"),
        ("email", "", "email"),
        ("format", "pdf", "format"),
        ("packages", "Pkg", "packages"),
        ("packages", ["ok", ""], "packages"),
    ],
)
def test_create_rule_validation(rules_path, field, value, match):
    with pytest.raises(ValueError, match=match):
        pca.create_rule(_rule_data(**{field: value}))


def test_update_rule_preserves_state(rules_path):
    rule = pca.create_rule(_rule_data())
    pca._save_rule_state(rule["id"], {"Pkg": "abc"}, {"ran_at": "t", "status": "ok"})
    updated = pca.update_rule(rule["id"], _rule_data(name="New", email="c@d.com"))
    assert updated["name"] == "New"
    assert updated["sent"] == {"Pkg": "abc"}
    assert len(updated["runs"]) == 1


def test_update_and_delete_missing_rule(rules_path):
    with pytest.raises(KeyError):
        pca.update_rule("nope", _rule_data())
    with pytest.raises(KeyError):
        pca.delete_rule("nope")


def test_delete_rule(rules_path):
    rule = pca.create_rule(_rule_data())
    pca.delete_rule(rule["id"])
    assert pca.get_all_rules() == []


def test_save_rule_state_caps_runs_and_skips_missing_rule(rules_path):
    rule = pca.create_rule(_rule_data())
    for i in range(pca._MAX_RUNS + 5):
        pca._save_rule_state(rule["id"], {}, {"ran_at": str(i), "status": "ok"})
    runs = pca.get_all_rules()[0]["runs"]
    assert len(runs) == pca._MAX_RUNS
    assert runs[0]["ran_at"] == str(pca._MAX_RUNS + 4)  # newest first
    pca._save_rule_state(
        "deleted-rule", {}, {"ran_at": "x", "status": "ok"}
    )  # no raise


def test_diff_attachment_json():
    diffs = {"FW1": {"root": POLICY_BLOCK}}
    att = pca.build_diff_attachment(
        "Corp", "Pkg/A b", diffs, "json", "2026-10-02T01:00:00Z"
    )
    assert att["mimetype"] == "application/json"
    assert att["filename"] == "Pkg_A_b-policy-changes-2026-10-02.json"
    payload = json.loads(att["data"])
    assert payload["package"] == "Pkg/A b"
    assert payload["devices"]["FW1"]["root"][0]["line"] == "config firewall policy"


def test_diff_attachment_csv_rows():
    diffs = {"FW1": {"root": POLICY_BLOCK}}
    att = pca.build_diff_attachment("Corp", "Pkg", diffs, "csv", "2026-10-02T01:00:00Z")
    rows = list(csv.reader(io.StringIO(att["data"].decode())))
    assert ["device", "vdom", "type", "line"] in rows
    assert ["FW1", "root", "add", "        set action accept"] in rows


def test_diff_attachment_html_escapes():
    diffs = {"FW1": {"root": [_c("set comment <script>alert(1)</script>", "add")]}}
    att = pca.build_diff_attachment(
        "Corp", "<b>Pkg</b>", diffs, "html", "2026-10-02T01:00:00Z"
    )
    body = att["data"].decode()
    assert "<script>" not in body and "<b>Pkg</b>" not in body
    assert "&lt;script&gt;" in body


def test_build_email_html_lists_devices_and_escapes():
    diffs = {"FW<1>": {"root": POLICY_BLOCK}}
    body = pca.build_email_html("Rule", "Corp", "Pkg", diffs, "2026-10-02T01:00:00Z")
    assert "FW&lt;1&gt;" in body
    assert "Pkg" in body and "Corp" in body


def test_policy_reports_groups_attachments_by_package(monkeypatch):
    from app import rule_policy_scheduler as rp

    monkeypatch.setattr(
        rp,
        "_bulk_policy_adom",
        lambda adom, pkgs, g, h, w=4: {
            "results": [
                {"package_name": "Pkg-A", "error": None},
                {"package_name": "Pkg-B", "error": "boom"},
            ],
            "skipped": [],
        },
    )
    monkeypatch.setattr(
        rp,
        "_build_attachment_rp",
        lambda r, job, fmt: [(f"{r['package_name']}.html", b"x")],
    )
    out = pca._policy_reports("Corp", ["Pkg-A", "Pkg-B"], "html")
    assert list(out) == [
        "Pkg-A"
    ]  # errored package omitted so caller treats it as failed
    assert out["Pkg-A"] == [
        {"filename": "Pkg-A.html", "data": b"x", "mimetype": "text/html"}
    ]


@pytest.fixture
def harness(rules_path, monkeypatch):
    sent = []
    state = {"fail_send": False, "fail_reports": False}

    monkeypatch.setattr(
        pca,
        "_fetch_packages_and_groups",
        lambda adom: (
            [
                {"name": "Pkg-A", "scope member": [{"name": "FW1", "vdom": "root"}]},
                {"name": "Pkg-B", "scope member": [{"name": "FW2", "vdom": "root"}]},
            ],
            {},
        ),
    )

    def fake_reports(adom, packages, fmt):
        if state["fail_reports"]:
            raise RuntimeError("fmg down")
        return {
            p: [{"filename": f"{p}.html", "data": b"x", "mimetype": "text/html"}]
            for p in packages
        }

    monkeypatch.setattr(pca, "_policy_reports", fake_reports)

    def fake_send(to, subject, body, attachments):
        if state["fail_send"]:
            raise RuntimeError("smtp down")
        sent.append({"to": to, "subject": subject, "atts": attachments})

    monkeypatch.setattr(pca, "_send_email", fake_send)
    return sent, state


def _results(a=True, b=False, fw1_status="ok"):
    return [
        _result(
            "FW1",
            status=fw1_status,
            vdoms=[{"name": "root", "changes": POLICY_BLOCK if a else []}],
        ),
        _result("FW2", vdoms=[{"name": "root", "changes": POLICY_BLOCK if b else []}]),
    ]


def test_sends_one_email_per_changed_package_with_two_attachments(harness, rules_path):
    sent, _ = harness
    pca.create_rule(_rule_data(packages=[]))
    pca.evaluate_alerts("Corp", _results(a=True, b=True))
    assert len(sent) == 2
    for m in sent:
        assert len(m["atts"]) == 2  # diff + policy report
        assert "-policy-changes-" in m["atts"][0]["filename"]  # attachment 1 = diff
        assert m["atts"][1]["filename"].endswith(
            ".html"
        )  # attachment 2 = policy report
    assert {m["subject"] for m in sent} == {
        "[Package Change] Corp / Pkg-A",
        "[Package Change] Corp / Pkg-B",
    }


def test_only_watched_packages_alert(harness, rules_path):
    sent, _ = harness
    pca.create_rule(_rule_data(packages=["Pkg-B"]))
    pca.evaluate_alerts("Corp", _results(a=True, b=True))
    assert [m["subject"] for m in sent] == ["[Package Change] Corp / Pkg-B"]


def test_same_diff_is_not_resent(harness, rules_path):
    sent, _ = harness
    pca.create_rule(_rule_data())
    pca.evaluate_alerts("Corp", _results())
    pca.evaluate_alerts("Corp", _results())
    assert len(sent) == 1


def test_changed_diff_resends(harness, rules_path):
    sent, _ = harness
    pca.create_rule(_rule_data())
    pca.evaluate_alerts("Corp", _results())
    changed = _results()
    changed[0]["vdoms"][0]["changes"] = POLICY_BLOCK[:-1] + [
        _c("    set x", "add"),
        _c("end"),
    ]
    pca.evaluate_alerts("Corp", changed)
    assert len(sent) == 2


def test_clean_run_rearms_identical_diff(harness, rules_path):
    sent, _ = harness
    pca.create_rule(_rule_data())
    pca.evaluate_alerts("Corp", _results(a=True))
    pca.evaluate_alerts("Corp", _results(a=False))  # installed -> clean
    pca.evaluate_alerts("Corp", _results(a=True))  # same diff again
    assert len(sent) == 2


def test_errored_device_does_not_rearm(harness, rules_path):
    sent, _ = harness
    pca.create_rule(_rule_data())
    pca.evaluate_alerts("Corp", _results(a=True))
    pca.evaluate_alerts("Corp", _results(a=False, fw1_status="error"))  # unreadable
    pca.evaluate_alerts("Corp", _results(a=True))  # same diff
    assert len(sent) == 1


def test_send_failure_is_retried_and_isolated(harness, rules_path):
    sent, state = harness
    pca.create_rule(_rule_data())
    state["fail_send"] = True
    pca.evaluate_alerts("Corp", _results(a=True, b=True))
    stored = pca.get_all_rules()[0]
    assert stored["sent"] == {}
    assert stored["runs"][0]["status"] == "error"
    assert (
        len(stored["runs"][0]["errors"]) == 2
    )  # both tried; neither blocked the other
    state["fail_send"] = False
    pca.evaluate_alerts("Corp", _results(a=True, b=True))
    assert len(sent) == 2


def test_report_failure_leaves_package_unsent(harness, rules_path):
    sent, state = harness
    pca.create_rule(_rule_data())
    state["fail_reports"] = True
    pca.evaluate_alerts("Corp", _results(a=True))
    assert sent == []
    assert pca.get_all_rules()[0]["sent"] == {}
    state["fail_reports"] = False
    pca.evaluate_alerts("Corp", _results(a=True))
    assert len(sent) == 1


def test_disabled_and_other_adom_rules_ignored(harness, rules_path):
    sent, _ = harness
    pca.create_rule(_rule_data(enabled=False))
    pca.create_rule(_rule_data(adom="Other"))
    pca.evaluate_alerts("Corp", _results(a=True))
    assert sent == []


def test_no_rules_makes_no_fmg_calls(rules_path, monkeypatch):
    def boom(adom):
        raise AssertionError("must not call FMG with no rules")

    monkeypatch.setattr(pca, "_fetch_packages_and_groups", boom)
    pca.evaluate_alerts("Corp", _results())


def test_rule_deleted_mid_evaluation_is_skipped(harness, rules_path, monkeypatch):
    _sent, _ = harness
    rule = pca.create_rule(_rule_data())
    real_send = pca._send_email

    def send_then_delete(*a, **k):
        real_send(*a, **k)
        pca.delete_rule(rule["id"])

    monkeypatch.setattr(pca, "_send_email", send_then_delete)
    pca.evaluate_alerts("Corp", _results(a=True))  # must not raise
    assert pca.get_all_rules() == []


def test_send_test_email(harness, rules_path):
    sent, _ = harness
    rule = pca.create_rule(_rule_data())
    pca.send_test_email(rule["id"])
    assert sent[0]["atts"] == [] and "TEST" in sent[0]["subject"]
    assert pca.get_all_rules()[0]["sent"] == {}
    with pytest.raises(KeyError):
        pca.send_test_email("nope")


# ── Final-review fixes ────────────────────────────────────────────────────────

_IFACE_RAW = """        config system interface
            edit port1
                set alias x
            next
        end
"""
_POLICY_RAW = """        config firewall policy
            edit 5
                set action accept
            next
        end
"""


def _real_changes(body):
    """Run a FortiManager Format-B diff through the real parser."""
    from app.fmg_client import parse_preview_diff

    raw = "config vdom\n    edit root\n" + body + "    next\nend\n"
    return parse_preview_diff(raw)["vdoms"][0]["changes"]


def _kept_lines(body):
    return [c["line"].strip() for c in pca.filter_policy_changes(_real_changes(body))]


def test_real_parser_policy_after_unrelated_block_is_kept():
    kept = _kept_lines(_IFACE_RAW + _POLICY_RAW)
    assert "config firewall policy" in kept and "edit 5" in kept
    assert "edit port1" not in kept and "config system interface" not in kept


def test_real_parser_unrelated_block_after_policy_is_dropped():
    kept = _kept_lines(_POLICY_RAW + _IFACE_RAW)
    assert "edit 5" in kept
    assert "edit port1" not in kept and "config system interface" not in kept


def test_real_parser_unrelated_only_is_empty():
    assert _kept_lines(_IFACE_RAW) == []


def test_real_parser_nested_config_stays_in_policy_section():
    nested = """        config firewall policy
            edit 7
                config identity-based-policy
                    edit 1
                    next
                end
                set comment after-nested
            next
        end
"""
    kept = _kept_lines(_IFACE_RAW + nested)
    assert "set comment after-nested" in kept
    assert "edit port1" not in kept


def _two_target_harness(monkeypatch, rules_path):
    sent = []
    monkeypatch.setattr(
        pca,
        "_fetch_packages_and_groups",
        lambda adom: (
            [
                {
                    "name": "Pkg-A",
                    "scope member": [
                        {"name": "FW1", "vdom": "root"},
                        {"name": "FW2", "vdom": "root"},
                    ],
                }
            ],
            {},
        ),
    )
    monkeypatch.setattr(
        pca,
        "_policy_reports",
        lambda adom, pkgs, fmt: {
            p: [{"filename": f"{p}.html", "data": b"x", "mimetype": "text/html"}]
            for p in pkgs
        },
    )
    monkeypatch.setattr(
        pca, "_send_email", lambda to, subj, body, atts: sent.append(subj)
    )
    return sent


def _two_results(fw2_status="ok"):
    return [
        _result("FW1", vdoms=[{"name": "root", "changes": POLICY_BLOCK}]),
        _result(
            "FW2",
            status=fw2_status,
            vdoms=[{"name": "root", "changes": POLICY_BLOCK}],
        ),
    ]


def test_partial_unreadable_targets_skip_package_and_keep_state(
    rules_path, monkeypatch
):
    sent = _two_target_harness(monkeypatch, rules_path)
    pca.create_rule(_rule_data())
    pca.evaluate_alerts("Corp", _two_results())  # both readable -> 1 alert
    before = pca.get_all_rules()[0]["sent"]
    pca.evaluate_alerts("Corp", _two_results(fw2_status="error"))  # FW2 unreadable
    pca.evaluate_alerts("Corp", _two_results())  # FW2 back, same diff
    assert len(sent) == 1  # no partial-diff alert, no duplicate afterwards
    assert pca.get_all_rules()[0]["sent"] == before
    skipped = [r for r in pca.get_all_rules()[0]["runs"] if r.get("skipped")]
    assert skipped and "Pkg-A" in skipped[0]["skipped"][0]


def test_unknown_group_scope_does_not_clear_state(rules_path, monkeypatch):
    # Group lookup failed: scope member "GRP" was not expanded, so its
    # "device" never appears in the preview results.
    sent = []
    monkeypatch.setattr(
        pca,
        "_fetch_packages_and_groups",
        lambda adom: ([{"name": "Pkg-A", "scope member": [{"name": "GRP"}]}], {}),
    )
    monkeypatch.setattr(pca, "_send_email", lambda *a: sent.append(a))
    rule = pca.create_rule(_rule_data())
    pca._save_rule_state(rule["id"], {"Pkg-A": "hash"}, {"ran_at": "t", "status": "ok"})
    pca.evaluate_alerts("Corp", _results(a=False))
    assert pca.get_all_rules()[0]["sent"] == {"Pkg-A": "hash"}
    assert sent == []


def test_watched_package_missing_from_adom_keeps_state(harness, rules_path):
    rule = pca.create_rule(_rule_data(packages=["Gone"]))
    pca._save_rule_state(rule["id"], {"Gone": "hash"}, {"ran_at": "t", "status": "ok"})
    pca.evaluate_alerts("Corp", _results(a=False))
    stored = pca.get_all_rules()[0]
    assert stored["sent"] == {"Gone": "hash"}
    assert "Gone" in stored["runs"][0]["skipped"][0]


def test_fetch_rejects_empty_package_list(monkeypatch):
    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get_policy_packages(self, adom):
            return []  # what FMGClient returns when the call errors

    monkeypatch.setattr("app.fmg_helpers.make_client", lambda: FakeClient())
    with pytest.raises(RuntimeError, match="no policy packages"):
        pca._fetch_packages_and_groups("Corp")


def test_package_lookup_failure_is_recorded_on_every_rule(rules_path, monkeypatch):
    def boom(adom):
        raise RuntimeError("fmg login failed")

    monkeypatch.setattr(pca, "_fetch_packages_and_groups", boom)
    r1 = pca.create_rule(_rule_data(name="one"))
    pca.create_rule(_rule_data(name="two"))
    pca._save_rule_state(r1["id"], {"Pkg-A": "hash"}, {"ran_at": "t", "status": "ok"})
    pca.evaluate_alerts("Corp", _results())  # must not raise
    for rule in pca.get_all_rules():
        assert rule["runs"][0]["status"] == "error"
        assert "fmg login failed" in rule["runs"][0]["errors"][0]
    assert pca.get_all_rules()[0]["sent"] == {"Pkg-A": "hash"}  # state untouched


def test_one_rule_failing_does_not_stop_the_others(harness, rules_path, monkeypatch):
    sent, _ = harness
    pca.create_rule(_rule_data(name="broken"))
    pca.create_rule(_rule_data(name="fine"))
    real = pca.collect_package_diffs
    calls = {"n": 0}

    def flaky(targets, results):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("disk full")
        return real(targets, results)

    monkeypatch.setattr(pca, "collect_package_diffs", flaky)
    pca.evaluate_alerts("Corp", _results(a=True))  # must not raise
    rules = {r["name"]: r for r in pca.get_all_rules()}
    assert rules["broken"]["runs"][0]["status"] == "error"
    assert "disk full" in rules["broken"]["runs"][0]["errors"][0]
    assert len(sent) == 1  # the second rule still alerted
