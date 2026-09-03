import os
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

from datetime import date
from app.hygiene_fix import _append_tag, _find_tag, build_fixes


def test_append_tag_no_prior_comment():
    result = _append_tag("", date(2026, 9, 3))
    assert result == "[HygieneFix 2026-09-03]"


def test_append_tag_preserves_prior_comment():
    result = _append_tag("Allow vendor access", date(2026, 9, 3))
    assert result == "Allow vendor access [HygieneFix 2026-09-03]"


def test_append_tag_exempt_marker():
    result = _append_tag("Reviewed", date(2026, 9, 3), exempt=True)
    assert result == "Reviewed [HygieneFix EXEMPT 2026-09-03]"


def test_append_tag_truncates_long_comment_to_255_chars():
    long_comment = "x" * 300
    result = _append_tag(long_comment, date(2026, 9, 3))
    assert len(result) <= 255
    assert result.endswith("[HygieneFix 2026-09-03]")


def test_find_tag_returns_date_when_present():
    assert _find_tag("Old note [HygieneFix 2026-06-01]") == date(2026, 6, 1)


def test_find_tag_returns_none_when_absent():
    assert _find_tag("No tag here") is None


def test_find_tag_matches_exempt_variant():
    assert _find_tag("Reviewed [HygieneFix EXEMPT 2026-06-01]") == date(2026, 6, 1)


def _live_policy(policyid, logtraffic="disable", comments=""):
    return {"policyid": policyid, "name": "rule-1", "logtraffic": logtraffic, "comments": comments}


def test_build_fixes_unlogged_generates_cli():
    live = [_live_policy(10)]
    findings = [{"policy_id": "10", "policy_name": "rule-1", "check": "unlogged", "detail": "no logging"}]
    result = build_fixes(live, findings, now=None)
    assert result["stale_findings"] == []
    assert len(result["fixes"]) == 1
    fix = result["fixes"][0]
    assert fix["check"] == "unlogged"
    assert len(fix["options"]) == 1
    assert "set logtraffic all" in fix["options"][0]["cli"][0]
    assert "edit 10" in fix["options"][0]["cli"][0]


def test_build_fixes_flags_stale_finding():
    live = [_live_policy(10)]
    findings = [{"policy_id": "999", "policy_name": "ghost", "check": "unlogged", "detail": "no logging"}]
    result = build_fixes(live, findings, now=None)
    assert result["fixes"] == []
    assert len(result["stale_findings"]) == 1
    assert "policy_id not found" in result["stale_findings"][0]["reason"]


def test_build_fixes_skips_unknown_check_key():
    live = [_live_policy(10)]
    findings = [{"policy_id": "10", "policy_name": "rule-1", "check": "not_a_real_check", "detail": "x"}]
    result = build_fixes(live, findings, now=None)
    assert result["fixes"] == []
    assert result["stale_findings"] == []


def test_unnamed_suggests_name_from_src_and_dst():
    live = [{"policyid": 5, "name": "", "srcaddr": ["Vendor-API"], "dstaddr": ["Internal-DB"], "comments": ""}]
    findings = [{"policy_id": "5", "policy_name": "Policy #5", "check": "unnamed", "detail": "no name"}]
    result = build_fixes(live, findings, now=None)
    opt = result["fixes"][0]["options"][0]
    assert 'set name "Allow Vendor-API to Internal-DB"' in opt["cli"][0]
    assert "[HygieneFix" in opt["new_comment"]


def test_unnamed_falls_back_to_unknown_when_no_specific_reference():
    live = [{"policyid": 6, "name": "", "srcaddr": ["all"], "dstaddr": ["any"], "comments": ""}]
    findings = [{"policy_id": "6", "policy_name": "Policy #6", "check": "unnamed", "detail": "no name"}]
    result = build_fixes(live, findings, now=None)
    opt = result["fixes"][0]["options"][0]
    assert 'set name "Unknown -- Requires additional research"' in opt["cli"][0]


def test_expired_disables_and_tags():
    live = [{"policyid": 7, "name": "old-rule", "comments": ""}]
    findings = [{"policy_id": "7", "policy_name": "old-rule", "check": "expired", "detail": "past end date"}]
    result = build_fixes(live, findings, now=None)
    opt = result["fixes"][0]["options"][0]
    assert "set status disable" in opt["cli"][0]
    assert "[HygieneFix" in opt["new_comment"]


def test_unhit_disables_and_tags():
    live = [{"policyid": 8, "name": "unused-rule", "comments": "orig note"}]
    findings = [{"policy_id": "8", "policy_name": "unused-rule", "check": "unhit", "detail": "zero hits"}]
    result = build_fixes(live, findings, now=None)
    opt = result["fixes"][0]["options"][0]
    assert "set status disable" in opt["cli"][0]
    assert opt["new_comment"].startswith("orig note")


from datetime import UTC, datetime


def test_missing_security_profile_returns_no_options():
    live = [{"policyid": 9, "name": "no-utm", "comments": ""}]
    findings = [{"policy_id": "9", "policy_name": "no-utm", "check": "missing_security_profile", "detail": "no UTM"}]
    result = build_fixes(live, findings, now=None)
    assert result["fixes"][0]["options"] == []


def test_disabled_with_no_prior_tag_proposes_adding_one():
    live = [{"policyid": 11, "name": "old-disabled", "comments": "manually turned off"}]
    findings = [{"policy_id": "11", "policy_name": "old-disabled", "check": "disabled", "detail": "status=disable"}]
    result = build_fixes(live, findings, now=datetime(2026, 9, 3, tzinfo=UTC))
    opt = result["fixes"][0]["options"][0]
    assert opt["option_id"] == "tag"
    assert "[HygieneFix 2026-09-03]" in opt["new_comment"]


def test_disabled_with_tag_under_90_days_needs_no_action():
    live = [{"policyid": 12, "name": "recently-disabled", "comments": "note [HygieneFix 2026-08-01]"}]
    findings = [{"policy_id": "12", "policy_name": "recently-disabled", "check": "disabled", "detail": "status=disable"}]
    result = build_fixes(live, findings, now=datetime(2026, 9, 3, tzinfo=UTC))
    assert result["fixes"][0]["options"] == []


def test_disabled_with_tag_over_90_days_proposes_delete():
    live = [{"policyid": 13, "name": "stale-disabled", "comments": "note [HygieneFix 2026-01-01]"}]
    findings = [{"policy_id": "13", "policy_name": "stale-disabled", "check": "disabled", "detail": "status=disable"}]
    result = build_fixes(live, findings, now=datetime(2026, 9, 3, tzinfo=UTC))
    opt = result["fixes"][0]["options"][0]
    assert opt["option_id"] == "delete"
    assert "delete 13" in opt["cli"][0]
    assert opt["new_comment"] is None


def test_over_permissive_returns_disable_and_exempt_options():
    live = [{"policyid": 14, "name": "wide-open", "comments": ""}]
    findings = [{"policy_id": "14", "policy_name": "wide-open", "check": "over_permissive", "detail": "fully open"}]
    result = build_fixes(live, findings, now=None)
    options = result["fixes"][0]["options"]
    assert [o["option_id"] for o in options] == ["disable", "exempt"]
    assert "set status disable" in options[0]["cli"][0]
    assert "EXEMPT" in options[1]["new_comment"]
    assert "set status disable" not in options[1]["cli"][0]


def test_redundant_disables_later_rule_and_names_duplicate():
    live = [{"policyid": 15, "name": "later-rule", "comments": ""}]
    findings = [{
        "policy_id": "15", "policy_name": "later-rule", "check": "redundant",
        "detail": "matches earlier rule",
        "duplicate_of": {"id": "3", "name": "earlier-rule"},
    }]
    result = build_fixes(live, findings, now=None)
    opt = result["fixes"][0]["options"][0]
    assert "set status disable" in opt["cli"][0]
    assert "earlier-rule" in opt["description"]
    assert "id 3" in opt["description"]
