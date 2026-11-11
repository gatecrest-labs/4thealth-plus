"""Tests for app.rule_lookup_ai.build_lookup_narrative."""
import json
from unittest.mock import patch

from app import rule_lookup_ai


def _rows(n):
    return [{"policyid": i, "name": f"r{i}", "srcaddr": ["a"], "dstaddr": ["b"],
             "service": ["HTTPS"], "action": "accept", "status": "enable",
             "comment": "secret comment", "match": {"src": {"names": {"a": "exact"}}}}
            for i in range(n)]


def _capture(rows, skipped=3, total=None):
    seen = {}

    def fake(system_prompt, payload, *, feature, user=None):
        seen.update(system=system_prompt, payload=payload, feature=feature, user=user)
        return "ok", None

    with patch("app.rule_lookup_ai.safe_narrate", side_effect=fake):
        out = rule_lookup_ai.build_lookup_narrative(
            "Corp", {"src": "10.0.0.1"},
            {"rows": rows, "skipped_count": skipped, "total": total}, "bob")
    return out, seen


def test_trims_to_25_rows_and_reports_remainder():
    out, seen = _capture(_rows(5000), total=5000)
    assert out == ("ok", None)
    assert len(seen["payload"]["rows"]) == 25
    assert seen["payload"]["rows_not_shown"] == 4975
    assert seen["feature"] == "rule_lookup_explain"
    assert seen["user"] == "bob"
    assert len(json.dumps(seen["payload"])) < 64_000


def test_includes_skipped_count():
    _, seen = _capture(_rows(2), skipped=7)
    assert seen["payload"]["skipped_count"] == 7
    assert seen["payload"]["rows_not_shown"] == 0
    assert "not evaluated" in seen["system"]


def test_comments_not_sent():
    _, seen = _capture(_rows(2))
    assert "comment" not in json.dumps(seen["payload"])


def test_match_is_slimmed_and_malformed_fields_tolerated():
    row = {"policyid": 1, "srcaddr": {"x": 1}, "match": {"src": {"names": {"a": "exact", "b": {"z": 1}}, "via": {"a": ["g"]}}, "port": 3}}
    _, seen = _capture([row])
    r = seen["payload"]["rows"][0]
    assert r["srcaddr"] == []
    assert r["match"] == {"src": {"a": "exact"}}
