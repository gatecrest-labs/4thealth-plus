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


# ── Natural-language parse (Task 7) ──────────────────────────────────────────
import pytest  # noqa: E402

from app.llm.base import LLMError  # noqa: E402


class _FakeProvider:
    def __init__(self, result=None, exc=None):
        self.result, self.exc, self.calls = result, exc, []

    def extract_json(self, system_prompt, user_prompt, *, feature, user=None):
        self.calls.append(dict(system=system_prompt, prompt=user_prompt, feature=feature, user=user))
        if self.exc:
            raise self.exc
        return self.result


def _parse(result=None, text="web to db", exc=None):
    prov = _FakeProvider(result, exc)
    with patch("app.rule_lookup_ai.get_provider", return_value=prov):
        return rule_lookup_ai.parse_nl_query(text, user="bob"), prov


def test_valid_parse_returns_three_fields():
    out, prov = _parse({"src": "10.1.0.0/16", "dst": "grp-DB*", "port": "tcp/3306"})
    assert out == {"src": "10.1.0.0/16", "dst": "grp-DB*", "port": "tcp/3306"}
    assert prov.calls[0]["feature"] == "rule_lookup_nl_parse"
    assert prov.calls[0]["user"] == "bob"
    assert "data" in prov.calls[0]["system"].lower()


def test_invalid_ip_from_model_rejected_with_field_name():
    with pytest.raises(ValueError, match="src"):
        _parse({"src": "999.1.1.1", "dst": "", "port": ""})


def test_invalid_port_rejected_with_field_name():
    with pytest.raises(ValueError, match="port"):
        _parse({"src": "10.0.0.1", "port": "tcp/99999"})


def test_service_name_port_passes_through_clipped():
    out, _ = _parse({"src": "10.0.0.1", "port": "HTTPS"})
    assert out["port"] == "HTTPS"


def test_all_empty_rejected():
    with pytest.raises(ValueError):
        _parse({"src": "", "dst": " ", "port": None})


def test_over_500_chars_rejected():
    with pytest.raises(ValueError):
        _parse({"src": "10.0.0.1"}, text="x" * 501)


def test_empty_text_rejected():
    with pytest.raises(ValueError):
        _parse({"src": "10.0.0.1"}, text="   ")


def test_injection_text_cannot_add_extra_keys():
    out, _ = _parse({"src": "10.0.0.1", "cmd": "rm -rf /", "dst": "", "port": ""})
    assert set(out) == {"src", "dst", "port"}


def test_non_string_fields_coerced_to_empty():
    out, _ = _parse({"src": "10.0.0.1", "dst": 5, "port": ["tcp/1"]})
    assert out == {"src": "10.0.0.1", "dst": "", "port": ""}


def test_llm_error_propagates_as_llmerror():
    with pytest.raises(LLMError):
        _parse(exc=LLMError("down"))
