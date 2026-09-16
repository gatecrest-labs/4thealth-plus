"""Tests for app.hygiene_ai.explain_finding."""
import json
from unittest.mock import patch

import pytest


def test_explain_finding_with_rule_detail():
    from app.hygiene_ai import explain_finding

    finding = {
        "policy_id": "42", "policy_name": "Allow-Web", "seq": 5,
        "check": "unlogged", "detail": "logtraffic = 'disable' — no traffic logging.",
        "rule_detail": {
            "id": "42", "name": "Allow-Web", "status": "enable", "action": "accept",
            "srcaddr": ["CORP-NET"], "dstaddr": ["all"], "service": ["HTTPS"],
            "srcintf": ["port1"], "dstintf": ["port2"], "fsso_groups": [], "comment": "",
        },
    }

    with patch("app.llm.get_provider") as mock_get_provider:
        mock_get_provider.return_value.narrate.return_value = (
            "This rule allows outbound HTTPS without logging, so matching "
            "traffic leaves no audit trail. Enable logging:\n"
            "config firewall policy\n  edit 42\n    set logtraffic all\n  next\nend"
        )
        result = explain_finding(finding)

    assert "logtraffic all" in result
    mock_get_provider.return_value.narrate.assert_called_once()
    user_prompt = mock_get_provider.return_value.narrate.call_args.kwargs["user_prompt"]
    sent = json.loads(user_prompt)
    assert sent["check"] == "unlogged"
    assert sent["rule_detail"]["name"] == "Allow-Web"


def test_explain_finding_with_shadow_rules():
    from app.hygiene_ai import explain_finding

    finding = {
        "policy_id": "10", "policy_name": "Old-Any-Any", "seq": 2,
        "check": "shadow",
        "detail": "Fully shadowed by rule 'Allow-Any-Outbound' (id 3) which appears earlier.",
        "shadow_rule": {"id": "10", "name": "Old-Any-Any", "status": "enable", "action": "accept",
                         "srcaddr": ["all"], "dstaddr": ["all"], "service": ["ALL"],
                         "fsso_groups": [], "comment": ""},
        "shadowing_rule": {"id": "3", "name": "Allow-Any-Outbound", "status": "enable", "action": "accept",
                            "srcaddr": ["all"], "dstaddr": ["all"], "service": ["ALL"],
                            "fsso_groups": [], "comment": ""},
    }

    with patch("app.llm.get_provider") as mock_get_provider:
        mock_get_provider.return_value.narrate.return_value = "Rule 10 will never match traffic; consider removing it."
        result = explain_finding(finding)

    assert "never match" in result
    user_prompt = mock_get_provider.return_value.narrate.call_args.kwargs["user_prompt"]
    sent = json.loads(user_prompt)
    assert sent["shadow_rule"]["id"] == "10"
    assert sent["shadowing_rule"]["id"] == "3"


def test_explain_finding_rejects_oversized_payload():
    from app.hygiene_ai import explain_finding

    finding = {
        "policy_id": "42", "policy_name": "Allow-Web", "seq": 5,
        "check": "unlogged", "detail": "logtraffic = 'disable' — no traffic logging.",
        "rule_detail": {"comment": "x" * 100_000},
    }

    with (
        patch("app.llm.get_provider") as mock_get_provider,
        pytest.raises(ValueError, match="too large"),
    ):
        explain_finding(finding)
    mock_get_provider.return_value.narrate.assert_not_called()
