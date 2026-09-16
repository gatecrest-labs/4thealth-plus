"""Tests for app.device_review_ai.build_narrative."""
from unittest.mock import patch


def test_build_narrative_calls_provider_and_returns_text():
    from app.device_review_ai import build_narrative

    check_summary = [
        {"key": "trusted_hosts", "name": "Trusted Hosts on Admin Accounts (CIS)",
         "description": "desc", "PASS": 2, "INFO": 0, "WARN": 0,
         "CONFIG_MISSING": 0, "FAIL": 1, "INSECURE": 0},
    ]
    results = [
        {"device": "fw-01", "ip": "10.0.0.1", "error": None, "rows": [
            {"device": "fw-01", "check": "Trusted Hosts on Admin Accounts (CIS)",
             "result": "FAIL", "interface": "system", "vdom": "", "ip": "",
             "detail": "Admin account(s) with no trusted-host restriction: admin"},
        ]},
    ]

    with patch("app.llm.get_provider") as mock_get_provider:
        mock_get_provider.return_value.narrate.return_value = "Overall posture is strong except for one admin trusted-host gap."
        narrative = build_narrative("CorpADOM", check_summary, results)

    assert narrative == "Overall posture is strong except for one admin trusted-host gap."
    mock_get_provider.return_value.narrate.assert_called_once()
    call_kwargs = mock_get_provider.return_value.narrate.call_args.kwargs
    assert "system_prompt" in call_kwargs
    assert "user_prompt" in call_kwargs
    assert "CorpADOM" in call_kwargs["user_prompt"]
    assert "fw-01" in call_kwargs["user_prompt"]


def test_build_narrative_caps_rows_sent_to_llm():
    from app.device_review_ai import build_narrative

    results = [
        {"device": f"fw-{i:02d}", "ip": "", "error": None, "rows": [
            {"device": f"fw-{i:02d}", "check": "X", "result": "FAIL",
             "interface": "system", "vdom": "", "ip": "", "detail": "bad"},
        ]}
        for i in range(50)
    ]

    with patch("app.llm.get_provider") as mock_get_provider:
        mock_get_provider.return_value.narrate.return_value = "summary"
        build_narrative("CorpADOM", [], results)

    user_prompt = mock_get_provider.return_value.narrate.call_args.kwargs["user_prompt"]
    import json as _json
    sent = _json.loads(user_prompt)
    assert len(sent["failing_and_insecure_findings"]) == 40
