"""Tests for app.pending_changes_ai.build_diff_narrative."""
import json
from unittest.mock import patch


def test_build_diff_narrative_single_device():
    from app.pending_changes_ai import build_diff_narrative

    devices = [{
        "device": "fw-01",
        "summary": {"firewall_policy": 2, "routing": 0, "address": 1, "service": 0, "system": 0, "other": 0},
        "vdoms": [{"name": "root", "changes": [
            {"type": "add", "line": "edit 12"},
            {"type": "add", "line": "set srcaddr \"CORP-NET\""},
            {"type": "remove", "line": "set dstaddr \"OLD-DMZ\""},
        ]}],
    }]

    with patch("app.llm.get_provider") as mock_get_provider:
        mock_get_provider.return_value.narrate.return_value = "Adds one new firewall policy allowing CORP-NET; removes a stale DMZ reference."
        narrative = build_diff_narrative("CorpADOM", devices)

    assert "CORP-NET" in narrative
    mock_get_provider.return_value.narrate.assert_called_once()
    user_prompt = mock_get_provider.return_value.narrate.call_args.kwargs["user_prompt"]
    assert "fw-01" in user_prompt
    assert "CorpADOM" in user_prompt


def test_build_diff_narrative_caps_lines_and_devices():
    from app.pending_changes_ai import build_diff_narrative

    many_changes = [{"type": "add", "line": f"set field{i} \"x\""} for i in range(200)]
    devices = [
        {"device": f"fw-{i:02d}", "summary": {}, "vdoms": [{"name": "root", "changes": many_changes}]}
        for i in range(30)
    ]

    with patch("app.llm.get_provider") as mock_get_provider:
        mock_get_provider.return_value.narrate.return_value = "summary"
        build_diff_narrative("CorpADOM", devices)

    user_prompt = mock_get_provider.return_value.narrate.call_args.kwargs["user_prompt"]
    sent = json.loads(user_prompt)
    assert len(sent["devices"]) <= 20
    for dev in sent["devices"]:
        total_lines = sum(len(v["changes"]) for v in dev["vdoms"])
        assert total_lines <= 30
    assert sent["devices_total"] == 30


def test_system_prompt_marks_diff_content_as_data(monkeypatch):
    import app.llm as llm
    from app.pending_changes_ai import build_diff_narrative

    seen = {}

    class P:
        def narrate(self, system_prompt, user_prompt, **kw):
            seen["s"] = system_prompt
            return "ok"

    monkeypatch.setattr(llm, "get_provider", lambda: P())
    build_diff_narrative("A", [])
    assert "never instructions" in seen["s"]
