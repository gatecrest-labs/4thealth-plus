"""Tests for app/planner/naming_template.py — pattern token substitution."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.planner.models import PlannerDataError
from app.planner.naming_template import NamingTemplateError, render


def test_render_substitutes_single_token():
    assert render("H_<IP_ADDRESS>", IP_ADDRESS="10.1.2.3") == "H_10.1.2.3"


def test_render_substitutes_multiple_tokens():
    result = render(
        "<TICKET_ID>_<SRC_INTF>_TO_<DST_INTF>_<SEQ>",
        TICKET_ID="CHG0012345", SRC_INTF="WAN", DST_INTF="DMZ", SEQ="001",
    )
    assert result == "CHG0012345_WAN_TO_DMZ_001"


def test_render_no_tokens_returns_pattern_unchanged():
    assert render("STATIC_NAME") == "STATIC_NAME"


def test_render_empty_pattern_raises():
    with pytest.raises(NamingTemplateError) as exc_info:
        render("", IP_ADDRESS="10.1.2.3")
    assert exc_info.value.source == "naming_template"


def test_render_none_pattern_raises():
    with pytest.raises(NamingTemplateError):
        render(None)


def test_render_missing_token_raises():
    with pytest.raises(NamingTemplateError) as exc_info:
        render("H_<IP_ADDRESS>")
    assert "IP_ADDRESS" in exc_info.value.detail


def test_render_missing_token_raises_is_planner_data_error():
    # NamingTemplateError must be catchable anywhere PlannerDataError already is
    with pytest.raises(PlannerDataError):
        render("H_<IP_ADDRESS>")


def test_render_lowercase_angle_brackets_not_treated_as_token():
    # only <UPPER_SNAKE> matches the token regex — a literal "<foo>" in a
    # pattern passes through unchanged rather than being misidentified
    assert render("literal_<foo>_text") == "literal_<foo>_text"
