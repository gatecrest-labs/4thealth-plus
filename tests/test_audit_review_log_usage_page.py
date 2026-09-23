"""Smoke test for the Log-Based Rule Review section on the Audit Review page.

Confirms the new section's key element IDs are present in the rendered
markup for a user with audit_review tab access, catching gross template
breakage (e.g. a bad insertion point) that a JS-only check can't see.
"""

import time
from unittest.mock import patch

import pytest


@pytest.fixture
def app():
    from app import create_app

    return create_app()


_TEST_USERS = {"admin": {"password_hash": "$2b$12$placeholder", "role": "admin"}}


@pytest.fixture
def client(app):
    with (
        app.test_client() as c,
        patch("app.auth._load_users", return_value=_TEST_USERS),
    ):
        with c.session_transaction() as sess:
            sess["user"] = "admin"
            sess["role"] = "admin"
            sess["_csrf_token"] = "test-csrf"
            sess["login_at"] = int(time.time())
        yield c


def test_audit_review_page_contains_log_usage_section(client):
    resp = client.get("/audit-review")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    for element_id in (
        "logUsageDisabledNotice",
        "logUsageAdom",
        "logUsagePackage",
        "logUsageRule",
        "logUsageDays",
        "logUsageRunBtn",
        "logUsageRunning",
        "logUsageError",
        "logUsageResults",
        "logUsageHeader",
        "logUsageWarnings",
        "logUsageSrcBody",
        "logUsageSrcNotEval",
        "logUsageDstBody",
        "logUsageDstNotEval",
        "logUsageSvcBody",
        "logUsageSvcNotEval",
        "logUsageExportCsvBtn",
    ):
        assert f'id="{element_id}"' in html, f"missing element id={element_id}"

    assert "Log-Based Rule Review" in html
