"""Tests for PSIRT advisory enrichment (fortiguard.com + CISA KEV), mocked HTTP."""
from unittest.mock import MagicMock

from app.psirt.enrich import check_kev, enrich_advisory, fetch_advisory_page
from app.psirt.models import Advisory


def _fake_response(status_code=200, json_data=None, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.text = text
    return resp


def test_check_kev_hit():
    client = MagicMock()
    client.get.return_value = _fake_response(
        json_data={"vulnerabilities": [{"cveID": "CVE-2024-12345"}]}
    )
    assert check_kev(["CVE-2024-12345"], client, "https://kev.example/feed.json") is True


def test_check_kev_miss():
    client = MagicMock()
    client.get.return_value = _fake_response(json_data={"vulnerabilities": []})
    assert check_kev(["CVE-2024-99999"], client, "https://kev.example/feed.json") is False


def test_check_kev_empty_url_returns_false():
    client = MagicMock()
    assert check_kev(["CVE-2024-12345"], client, "") is False
    client.get.assert_not_called()


def test_check_kev_network_failure_returns_false():
    client = MagicMock()
    client.get.side_effect = Exception("connection refused")
    assert check_kev(["CVE-2024-12345"], client, "https://kev.example/feed.json") is False


def test_fetch_advisory_page_extracts_cvss_and_severity():
    client = MagicMock()
    client.get.return_value = _fake_response(
        text="Some advisory text. CVSS Score: 8.1 more text. Severity: High done."
    )
    result = fetch_advisory_page("https://fortiguard.com/psirt/FG-IR-24-001", client)
    assert result["fetched"] is True
    assert result["cvss_score"] == 8.1
    assert result["fortinet_severity"] == "High"


def test_fetch_advisory_page_network_failure_degrades():
    client = MagicMock()
    client.get.side_effect = Exception("timeout")
    result = fetch_advisory_page("https://fortiguard.com/psirt/FG-IR-24-001", client)
    assert result["fetched"] is False
    assert result["cvss_score"] is None


def test_fetch_advisory_page_empty_url_returns_not_fetched():
    client = MagicMock()
    result = fetch_advisory_page("", client)
    assert result["fetched"] is False
    client.get.assert_not_called()


def test_enrich_advisory_fills_missing_fields():
    client = MagicMock()
    client.get.side_effect = [
        _fake_response(text="CVSS Score: 7.2. Severity: High."),  # advisory page
        _fake_response(json_data={"vulnerabilities": []}),         # KEV feed
    ]
    adv = Advisory(advisory_id="FG-IR-24-001", advisory_url="https://fortiguard.com/psirt/FG-IR-24-001")
    enriched = enrich_advisory(adv, client, "https://kev.example/feed.json", enrichment_enabled=True)
    assert enriched.cvss_score == 7.2
    assert enriched.fortinet_severity == "High"
    assert enriched.enrichment_degraded is False


def test_enrich_advisory_disabled_flag_skips_fetches_entirely():
    client = MagicMock()
    adv = Advisory(advisory_id="FG-IR-24-001", advisory_url="https://fortiguard.com/psirt/FG-IR-24-001")
    enriched = enrich_advisory(adv, client, "https://kev.example/feed.json", enrichment_enabled=False)
    client.get.assert_not_called()
    assert enriched.enrichment_degraded is True
    assert enriched._kev_hit is False


def test_enrich_advisory_never_raises_on_total_failure():
    client = MagicMock()
    client.get.side_effect = Exception("dns failure")
    adv = Advisory(advisory_id="FG-IR-24-001", advisory_url="https://fortiguard.com/psirt/FG-IR-24-001")
    enriched = enrich_advisory(adv, client, "https://kev.example/feed.json", enrichment_enabled=True)
    assert enriched.enrichment_degraded is True
