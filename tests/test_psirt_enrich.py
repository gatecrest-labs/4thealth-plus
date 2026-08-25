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
    hit, fetched_ok = check_kev(["CVE-2024-12345"], client, "https://kev.example/feed.json")
    assert hit is True
    assert fetched_ok is True


def test_check_kev_miss():
    client = MagicMock()
    client.get.return_value = _fake_response(json_data={"vulnerabilities": []})
    hit, fetched_ok = check_kev(["CVE-2024-99999"], client, "https://kev.example/feed.json")
    assert hit is False
    assert fetched_ok is True


def test_check_kev_empty_url_returns_false_but_not_a_failure():
    client = MagicMock()
    hit, fetched_ok = check_kev(["CVE-2024-12345"], client, "")
    assert hit is False
    assert fetched_ok is True  # deliberate no-op, not a fetch failure
    client.get.assert_not_called()


def test_check_kev_network_failure_returns_false_and_marks_not_fetched():
    client = MagicMock()
    client.get.side_effect = Exception("connection refused")
    hit, fetched_ok = check_kev(["CVE-2024-12345"], client, "https://kev.example/feed.json")
    assert hit is False
    assert fetched_ok is False


def test_check_kev_non_200_status_marks_not_fetched():
    client = MagicMock()
    client.get.return_value = _fake_response(status_code=503)
    hit, fetched_ok = check_kev(["CVE-2024-12345"], client, "https://kev.example/feed.json")
    assert hit is False
    assert fetched_ok is False


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


def test_enrich_advisory_kev_fetch_fails_but_page_fetch_succeeds_is_degraded():
    """Finding #4: a KEV-feed failure must not look like 'checked, not KEV-listed' —
    it must set enrichment_degraded=True and flag _kev_fetch_failed even though the
    advisory-page fetch succeeded fine."""
    client = MagicMock()
    page_resp = _fake_response(text="CVSS Score: 9.8. Severity: Critical.")
    kev_resp = MagicMock()
    kev_resp.status_code = 503  # KEV feed down
    client.get.side_effect = [page_resp, kev_resp]
    adv = Advisory(advisory_id="FG-IR-24-001", advisory_url="https://fortiguard.com/psirt/FG-IR-24-001",
                    cve_ids=["CVE-2024-99999"])
    enriched = enrich_advisory(adv, client, "https://kev.example/feed.json", enrichment_enabled=True)
    # Advisory page data still comes through...
    assert enriched.cvss_score == 9.8
    assert enriched.fortinet_severity == "Critical"
    # ...but the overall assessment must be marked degraded because KEV
    # membership could not be corroborated, and _kev_hit must not silently
    # read as "confirmed not KEV-listed".
    assert enriched.enrichment_degraded is True
    assert enriched._kev_hit is False
    assert enriched._kev_fetch_failed is True


def test_enrich_advisory_disabled_reuses_already_enriched_values():
    """Finding #6 support: a second enrich_advisory() call with
    enrichment_enabled=False on an already-enriched advisory (the merge-loop
    per-ADOM reuse pattern) must not stomp the real enrichment signal."""
    client = MagicMock()
    client.get.side_effect = [
        _fake_response(text="CVSS Score: 7.2. Severity: High."),
        _fake_response(json_data={"vulnerabilities": [{"cveID": "CVE-2024-12345"}]}),
    ]
    adv = Advisory(advisory_id="FG-IR-24-001", advisory_url="https://fortiguard.com/psirt/FG-IR-24-001",
                    cve_ids=["CVE-2024-12345"])
    enriched_once = enrich_advisory(adv, client, "https://kev.example/feed.json", enrichment_enabled=True)
    assert enriched_once._kev_hit is True
    assert enriched_once.enrichment_degraded is False

    # Reuse it through a disabled call, as the merge loop does for every
    # ADOM after the first.
    reused = enrich_advisory(enriched_once, client, "https://kev.example/feed.json", enrichment_enabled=False)
    assert reused._kev_hit is True  # preserved, not reset to False
    assert reused.enrichment_degraded is False  # preserved, not forced True
    assert reused.cvss_score == 7.2


def test_enrich_advisory_disabled_fresh_advisory_still_degrades():
    """The original PSIRT_ENRICHMENT_ENABLED=false (air-gapped) semantics
    must still hold for an advisory that has never been enriched."""
    client = MagicMock()
    adv = Advisory(advisory_id="FG-IR-24-001", advisory_url="https://fortiguard.com/psirt/FG-IR-24-001")
    enriched = enrich_advisory(adv, client, "https://kev.example/feed.json", enrichment_enabled=False)
    assert enriched.enrichment_degraded is True
    assert enriched._kev_hit is False
