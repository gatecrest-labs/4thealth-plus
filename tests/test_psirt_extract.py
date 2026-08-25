"""Tests for app.psirt.extract — LLM-backed advisory field extraction + validation."""
import pytest

from app.llm.base import LLMError, LLMProvider
from app.psirt.extract import ExtractionError, extract_advisory


class _FakeProvider(LLMProvider):
    def __init__(self, response: dict):
        self._response = response

    def narrate(self, system_prompt: str, user_prompt: str) -> str:
        import json
        return json.dumps(self._response)


_VALID_EXTRACTION = {
    "advisory_id": "FG-IR-24-001",
    "advisory_url": "https://fortiguard.com/psirt/FG-IR-24-001",
    "cve_ids": ["CVE-2024-12345"],
    "published_date": "2024-01-15",
    "fortinet_severity": "High",
    "cvss_score": 8.1,
    "description": "A vulnerability in FortiOS allows...",
    "affected_ranges": [
        {"product": "FortiOS", "min_version": "", "max_version": "7.4.4",
         "fixed_version": "7.4.5", "notes": ""},
    ],
    "workaround_text": "Disable HTTP/HTTPS admin access",
    "exploited_in_wild_text": "",
}


def test_extract_advisory_happy_path():
    provider = _FakeProvider(_VALID_EXTRACTION)
    advisory = extract_advisory("raw email text here", provider)
    assert advisory.advisory_id == "FG-IR-24-001"
    assert advisory.cve_ids == ["CVE-2024-12345"]
    assert len(advisory.affected_ranges) == 1
    assert advisory.affected_ranges[0].product == "FortiOS"
    assert advisory.cvss_score == 8.1


def test_extract_advisory_missing_advisory_id_raises():
    data = dict(_VALID_EXTRACTION)
    data["advisory_id"] = ""
    provider = _FakeProvider(data)
    with pytest.raises(ExtractionError) as exc_info:
        extract_advisory("raw email text", provider)
    assert exc_info.value.field == "advisory_id"


def test_extract_advisory_invalid_advisory_id_characters_raises():
    data = dict(_VALID_EXTRACTION)
    data["advisory_id"] = "FG-IR-24-001; DROP TABLE"
    provider = _FakeProvider(data)
    with pytest.raises(ExtractionError) as exc_info:
        extract_advisory("raw email text", provider)
    assert exc_info.value.field == "advisory_id"


def test_extract_advisory_missing_cve_ids_raises():
    data = dict(_VALID_EXTRACTION)
    data["cve_ids"] = []
    provider = _FakeProvider(data)
    with pytest.raises(ExtractionError) as exc_info:
        extract_advisory("raw email text", provider)
    assert exc_info.value.field == "cve_ids"


def test_extract_advisory_malformed_cve_id_raises():
    data = dict(_VALID_EXTRACTION)
    data["cve_ids"] = ["not-a-cve"]
    provider = _FakeProvider(data)
    with pytest.raises(ExtractionError) as exc_info:
        extract_advisory("raw email text", provider)
    assert exc_info.value.field == "cve_ids"


def test_extract_advisory_missing_affected_ranges_raises():
    data = dict(_VALID_EXTRACTION)
    data["affected_ranges"] = []
    provider = _FakeProvider(data)
    with pytest.raises(ExtractionError) as exc_info:
        extract_advisory("raw email text", provider)
    assert exc_info.value.field == "affected_ranges"


def test_extract_advisory_affected_range_missing_product_raises():
    data = dict(_VALID_EXTRACTION)
    data["affected_ranges"] = [{"min_version": "", "max_version": "7.4.4"}]
    provider = _FakeProvider(data)
    with pytest.raises(ExtractionError) as exc_info:
        extract_advisory("raw email text", provider)
    assert exc_info.value.field == "affected_ranges"


def test_extract_advisory_llm_failure_propagates_as_extraction_error():
    class _FailingProvider(LLMProvider):
        def narrate(self, system_prompt: str, user_prompt: str) -> str:
            raise LLMError("API unreachable")

    with pytest.raises(ExtractionError) as exc_info:
        extract_advisory("raw email text", _FailingProvider())
    assert exc_info.value.field == "llm"


def test_extract_advisory_optional_fields_default_when_absent():
    minimal = {
        "advisory_id": "FG-IR-24-002",
        "cve_ids": ["CVE-2024-99999"],
        "affected_ranges": [{"product": "FortiOS", "max_version": "7.2.0"}],
    }
    provider = _FakeProvider(minimal)
    advisory = extract_advisory("raw email text", provider)
    assert advisory.workaround_text == ""
    assert advisory.exploited_in_wild_text == ""
    assert advisory.cvss_score is None
