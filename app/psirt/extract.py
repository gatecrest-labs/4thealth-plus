"""
LLM-backed extraction of structured Advisory fields from a raw PSIRT
advisory email/text.

This is the one point in the PSIRT feature where an LLM is involved — it
only extracts; it never computes a verdict, version match, or score.
Mirrors the validation 4tanalyst's parse_advisory tool performs (CVE ID
regex, non-empty affected_ranges, advisory_id character whitelist), since
there's no conversational back-and-forth to ask the user for a missing
field here — invalid extraction surfaces as a specific field name the
caller (the route) turns into a targeted UI error instead.
"""

from __future__ import annotations

import re

from app.llm.base import LLMError, LLMProvider
from app.psirt.models import Advisory, AffectedRange

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_ADVISORY_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")

_SYSTEM_PROMPT = """You are extracting structured fields from a Fortinet PSIRT
security advisory email. Read the provided text and return a JSON object
with these keys:

- advisory_id (string, required): Fortinet's advisory ID, e.g. "FG-IR-24-001"
- advisory_url (string, optional): link to the fortiguard.com advisory page
- cve_ids (array of strings, required): CVE identifiers, format "CVE-YYYY-NNNN"
- published_date (string, optional): the advisory's published date
- fortinet_severity (string, optional): "Critical", "High", "Medium", or "Low"
- cvss_score (number or null, optional): the CVSS base score if stated
- description (string, optional): one-line summary of the vulnerability
- affected_ranges (array of objects, required, at least one entry): each with
  "product" (required — use "FortiOS" or "FortiManager" for anything you want
  matched against a fleet; use the exact product name from the email for
  anything else), "min_version" (empty string for an open-ended lower bound),
  "max_version" (empty string for an open-ended upper bound), "fixed_version",
  "notes"
- workaround_text (string, optional): the vendor's workaround/mitigation text, verbatim
- exploited_in_wild_text (string, optional): Fortinet's own exploitation
  language, verbatim (empty string if the advisory doesn't mention it)

Do not guess at a value you cannot find in the text — omit the key or use
an empty string/null instead."""


class ExtractionError(Exception):
    """A required field was missing/malformed, or the LLM call itself failed."""

    def __init__(self, field: str, detail: str):
        self.field = field
        self.detail = detail
        super().__init__(f"[{field}] {detail}")


def extract_advisory(
    raw_text: str, provider: LLMProvider, user: str | None = None
) -> Advisory:
    try:
        extracted = provider.extract_json(
            _SYSTEM_PROMPT, raw_text, feature="psirt_extract", user=user
        )
    except LLMError as exc:
        raise ExtractionError("llm", str(exc)) from exc

    advisory_id = str(extracted.get("advisory_id", "")).strip()
    if not advisory_id:
        raise ExtractionError("advisory_id", "advisory_id is required")
    if not _ADVISORY_ID_RE.match(advisory_id):
        raise ExtractionError(
            "advisory_id",
            f"advisory_id contains invalid characters: {advisory_id!r} (allowed: A-Z a-z 0-9 . _ -)",
        )

    cve_ids = extracted.get("cve_ids", [])
    if not isinstance(cve_ids, list) or not cve_ids:
        raise ExtractionError("cve_ids", "cve_ids must be a non-empty list")
    for cve in cve_ids:
        if not _CVE_RE.match(str(cve)):
            raise ExtractionError(
                "cve_ids", f"malformed CVE id: {cve!r} (expected CVE-YYYY-NNNN)"
            )

    raw_ranges = extracted.get("affected_ranges", [])
    if not isinstance(raw_ranges, list) or not raw_ranges:
        raise ExtractionError(
            "affected_ranges", "affected_ranges must be a non-empty list"
        )
    ranges: list[AffectedRange] = []
    for r in raw_ranges:
        if not isinstance(r, dict) or not r.get("product"):
            raise ExtractionError(
                "affected_ranges",
                f"malformed affected_ranges entry: {r!r} (product is required)",
            )
        ranges.append(
            AffectedRange(
                product=str(r.get("product", "")),
                min_version=str(r.get("min_version", "") or ""),
                max_version=str(r.get("max_version", "") or ""),
                fixed_version=str(r.get("fixed_version", "") or ""),
                notes=str(r.get("notes", "") or ""),
            )
        )

    cvss_raw = extracted.get("cvss_score")
    cvss_score = float(cvss_raw) if isinstance(cvss_raw, (int, float)) else None

    return Advisory(
        advisory_id=advisory_id,
        advisory_url=str(extracted.get("advisory_url", "") or ""),
        cve_ids=[str(c) for c in cve_ids],
        published_date=str(extracted.get("published_date", "") or ""),
        fortinet_severity=str(extracted.get("fortinet_severity", "") or ""),
        cvss_score=cvss_score,
        description=str(extracted.get("description", "") or ""),
        affected_ranges=ranges,
        workaround_text=str(extracted.get("workaround_text", "") or ""),
        exploited_in_wild_text=str(extracted.get("exploited_in_wild_text", "") or ""),
    )
