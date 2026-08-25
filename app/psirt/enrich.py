"""
Best-effort enrichment of an LLM-extracted Advisory from two external
sources: the live fortiguard.com advisory page (fills/corroborates CVSS
and severity) and the CISA Known Exploited Vulnerabilities catalog (an
independent signal that a CVE is being actively exploited).

Both fetches are optional and failures never raise — enrichment always
degrades gracefully to "use what the email gave us." Callers pass in a
requests-compatible http_client (requests itself, or a mock/session in
tests) so tests never touch the network. enrichment_enabled=False skips
both fetches entirely (PSIRT_ENRICHMENT_ENABLED=false — air-gapped
deployments).
"""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

from app.psirt.models import Advisory

_CVSS_RE = re.compile(r"CVSS\s*Score:?\s*([\d]+(?:\.[\d]+)?)", re.IGNORECASE)
_SEVERITY_RE = re.compile(r"Severity:?\s*(Critical|High|Medium|Low)", re.IGNORECASE)


def check_kev(cve_ids: list[str], http_client: Any, kev_url: str, timeout: float = 5.0) -> bool:
    """Check if any CVE in cve_ids appears in the CISA KEV catalog.

    Never raises — network failures return False.
    """
    if not cve_ids or not kev_url:
        return False
    try:
        resp = http_client.get(kev_url, timeout=timeout)
        if resp.status_code != 200:
            return False
        data = resp.json()
    except Exception:
        return False
    entries = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    known = {e.get("cveID", "") for e in entries if isinstance(e, dict)}
    return any(cve in known for cve in cve_ids)


def fetch_advisory_page(advisory_url: str, http_client: Any, timeout: float = 5.0) -> dict:
    """Fetch the fortiguard.com advisory page and extract CVSS score and severity.

    Never raises — network failures or parse errors return fetched=False.
    """
    if not advisory_url:
        return {"fetched": False, "cvss_score": None, "fortinet_severity": "", "raw_text": ""}
    try:
        resp = http_client.get(advisory_url, timeout=timeout)
        if resp.status_code != 200:
            return {"fetched": False, "cvss_score": None, "fortinet_severity": "", "raw_text": ""}
        text = resp.text
    except Exception:
        return {"fetched": False, "cvss_score": None, "fortinet_severity": "", "raw_text": ""}

    cvss_match = _CVSS_RE.search(text)
    severity_match = _SEVERITY_RE.search(text)
    return {
        "fetched": True,
        "cvss_score": float(cvss_match.group(1)) if cvss_match else None,
        "fortinet_severity": severity_match.group(1) if severity_match else "",
        "raw_text": text,
    }


def enrich_advisory(
    advisory: Advisory,
    http_client: Any,
    kev_url: str,
    enrichment_enabled: bool = True,
    timeout: float = 5.0,
) -> Advisory:
    """Enrich an Advisory from fortiguard.com and CISA KEV catalog.

    Returns a new Advisory; never raises. When enrichment_enabled is False,
    both fetches are skipped entirely and enrichment_degraded is set True.
    """
    if not enrichment_enabled:
        enriched = replace(advisory, enrichment_degraded=True)
        enriched._kev_hit = False  # type: ignore[attr-defined]
        return enriched

    page = fetch_advisory_page(advisory.advisory_url, http_client, timeout=timeout)
    kev_hit = check_kev(advisory.cve_ids, http_client, kev_url, timeout=timeout)

    updates: dict = {}
    if page["fetched"]:
        if advisory.cvss_score is None and page["cvss_score"] is not None:
            updates["cvss_score"] = page["cvss_score"]
        if not advisory.fortinet_severity and page["fortinet_severity"]:
            updates["fortinet_severity"] = page["fortinet_severity"]

    updates["enrichment_degraded"] = not page["fetched"]

    enriched = replace(advisory, **updates)
    enriched._kev_hit = kev_hit  # type: ignore[attr-defined]
    return enriched
