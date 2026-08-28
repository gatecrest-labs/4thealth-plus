"""Static FortiOS end-of-support table. Update when Fortinet publishes new EOL dates.

Source: Fortinet's published FortiOS Support Lifecycle
(https://support.fortinet.com/Information/Support-Lifecycle.aspx as of authoring).
Versions are matched by exact string after stripping a leading "v"/"V".
"""

from __future__ import annotations

_EOL_VERSIONS: set[str] = {
    "6.0.0", "6.0.1", "6.0.2", "6.0.3", "6.0.4", "6.0.5",
    "6.2.0", "6.2.1", "6.2.2", "6.2.3",
    "6.4.0", "6.4.1", "6.4.2", "6.4.3", "6.4.4", "6.4.5",
    "6.4.6", "6.4.7", "6.4.8", "6.4.9", "6.4.10", "6.4.11",
    "6.4.12", "6.4.13", "6.4.14",
    "7.0.0", "7.0.1", "7.0.2",
}


def is_eol(version: str) -> bool:
    """Return True if version is a known end-of-support FortiOS release.

    Unrecognized versions (including newer releases not yet in the table)
    return False -- absence of data must never render as a false EOL flag.
    """
    normalized = version.lstrip("vV")
    return normalized in _EOL_VERSIONS
