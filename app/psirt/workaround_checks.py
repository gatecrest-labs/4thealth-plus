"""
Registry of recognized PSIRT workaround patterns and the deterministic
FortiManager config checks that verify whether each is already applied.

Advisory workaround text is free-form English written by Fortinet. Rather
than have the LLM guess whether a workaround is in place, extraction only
captures the raw text; this module matches that text against a small,
explicitly-registered set of patterns and runs a real config check for
each match via app.fmg_client.FMGClient. Unrecognized text never gets a
guessed status — it comes back as "manual_verification_required", and the
registry is expected to grow one advisory at a time.

configure_trusted_hosts is a REAL check here (unlike the 4tanalyst source,
where it was a permanent stub returning manual_verification_required
because the underlying FMG query wasn't implemented there) — this repo
already has FMGClient.get_device_admins() and the exact unrestricted-host
detection logic in app.device_review._run_trusted_hosts, reused below.
"""

from __future__ import annotations

import ipaddress as _ipaddress
from collections.abc import Callable
from typing import Any

_ADMIN_ACCESS_SERVICES = {"http", "https"}

_RFC1918_NETS = [
    _ipaddress.ip_network("10.0.0.0/8"),
    _ipaddress.ip_network("172.16.0.0/12"),
    _ipaddress.ip_network("192.168.0.0/16"),
    _ipaddress.ip_network("100.64.0.0/10"),  # shared address space (RFC 6598)
    _ipaddress.ip_network("169.254.0.0/16"),  # link-local
    _ipaddress.ip_network("127.0.0.0/8"),  # loopback
]

# Same unrestricted-trusthost values app.device_review._run_trusted_hosts uses.
_UNRESTRICTED_HOSTS = {"0.0.0.0/0", "0.0.0.0 0.0.0.0", "0.0.0.0/0.0.0.0"}


def _is_public_ip(ip_str: str) -> bool:
    """Return True if the IP is publicly routable (not RFC1918 / link-local / loopback)."""
    try:
        addr = _ipaddress.ip_address(str(ip_str or "").split("/")[0].split()[0])
        return (
            not addr.is_loopback
            and not addr.is_link_local
            and not any(addr in net for net in _RFC1918_NETS)
        )
    except ValueError:
        return False


def _allowaccess_has_gui(iface: dict) -> bool:
    allowaccess = iface.get("allowaccess", []) or []
    if isinstance(allowaccess, str):
        allowaccess = allowaccess.split()
    return bool(_ADMIN_ACCESS_SERVICES & {str(a).lower() for a in allowaccess})


def _check_disable_http_https_admin_access(client: Any, adom: str, device: str) -> str:
    """Check that no interface allows HTTP/HTTPS admin access (any interface)."""
    interfaces = client.get_device_interfaces_all_vdoms(adom, device)
    if not isinstance(interfaces, list):
        return "manual_verification_required"
    found_any_interface = False
    for iface in interfaces:
        if not isinstance(iface, dict):
            continue
        found_any_interface = True
        if _allowaccess_has_gui(iface):
            return "not_in_place"
    if not found_any_interface:
        return "manual_verification_required"
    return "in_place"


def _check_disable_gui_internet_facing(client: Any, adom: str, device: str) -> str:
    """Check that no internet-facing interface (public IP) allows HTTP/HTTPS admin access."""
    interfaces = client.get_device_interfaces_all_vdoms(adom, device)
    if not isinstance(interfaces, list):
        return "manual_verification_required"
    found_any_interface = False
    found_any_public = False
    for iface in interfaces:
        if not isinstance(iface, dict):
            continue
        found_any_interface = True
        ip_raw = str(iface.get("ip", "") or "")
        if not ip_raw or ip_raw in ("0.0.0.0/0", "0.0.0.0 0.0.0.0", "0.0.0.0"):
            continue
        if not _is_public_ip(ip_raw):
            continue
        found_any_public = True
        if _allowaccess_has_gui(iface):
            return "not_in_place"
    if not found_any_interface:
        return "manual_verification_required"
    if not found_any_public:
        return "manual_verification_required"
    return "in_place"


def _check_trusted_hosts(client: Any, adom: str, device: str) -> str:
    """Real check — mirrors app.device_review._run_trusted_hosts' unrestricted-host detection."""
    admins = client.get_device_admins(adom, device)
    if not isinstance(admins, list):
        return "manual_verification_required"
    for acct in admins:
        if not isinstance(acct, dict):
            continue
        hosts = [str(acct.get(f"trusthost{i}", "")).strip() for i in range(1, 11)]
        non_empty = [h for h in hosts if h and h != "0.0.0.0/255.255.255.255"]
        if not non_empty or all(
            h in _UNRESTRICTED_HOSTS or h == "0.0.0.0 0.0.0.0" for h in non_empty
        ):
            return "not_in_place"
    return "in_place"


# pattern key -> (substrings that identify this workaround in advisory text, check function)
WORKAROUND_REGISTRY: dict[
    str, tuple[tuple[str, ...], Callable[[Any, str, str], str]]
] = {
    "disable_http_https_admin_access": (
        (
            "http/https admin",
            "https admin access",
            "http admin access",
            "disable http",
            "disable https",
        ),
        _check_disable_http_https_admin_access,
    ),
    "disable_gui_internet_facing": (
        (
            "internet-facing",
            "internet facing",
            "external interface",
            "wan interface",
            "disable gui on",
            "gui on internet",
            "internet exposed",
            "publicly accessible",
        ),
        _check_disable_gui_internet_facing,
    ),
    "configure_trusted_hosts": (
        (
            "trusted host",
            "trusthost",
            "restrict management access",
            "limit management access",
            "management access restriction",
            "allowed management ip",
        ),
        _check_trusted_hosts,
    ),
}


def match_workaround_pattern(workaround_text: str) -> str | None:
    text = (workaround_text or "").lower()
    for key, (substrings, _fn) in WORKAROUND_REGISTRY.items():
        if any(s in text for s in substrings):
            return key
    return None


def check_workaround(pattern_key: str, client: Any, adom: str, device: str) -> str:
    entry = WORKAROUND_REGISTRY.get(pattern_key)
    if entry is None:
        return "manual_verification_required"
    _substrings, check_fn = entry
    return check_fn(client, adom, device)
