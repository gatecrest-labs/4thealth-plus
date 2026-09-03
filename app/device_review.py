"""Device Review check engine.

Each CHECK entry in CHECKS describes one analysis that can be run against a
device.  To add a new check:

  1. Write a function  _run_<name>(device_name, device_data, params) -> list[Row]
  2. Append an entry to CHECKS (key, name, description, severity, data_keys,
     params_schema, run).

Row fields
----------
device      — device name
interface   — interface name, or "system" for device-level checks
vdom        — VDOM name (or "" / "root")
ip          — IP/prefix of the interface, or "" for system checks
type        — interface type, or "system"
status      — interface status, or "" for system checks
check       — display name of the check that produced this row
result      — "INSECURE" | "WARN" | "INFO"  (interface check)
              "PASS" | "FAIL" | "CONFIG_MISSING"  (CIS checks)
detail      — human-readable finding detail
protocols   — list of {name, secure} dicts (interface check only; [] for CIS)
has_insecure — bool convenience flag (interface check; False for CIS rows)
has_secure   — bool convenience flag (interface check; False for CIS rows)

data_keys / params_schema
-------------------------
data_keys    — list of device_data keys this check needs fetched
               ("interfaces", "ntp", "syslog").  Routes fetch only what is
               required by the selected checks.
params_schema — list of input descriptors that the UI should render before a
               run.  Each entry:
                 { key, label, type ("ip_list"), placeholder, required (bool) }
               Empty list means no user input needed (binary check).
"""

from __future__ import annotations

import functools
import ipaddress
import logging as _logging
import pathlib as _pathlib
import re as _re
import socket
from typing import Any

# ── Protocol security classification ─────────────────────────────────────────

_PROTO_SECURE: dict[str, bool | None] = {
    "https": True,
    "ssh": True,
    "snmp": True,
    "fabric": True,  # Fortinet Security Fabric (management-plane)
    "http": False,
    "telnet": False,
    "http-redirect": False,
    "ping": None,  # informational
    "fgfm": None,  # FortiGate-to-FortiManager
    "capwap": None,  # wireless controller
    "speed-test": None,
    "ftm": None,  # FortiToken Mobile
}

_PROTO_SEVERITY_PATH = str(
    _pathlib.Path(__file__).parent.parent / "protocol_severity.json"
)

_VALID_VALUES: dict[str, bool | None] = {
    "secure": True,
    "insecure": False,
    "info": None,
}


def _load_proto_overrides() -> dict[str, bool | None]:
    """Load protocol_severity.json overrides. Missing file → empty dict."""
    import json as _json

    try:
        with open(_PROTO_SEVERITY_PATH) as fh:
            raw = _json.load(fh)
    except FileNotFoundError:
        return {}
    except Exception as exc:
        _logging.getLogger(__name__).warning(
            "protocol_severity.json unreadable — using defaults: %s", exc
        )
        return {}
    if not isinstance(raw, dict):
        _logging.getLogger(__name__).warning(
            "protocol_severity.json must be a JSON object — using defaults"
        )
        return {}
    result: dict[str, bool | None] = {}
    for key, val in raw.items():
        if key.startswith("_"):
            continue  # skip comment/metadata keys
        if val is None:
            result[key.lower()] = None
        elif isinstance(val, str) and val.lower() in _VALID_VALUES:
            result[key.lower()] = _VALID_VALUES[val.lower()]
        else:
            _logging.getLogger(__name__).warning(
                "protocol_severity.json: invalid value %r for %r — ignored", val, key
            )
    return result


_EFFECTIVE_PROTO_SECURE: dict[str, bool | None] = {
    **_PROTO_SECURE,
    **_load_proto_overrides(),
}


def _classify_proto(name: str) -> bool | None:
    """Return True=secure, False=insecure, None=informational."""
    return _EFFECTIVE_PROTO_SECURE.get(name.lower(), None)


# ── Interface helpers ─────────────────────────────────────────────────────────


def _ip_str(iface: dict) -> str:
    raw = iface.get("ip") or iface.get("ipv4") or ""
    if isinstance(raw, list):
        raw = raw[0] if raw else ""
    if isinstance(raw, dict):
        raw = raw.get("ip", "")
    s = str(raw).strip()
    # CMDB returns "A.B.C.D M.M.M.M" — normalise to "A.B.C.D/M.M.M.M"
    if " " in s:
        s = s.replace(" ", "/", 1)
    return s


def _has_ip(iface: dict) -> bool:
    addr = _ip_str(iface)
    return bool(addr) and addr.split("/")[0] not in ("", "0.0.0.0")


def _allowed_protos(iface: dict) -> list[str]:
    """Return list of lower-cased allowed-access protocol tokens."""
    raw = iface.get("allowaccess") or iface.get("allow-access") or ""
    if isinstance(raw, list):
        tokens = [str(t).lower().strip() for t in raw if t]
    else:
        tokens = str(raw).replace(",", " ").lower().split()
    return [t for t in tokens if t]


# ── CIS param helpers ─────────────────────────────────────────────────────────


def _parse_host_list(raw: Any) -> list[str]:
    """Normalise a param value into a list of stripped, non-empty host strings.

    Accepts IPs and FQDNs. Splits on commas or whitespace.
    """
    if isinstance(raw, list):
        return [s.strip() for s in raw if str(s).strip()]
    if isinstance(raw, str):
        return [s.strip() for s in raw.replace(",", " ").split() if s.strip()]
    return []


@functools.lru_cache(maxsize=256)
def _resolve_host(host: str) -> frozenset[str]:
    """Return routable IP addresses that host resolves to.

    Filters loopback, link-local, and unspecified addresses to prevent
    DNS sinkholes from causing false-positive matches.
    Returns empty frozenset on any DNS error.
    """
    try:
        results = socket.getaddrinfo(host, None)
        addrs = set()
        for r in results:
            ip_str = r[4][0]
            try:
                addr = ipaddress.ip_address(ip_str)
                if not (addr.is_loopback or addr.is_link_local or addr.is_unspecified):
                    addrs.add(ip_str)
            except ValueError:
                pass  # skip unparseable addresses
        return frozenset(addrs)
    except Exception:
        return frozenset()


def _match_host(expected: str, configured: str) -> tuple[bool, str]:
    """Compare expected host against configured host.

    Tries direct string match first. On mismatch, resolves both via DNS
    and checks for IP intersection. Returns (matched, annotation) where
    annotation is '' on direct match or 'via DNS: expected → ip' on DNS match.
    """
    if expected == configured:
        return True, ""
    exp_ips = _resolve_host(expected)
    cfg_ips = _resolve_host(configured)
    common = exp_ips & cfg_ips
    if common:
        resolved_ip = next(iter(common))
        return True, f"via DNS: {expected} → {resolved_ip}"
    return False, ""


def _to_str(raw: Any) -> str:
    """Return a scalar param as a stripped string, ignoring empty lists."""
    if isinstance(raw, list):
        return raw[0].strip() if raw else ""
    return str(raw).strip() if raw is not None else ""


# ── Check: Interface Protocols ────────────────────────────────────────────────


def _run_interface_protocols(
    device_name: str, device_data: dict, params: dict
) -> list[dict]:
    """Return every interface that has an IP address and any management access."""
    rows: list[dict] = []
    for iface in device_data.get("interfaces", []):
        if not isinstance(iface, dict):
            continue
        if not _has_ip(iface):
            continue
        protos = _allowed_protos(iface)

        if not protos:
            rows.append(
                {
                    "device": device_name,
                    "interface": iface.get("name", ""),
                    "vdom": iface.get("vdom", ""),
                    "ip": _ip_str(iface),
                    "type": (iface.get("type") or "").lower(),
                    "status": (iface.get("status") or "").lower(),
                    "check": "Interface Protocols",
                    "result": "INFO",
                    "detail": "No management access",
                    "protocols": [],
                    "has_insecure": False,
                    "has_secure": False,
                }
            )
            continue

        proto_list = [{"name": p, "secure": _classify_proto(p)} for p in sorted(protos)]
        has_insecure = any(p["secure"] is False for p in proto_list)
        has_secure = any(p["secure"] is True for p in proto_list)

        has_info_only = any(p["secure"] is None for p in proto_list)

        if has_insecure:
            result = "INSECURE"
        elif has_secure or has_info_only:
            result = "INFO"
        else:
            result = "WARN"  # no protocols of any known type — safety net

        rows.append(
            {
                "device": device_name,
                "interface": iface.get("name", ""),
                "vdom": iface.get("vdom", ""),
                "ip": _ip_str(iface),
                "type": (iface.get("type") or "").lower(),
                "status": (iface.get("status") or "").lower(),
                "check": "Interface Protocols",
                "result": result,
                "detail": "",
                "protocols": proto_list,
                "has_insecure": has_insecure,
                "has_secure": has_secure,
            }
        )

    return rows


# ── Check: NTP Configuration (CIS) ───────────────────────────────────────────


def _run_ntp_config(device_name: str, device_data: dict, params: dict) -> list[dict]:
    """CIS: verify NTP is enabled and configured servers match expected hosts (IP or FQDN)."""
    ntp = device_data.get("ntp", {})
    expected = _parse_host_list(params.get("expected_servers", []))

    def _row(result: str, detail: str, ip: str = "") -> dict:
        return {
            "device": device_name,
            "interface": "system",
            "vdom": "",
            "ip": ip,
            "type": "system",
            "status": "",
            "check": "NTP Configuration (CIS)",
            "result": result,
            "detail": detail,
            "protocols": [],
            "has_insecure": False,
            "has_secure": False,
        }

    if not ntp:
        return [_row("FAIL", "NTP configuration could not be retrieved from device")]

    sync_enabled = str(ntp.get("ntpsync", "disable")).lower() == "enable"
    if not sync_enabled:
        return [_row("FAIL", "NTP sync is disabled (ntpsync=disable)")]

    raw_servers = ntp.get("ntpserver", [])
    if isinstance(raw_servers, dict):
        raw_servers = list(raw_servers.values())
    configured = [
        str(s.get("server", "")).strip()
        for s in raw_servers
        if isinstance(s, dict) and s.get("server")
    ]
    ip_str = ", ".join(configured)

    if not expected:
        detail = "NTP sync enabled. Configured: " + (
            ", ".join(configured) if configured else "(none)"
        )
        return [_row("CONFIG_MISSING", detail, ip_str)]

    parts = []
    any_fail = False
    for exp in expected:
        matched = False
        annotation = ""
        for conf in configured:
            ok, ann = _match_host(exp, conf)
            if ok:
                matched = True
                annotation = ann
                break
        if matched:
            entry = f"{exp} ✓" + (f" ({annotation})" if annotation else "")
        else:
            entry = f"{exp} ✗ (not found)"
            any_fail = True
        parts.append(entry)

    detail = ", ".join(parts)
    if any_fail:
        result = "WARN" if configured else "FAIL"
    else:
        result = "PASS"
    return [_row(result, detail, ip_str)]


# ── Check: Syslog Configuration (CIS) ────────────────────────────────────────


def _run_syslog_config(device_name: str, device_data: dict, params: dict) -> list[dict]:
    """CIS: verify syslog is enabled and sending to expected hosts (IP or FQDN)."""
    servers = device_data.get("syslog", [])
    expected = _parse_host_list(params.get("expected_servers", []))

    def _row(result: str, detail: str, ip: str = "") -> dict:
        return {
            "device": device_name,
            "interface": "system",
            "vdom": "",
            "ip": ip,
            "type": "system",
            "status": "",
            "check": "Syslog Configuration (CIS)",
            "result": result,
            "detail": detail,
            "protocols": [],
            "has_insecure": False,
            "has_secure": False,
        }

    configured = [
        str(s.get("server", "")).strip()
        for s in servers
        if isinstance(s, dict) and s.get("server")
    ]
    ip_str = ", ".join(configured)

    if not configured:
        if not expected:
            return [
                _row("CONFIG_MISSING", "No remote syslog servers enabled on device")
            ]
        # No servers configured but expected ones specified: build parts list to show mismatches
        parts = []
        for exp in expected:
            parts.append(f"{exp} ✗ (not found)")
        detail = ", ".join(parts)
        return [_row("FAIL", detail)]

    if not expected:
        return [_row("CONFIG_MISSING", "Syslog enabled. Configured: " + ip_str, ip_str)]

    parts = []
    any_fail = False
    for exp in expected:
        matched = False
        annotation = ""
        for conf in configured:
            ok, ann = _match_host(exp, conf)
            if ok:
                matched = True
                annotation = ann
                break
        if matched:
            entry = f"{exp} ✓" + (f" ({annotation})" if annotation else "")
        else:
            entry = f"{exp} ✗ (not found)"
            any_fail = True
        parts.append(entry)

    detail = ", ".join(parts)
    result = "WARN" if any_fail else "PASS"
    return [_row(result, detail, ip_str)]


# ── CIS row factory helper ────────────────────────────────────────────────────


def _cis_row(device_name: str, check_name: str, result: str, detail: str) -> dict:
    return {
        "device": device_name,
        "interface": "system",
        "vdom": "",
        "ip": "",
        "type": "system",
        "status": "",
        "check": check_name,
        "result": result,
        "detail": detail,
        "protocols": [],
        "has_insecure": False,
        "has_secure": False,
    }


# ── Check: Trusted hosts on admin accounts (CIS #1) ──────────────────────────

_UNRESTRICTED_HOSTS = {"0.0.0.0/0", "0.0.0.0 0.0.0.0", "0.0.0.0/0.0.0.0"}
_CHECK_TRUSTED_HOSTS = "Trusted Hosts on Admin Accounts (CIS)"


def _run_trusted_hosts(device_name: str, device_data: dict, params: dict) -> list[dict]:
    admins = device_data.get("admins", [])
    if not isinstance(admins, list):
        return [
            _cis_row(
                device_name,
                _CHECK_TRUSTED_HOSTS,
                "FAIL",
                "Admin list could not be retrieved",
            )
        ]

    unrestricted = []
    for acct in admins:
        if not isinstance(acct, dict):
            continue
        name = acct.get("name", "?")
        hosts = [str(acct.get(f"trusthost{i}", "")).strip() for i in range(1, 11)]
        # If every non-empty trusthost is an unrestricted wildcard, flag it
        non_empty = [h for h in hosts if h and h != "0.0.0.0/255.255.255.255"]
        if not non_empty or all(
            h in _UNRESTRICTED_HOSTS or h == "0.0.0.0 0.0.0.0" for h in non_empty
        ):
            unrestricted.append(name)

    if unrestricted:
        return [
            _cis_row(
                device_name,
                _CHECK_TRUSTED_HOSTS,
                "FAIL",
                f"Admin account(s) with no trusted-host restriction: {', '.join(unrestricted)}",
            )
        ]
    return [
        _cis_row(
            device_name,
            _CHECK_TRUSTED_HOSTS,
            "PASS",
            f"All {len(admins)} admin account(s) have trusted-host restrictions",
        )
    ]


# ── Check: Default admin account renamed or disabled (CIS #2) ─────────────────

_CHECK_DEFAULT_ADMIN = "Default 'admin' Account (CIS)"


def _run_default_admin(device_name: str, device_data: dict, params: dict) -> list[dict]:
    admins = device_data.get("admins", [])
    if not isinstance(admins, list):
        return [
            _cis_row(
                device_name,
                _CHECK_DEFAULT_ADMIN,
                "FAIL",
                "Admin list could not be retrieved",
            )
        ]

    for acct in admins:
        if not isinstance(acct, dict):
            continue
        if acct.get("name", "").lower() == "admin":
            disabled = str(acct.get("status", "enable")).lower() == "disable"
            if not disabled:
                return [
                    _cis_row(
                        device_name,
                        _CHECK_DEFAULT_ADMIN,
                        "FAIL",
                        "Built-in 'admin' account exists and is active — rename or disable it",
                    )
                ]
            return [
                _cis_row(
                    device_name,
                    _CHECK_DEFAULT_ADMIN,
                    "PASS",
                    "Built-in 'admin' account exists but is disabled",
                )
            ]

    return [
        _cis_row(
            device_name,
            _CHECK_DEFAULT_ADMIN,
            "PASS",
            "No active built-in 'admin' account found",
        )
    ]


# ── Check: Admin two-factor authentication (CIS) ─────────────────────────────

_CHECK_ADMIN_MFA = "Admin Two-Factor Authentication (CIS)"


def _run_admin_mfa(device_name: str, device_data: dict, params: dict) -> list[dict]:
    admins = device_data.get("admins")  # None = not fetched; [] = explicitly empty
    if admins is None:
        return [
            _cis_row(
                device_name,
                _CHECK_ADMIN_MFA,
                "CONFIG_MISSING",
                "Admin data could not be retrieved",
            )
        ]
    if not isinstance(admins, list):
        return [
            _cis_row(
                device_name,
                _CHECK_ADMIN_MFA,
                "FAIL",
                "Admin list could not be retrieved",
            )
        ]
    no_mfa = [
        str(a.get("name", "?"))
        for a in admins
        if isinstance(a, dict)
        and str(a.get("two-factor", "disable")).lower() == "disable"
    ]
    if no_mfa:
        return [
            _cis_row(
                device_name,
                _CHECK_ADMIN_MFA,
                "FAIL",
                f"Admin account(s) without MFA: {', '.join(no_mfa)}",
            )
        ]
    return [
        _cis_row(
            device_name,
            _CHECK_ADMIN_MFA,
            "PASS",
            f"All {len(admins)} admin account(s) have MFA enabled",
        )
    ]


# ── Check: Admin idle timeout (CIS #3) ────────────────────────────────────────

_CHECK_IDLE_TIMEOUT = "Admin Idle Timeout (CIS)"


def _run_idle_timeout(device_name: str, device_data: dict, params: dict) -> list[dict]:
    cfg = device_data.get("system_global", {})
    if not cfg:
        return [
            _cis_row(
                device_name,
                _CHECK_IDLE_TIMEOUT,
                "FAIL",
                "system/global could not be retrieved",
            )
        ]

    configured = cfg.get("admintimeout")
    if configured is None:
        return [
            _cis_row(
                device_name,
                _CHECK_IDLE_TIMEOUT,
                "CONFIG_MISSING",
                "admintimeout not found in system/global response",
            )
        ]

    configured = int(configured)
    raw_max = _to_str(params.get("max_timeout_minutes", ""))
    if not raw_max:
        return [
            _cis_row(
                device_name,
                _CHECK_IDLE_TIMEOUT,
                "CONFIG_MISSING",
                f"Configured idle timeout: {configured} min (no expected maximum supplied)",
            )
        ]

    max_timeout = int(raw_max)
    if configured > max_timeout:
        return [
            _cis_row(
                device_name,
                _CHECK_IDLE_TIMEOUT,
                "FAIL",
                f"Idle timeout is {configured} min — exceeds maximum of {max_timeout} min",
            )
        ]
    return [
        _cis_row(
            device_name,
            _CHECK_IDLE_TIMEOUT,
            "PASS",
            f"Idle timeout is {configured} min (≤ {max_timeout} min)",
        )
    ]


# ── Check: Admin lockout threshold (CIS #4) ───────────────────────────────────

_CHECK_LOCKOUT = "Admin Lockout Threshold (CIS)"


def _run_lockout_threshold(
    device_name: str, device_data: dict, params: dict
) -> list[dict]:
    cfg = device_data.get("system_global", {})
    if not cfg:
        return [
            _cis_row(
                device_name,
                _CHECK_LOCKOUT,
                "FAIL",
                "system/global could not be retrieved",
            )
        ]

    configured = cfg.get("admin-lockout-threshold") or cfg.get(
        "admin_lockout_threshold"
    )
    if configured is None:
        return [
            _cis_row(
                device_name,
                _CHECK_LOCKOUT,
                "CONFIG_MISSING",
                "admin-lockout-threshold not found in system/global response",
            )
        ]

    configured = int(configured)
    raw_max = _to_str(params.get("max_attempts", ""))
    if not raw_max:
        return [
            _cis_row(
                device_name,
                _CHECK_LOCKOUT,
                "CONFIG_MISSING",
                f"Lockout threshold: {configured} attempts (no expected maximum supplied)",
            )
        ]

    max_attempts = int(raw_max)
    if configured > max_attempts:
        return [
            _cis_row(
                device_name,
                _CHECK_LOCKOUT,
                "FAIL",
                f"Lockout threshold is {configured} — exceeds maximum of {max_attempts} failed attempts",
            )
        ]
    return [
        _cis_row(
            device_name,
            _CHECK_LOCKOUT,
            "PASS",
            f"Lockout threshold is {configured} failed attempts (≤ {max_attempts})",
        )
    ]


# ── Check: Password minimum length (CIS #5) ───────────────────────────────────

_CHECK_PWD_LENGTH = "Password Minimum Length (CIS)"


def _run_password_length(
    device_name: str, device_data: dict, params: dict
) -> list[dict]:
    cfg = device_data.get("password_policy", {})
    if not cfg:
        return [
            _cis_row(
                device_name,
                _CHECK_PWD_LENGTH,
                "FAIL",
                "system/password-policy could not be retrieved",
            )
        ]

    configured = cfg.get("minimum-length") or cfg.get("minimum_length")
    if configured is None:
        return [
            _cis_row(
                device_name,
                _CHECK_PWD_LENGTH,
                "CONFIG_MISSING",
                "minimum-length not found in password-policy response",
            )
        ]

    configured = int(configured)
    raw_min = _to_str(params.get("min_length", ""))
    if not raw_min:
        return [
            _cis_row(
                device_name,
                _CHECK_PWD_LENGTH,
                "CONFIG_MISSING",
                f"Minimum password length: {configured} characters (no expected minimum supplied)",
            )
        ]

    min_length = int(raw_min)
    if configured < min_length:
        return [
            _cis_row(
                device_name,
                _CHECK_PWD_LENGTH,
                "FAIL",
                f"Minimum password length is {configured} — below required minimum of {min_length}",
            )
        ]
    return [
        _cis_row(
            device_name,
            _CHECK_PWD_LENGTH,
            "PASS",
            f"Minimum password length is {configured} characters (≥ {min_length})",
        )
    ]


# ── Check: Local disk logging enabled (CIS #6) ───────────────────────────────

_CHECK_LOG_DISK = "Local Disk Logging (CIS)"


def _run_log_disk(device_name: str, device_data: dict, params: dict) -> list[dict]:
    cfg = device_data.get("log_disk", {})
    if not cfg:
        return [
            _cis_row(
                device_name,
                _CHECK_LOG_DISK,
                "FAIL",
                "log.disk/setting could not be retrieved",
            )
        ]

    status = str(cfg.get("status", "disable")).lower()
    if status != "enable":
        return [
            _cis_row(
                device_name,
                _CHECK_LOG_DISK,
                "FAIL",
                "Disk logging is disabled (status=disable)",
            )
        ]
    return [_cis_row(device_name, _CHECK_LOG_DISK, "PASS", "Disk logging is enabled")]


# ── Check: Log severity level (CIS #7) ───────────────────────────────────────

_CHECK_LOG_SEVERITY = "Log Severity Level (CIS)"
_SEVERITY_ORDER = [
    "emergency",
    "alert",
    "critical",
    "error",
    "warning",
    "notification",
    "information",
    "debug",
]


def _run_log_severity(device_name: str, device_data: dict, params: dict) -> list[dict]:
    cfg = device_data.get("log_disk", {})
    if not cfg:
        return [
            _cis_row(
                device_name,
                _CHECK_LOG_SEVERITY,
                "FAIL",
                "log.disk/setting could not be retrieved",
            )
        ]

    configured = str(cfg.get("severity", "")).lower()
    if not configured:
        return [
            _cis_row(
                device_name,
                _CHECK_LOG_SEVERITY,
                "CONFIG_MISSING",
                "severity field not found in log.disk/setting response",
            )
        ]

    raw_max = _to_str(params.get("max_severity", "")).lower()
    if not raw_max:
        return [
            _cis_row(
                device_name,
                _CHECK_LOG_SEVERITY,
                "CONFIG_MISSING",
                f"Configured log severity: {configured} (no expected maximum supplied)",
            )
        ]

    try:
        configured_idx = _SEVERITY_ORDER.index(configured)
    except ValueError:
        return [
            _cis_row(
                device_name,
                _CHECK_LOG_SEVERITY,
                "CONFIG_MISSING",
                f"Unrecognised configured severity value: '{configured}'",
            )
        ]

    try:
        max_idx = _SEVERITY_ORDER.index(raw_max)
    except ValueError:
        return [
            _cis_row(
                device_name,
                _CHECK_LOG_SEVERITY,
                "CONFIG_MISSING",
                f"Unrecognised expected severity value: '{raw_max}'",
            )
        ]

    # Lower index = more severe / finer. Configured must be ≤ max_idx (equal or finer).
    if configured_idx > max_idx:
        return [
            _cis_row(
                device_name,
                _CHECK_LOG_SEVERITY,
                "FAIL",
                f"Log severity is '{configured}' — coarser than required maximum '{raw_max}' (low-level events missed)",
            )
        ]
    return [
        _cis_row(
            device_name,
            _CHECK_LOG_SEVERITY,
            "PASS",
            f"Log severity is '{configured}' (≤ '{raw_max}')",
        )
    ]


# ── Check: FortiAnalyzer logging configured (CIS #8) ─────────────────────────

_CHECK_LOG_FAZ = "FortiAnalyzer Logging (CIS)"


def _run_log_faz(device_name: str, device_data: dict, params: dict) -> list[dict]:
    """CIS: verify FortiAnalyzer logging is enabled and server matches expected host (IP or FQDN).

    Checks all FAZ slots (log.fortianalyzer, log.fortianalyzer2, log.fortianalyzer3).
    """
    slots: list[dict] = device_data.get("log_faz") or []
    if not slots:
        return [
            _cis_row(
                device_name,
                _CHECK_LOG_FAZ,
                "FAIL",
                "log.fortianalyzer/setting could not be retrieved",
            )
        ]

    # Collect all enabled servers across all slots
    enabled_servers: list[str] = []
    any_enabled = False
    for slot in slots:
        status = str(slot.get("status", "disable")).lower()
        server = str(slot.get("server", "")).strip()
        if status == "enable":
            any_enabled = True
            if server:
                enabled_servers.append(server)

    if not any_enabled:
        return [
            {
                **_cis_row(
                    device_name,
                    _CHECK_LOG_FAZ,
                    "FAIL",
                    "FortiAnalyzer logging is disabled",
                ),
                "ip": "",
            }
        ]

    expected = _parse_host_list(params.get("expected_servers", []))
    configured_display = ", ".join(enabled_servers) if enabled_servers else "(none)"

    if not expected:
        detail = (
            f"FortiAnalyzer logging enabled. Configured server(s): {configured_display}"
        )
        return [
            {
                **_cis_row(device_name, _CHECK_LOG_FAZ, "CONFIG_MISSING", detail),
                "ip": configured_display,
            }
        ]

    parts = []
    any_match = False
    for exp in expected:
        matched = False
        ann = ""
        for srv in enabled_servers:
            ok, a = _match_host(exp, srv)
            if ok:
                matched = True
                ann = a
                break
        if matched:
            any_match = True
            entry = f"{exp} ✓" + (f" ({ann})" if ann else "")
        else:
            entry = f"{exp} ✗ (not found)"
        parts.append(entry)

    detail = ", ".join(parts)
    if any_match:
        result = "PASS"
    elif enabled_servers:
        result = "WARN"
    else:
        result = "FAIL"
    return [
        {
            **_cis_row(device_name, _CHECK_LOG_FAZ, result, detail),
            "ip": configured_display,
        }
    ]


# ── Check: DNS servers configured (CIS #9) ───────────────────────────────────

_CHECK_DNS = "DNS Servers (CIS)"


def _run_dns(device_name: str, device_data: dict, params: dict) -> list[dict]:
    """CIS: verify expected DNS servers (IP or FQDN) are configured on the device."""
    cfg = device_data.get("dns", {})
    if not cfg:
        return [
            _cis_row(
                device_name, _CHECK_DNS, "FAIL", "system/dns could not be retrieved"
            )
        ]

    primary = str(cfg.get("primary", "")).strip()
    secondary = str(cfg.get("secondary", "")).strip()
    configured = [s for s in [primary, secondary] if s and s != "0.0.0.0"]
    ip_str = ", ".join(configured)
    expected = _parse_host_list(params.get("expected_servers", []))

    if not expected:
        detail = "DNS configured: " + (ip_str if ip_str else "(none)")
        return [
            {
                **_cis_row(device_name, _CHECK_DNS, "CONFIG_MISSING", detail),
                "ip": ip_str,
            }
        ]

    parts = []
    any_fail = False
    for exp in expected:
        matched = False
        annotation = ""
        for conf in configured:
            ok, ann = _match_host(exp, conf)
            if ok:
                matched = True
                annotation = ann
                break
        if matched:
            entry = f"{exp} ✓" + (f" ({annotation})" if annotation else "")
        else:
            entry = f"{exp} ✗ (not found)"
            any_fail = True
        parts.append(entry)

    detail = ", ".join(parts)
    if any_fail:
        result = "WARN" if configured else "FAIL"
    else:
        result = "PASS"
    return [
        {
            **_cis_row(device_name, _CHECK_DNS, result, detail),
            "ip": ip_str,
        }
    ]


# ── Check: SNMP version enforcement (CIS #10) ────────────────────────────────

_CHECK_SNMP_VERSION = "SNMP Version Enforcement (CIS)"


def _run_snmp_version(device_name: str, device_data: dict, params: dict) -> list[dict]:
    sysinfo = device_data.get("snmp_sysinfo", {})
    communities = device_data.get("snmp_community", [])

    snmp_enabled = (
        str(sysinfo.get("status", "disable")).lower() == "enable" if sysinfo else True
    )

    if not snmp_enabled:
        return [
            _cis_row(
                device_name,
                _CHECK_SNMP_VERSION,
                "PASS",
                "SNMP is disabled on this device",
            )
        ]

    if not isinstance(communities, list):
        communities = []

    active_v1v2 = [
        c.get("name", "?")
        for c in communities
        if isinstance(c, dict) and str(c.get("status", "enable")).lower() == "enable"
    ]

    if active_v1v2:
        return [
            _cis_row(
                device_name,
                _CHECK_SNMP_VERSION,
                "FAIL",
                f"Active SNMPv1/v2c community(s) found: {', '.join(active_v1v2)} — use SNMPv3 only",
            )
        ]
    return [
        _cis_row(
            device_name,
            _CHECK_SNMP_VERSION,
            "PASS",
            "No active SNMPv1/v2c communities — SNMP v3 or disabled",
        )
    ]


# ── Check: SNMP read-only (CIS #11) ──────────────────────────────────────────

_CHECK_SNMP_READONLY = "SNMP Read-Only (CIS)"


def _run_snmp_readonly(device_name: str, device_data: dict, params: dict) -> list[dict]:
    users = device_data.get("snmp_users", [])
    if not isinstance(users, list):
        users = []

    if not users:
        return [
            _cis_row(
                device_name, _CHECK_SNMP_READONLY, "PASS", "No SNMPv3 users configured"
            )
        ]

    write_users = [
        u.get("name", "?")
        for u in users
        if isinstance(u, dict)
        and str(u.get("write-access", "disable")).lower() == "enable"
    ]

    if write_users:
        return [
            _cis_row(
                device_name,
                _CHECK_SNMP_READONLY,
                "FAIL",
                f"SNMPv3 user(s) with write access: {', '.join(write_users)}",
            )
        ]
    return [
        _cis_row(
            device_name,
            _CHECK_SNMP_READONLY,
            "PASS",
            f"All {len(users)} SNMPv3 user(s) are read-only",
        )
    ]


# ── Check: Minimum TLS version (CIS #12) ─────────────────────────────────────

_CHECK_TLS_VERSION = "Minimum TLS Version (CIS)"
_WEAK_TLS = {"tlsv1-0", "tlsv1-1", "tlsv1.0", "tlsv1.1", "tls1.0", "tls1.1"}


def _run_tls_version(device_name: str, device_data: dict, params: dict) -> list[dict]:
    cfg = device_data.get("system_global", {})
    if not cfg:
        return [
            _cis_row(
                device_name,
                _CHECK_TLS_VERSION,
                "FAIL",
                "system/global could not be retrieved",
            )
        ]

    # FortiOS uses either admin-https-ssl-versions (space-sep string) or ssl-min-proto-version
    ssl_versions = str(
        cfg.get("admin-https-ssl-versions", "")
        or cfg.get("admin_https_ssl_versions", "")
    ).lower()
    ssl_min = str(
        cfg.get("ssl-min-proto-version", "") or cfg.get("ssl_min_proto_version", "")
    ).lower()

    raw_min = _to_str(params.get("min_tls", "")).lower()

    weak_found = [v for v in ssl_versions.split() if v in _WEAK_TLS]

    # Also check ssl-min-proto-version
    if ssl_min in _WEAK_TLS:
        weak_found.append(ssl_min)

    if not ssl_versions and not ssl_min:
        detail = "TLS version fields not found in system/global"
        if raw_min:
            detail += f" (expected minimum: {raw_min})"
        return [_cis_row(device_name, _CHECK_TLS_VERSION, "CONFIG_MISSING", detail)]

    if weak_found:
        return [
            _cis_row(
                device_name,
                _CHECK_TLS_VERSION,
                "FAIL",
                f"Weak TLS version(s) allowed: {', '.join(set(weak_found))}",
            )
        ]

    detail = []
    if ssl_versions:
        detail.append(f"admin-https-ssl-versions: {ssl_versions}")
    if ssl_min:
        detail.append(f"ssl-min-proto-version: {ssl_min}")
    return [
        _cis_row(
            device_name,
            _CHECK_TLS_VERSION,
            "PASS",
            "; ".join(detail) if detail else "No weak TLS versions detected",
        )
    ]


# ── Check: SSH strong ciphers (CIS #13) ──────────────────────────────────────

_CHECK_SSH_CIPHERS = "SSH Strong Ciphers (CIS)"
_WEAK_SSH_ENC = {
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "3des-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
}
_WEAK_SSH_MAC = {"hmac-md5", "hmac-md5-96", "hmac-sha1-96"}


def _run_ssh_ciphers(device_name: str, device_data: dict, params: dict) -> list[dict]:
    cfg = device_data.get("system_global", {})
    if not cfg:
        return [
            _cis_row(
                device_name,
                _CHECK_SSH_CIPHERS,
                "FAIL",
                "system/global could not be retrieved",
            )
        ]

    enc_raw = str(cfg.get("ssh-enc-algo", "") or cfg.get("ssh_enc_algo", "")).lower()
    mac_raw = str(cfg.get("ssh-mac-algo", "") or cfg.get("ssh_mac_algo", "")).lower()

    if not enc_raw and not mac_raw:
        return [
            _cis_row(
                device_name,
                _CHECK_SSH_CIPHERS,
                "CONFIG_MISSING",
                "ssh-enc-algo / ssh-mac-algo not found in system/global",
            )
        ]

    weak_enc = [c for c in enc_raw.replace(",", " ").split() if c in _WEAK_SSH_ENC]
    weak_mac = [m for m in mac_raw.replace(",", " ").split() if m in _WEAK_SSH_MAC]

    findings = []
    if weak_enc:
        findings.append(f"Weak SSH enc-algo: {', '.join(weak_enc)}")
    if weak_mac:
        findings.append(f"Weak SSH mac-algo: {', '.join(weak_mac)}")

    if findings:
        return [_cis_row(device_name, _CHECK_SSH_CIPHERS, "FAIL", "; ".join(findings))]
    return [
        _cis_row(
            device_name,
            _CHECK_SSH_CIPHERS,
            "PASS",
            "No weak SSH ciphers or MAC algorithms detected",
        )
    ]


# ── Check: Firmware version compliance (CIS #14) ─────────────────────────────

_CHECK_FIRMWARE = "Firmware Version Compliance (CIS)"


def _parse_version(ver: str) -> tuple[int, ...]:
    """Parse 'v7.4.3', '7.4.3', '7.4' into a comparable int tuple."""
    ver = ver.strip().lstrip("vV")
    parts = []
    for part in ver.split("."):
        try:
            parts.append(int(part))
        except ValueError:
            break
    return tuple(parts)


def _run_firmware_version(
    device_name: str, device_data: dict, params: dict
) -> list[dict]:
    meta = device_data.get("device_meta", {})
    raw_min = _to_str(params.get("min_version", ""))

    # Build version string from meta
    version_str = meta.get("version_str", "")
    if not version_str:
        os_ver = meta.get("os_ver", 0)
        mr = meta.get("mr")
        patch = meta.get("patch")
        major = (
            int(os_ver) // 100
            if str(os_ver).isdigit() and int(os_ver) >= 100
            else os_ver
        )
        if mr is not None and patch is not None:
            version_str = f"{major}.{mr}.{patch}"
        elif mr is not None:
            version_str = f"{major}.{mr}"
        else:
            version_str = str(os_ver)

    if not version_str or version_str in ("0", "0.0", "0.0.0"):
        return [
            _cis_row(
                device_name,
                _CHECK_FIRMWARE,
                "CONFIG_MISSING",
                "Firmware version not available in device record",
            )
        ]

    if not raw_min:
        return [
            _cis_row(
                device_name,
                _CHECK_FIRMWARE,
                "CONFIG_MISSING",
                f"Running firmware: {version_str} (no minimum version supplied)",
            )
        ]

    running = _parse_version(version_str)
    minimum = _parse_version(raw_min)

    if running < minimum:
        return [
            _cis_row(
                device_name,
                _CHECK_FIRMWARE,
                "FAIL",
                f"Firmware {version_str} is below minimum required {raw_min}",
            )
        ]
    return [
        _cis_row(
            device_name,
            _CHECK_FIRMWARE,
            "PASS",
            f"Firmware {version_str} meets minimum requirement of {raw_min}",
        )
    ]


# ── Check: HA sync status (CIS #15) ──────────────────────────────────────────

_CHECK_HA_SYNC = "HA Sync Status (CIS)"


def _run_ha_sync(device_name: str, device_data: dict, params: dict) -> list[dict]:
    ha = device_data.get("ha_status", {})
    if not ha:
        return [
            _cis_row(
                device_name,
                _CHECK_HA_SYNC,
                "CONFIG_MISSING",
                "HA status could not be retrieved from device",
            )
        ]

    mode = str(ha.get("mode", "standalone")).lower()
    if mode == "standalone" or not mode:
        return [
            _cis_row(
                device_name,
                _CHECK_HA_SYNC,
                "INFO",
                "Device is not configured for HA (standalone)",
            )
        ]

    members = ha.get("members", [])
    if not isinstance(members, list):
        members = []

    out_of_sync = [
        m.get("hostname", m.get("name", "?"))
        for m in members
        if isinstance(m, dict)
        and str(m.get("sync_status", "")).lower()
        not in ("synchronized", "in_sync", "insync")
    ]

    if out_of_sync:
        return [
            _cis_row(
                device_name,
                _CHECK_HA_SYNC,
                "FAIL",
                f"HA member(s) out of sync: {', '.join(out_of_sync)}",
            )
        ]
    member_count = len(members) if members else "unknown"
    return [
        _cis_row(
            device_name,
            _CHECK_HA_SYNC,
            "PASS",
            f"HA mode: {mode}, all {member_count} member(s) synchronized",
        )
    ]


# ── Check: Hostname changed from default (CIS) ────────────────────────────────

_CHECK_HOSTNAME = "Hostname Changed From Default (CIS)"
_DEFAULT_HOSTNAME_RE = _re.compile(r"^fgt\d+$", _re.IGNORECASE)


def _run_hostname_changed(
    device_name: str, device_data: dict, params: dict
) -> list[dict]:
    cfg = device_data.get("system_global", {})
    if not cfg:
        return [
            _cis_row(
                device_name,
                _CHECK_HOSTNAME,
                "FAIL",
                "system/global could not be retrieved",
            )
        ]
    raw_hostname = cfg.get("hostname")
    if raw_hostname is None:
        return [
            _cis_row(
                device_name,
                _CHECK_HOSTNAME,
                "CONFIG_MISSING",
                "Hostname field not found in system/global response",
            )
        ]
    hostname = str(raw_hostname).strip()
    if (
        not hostname
        or hostname.lower() in ("fortigate", "fortigate-vm")
        or _DEFAULT_HOSTNAME_RE.match(hostname)
    ):
        return [
            _cis_row(
                device_name,
                _CHECK_HOSTNAME,
                "FAIL",
                f"Hostname '{hostname or '(empty)'}' appears to be a factory default — set a unique name",
            )
        ]
    return [_cis_row(device_name, _CHECK_HOSTNAME, "PASS", f"Hostname: {hostname}")]


# ── Check: Non-default admin ports (CIS) ─────────────────────────────────────

_CHECK_ADMIN_PORT = "Non-Default Admin Port (CIS)"


def _run_admin_port_nondefault(
    device_name: str, device_data: dict, params: dict
) -> list[dict]:
    cfg = device_data.get("system_global", {})
    if not cfg:
        return [
            _cis_row(
                device_name,
                _CHECK_ADMIN_PORT,
                "CONFIG_MISSING",
                "system/global could not be retrieved",
            )
        ]
    https_port = (
        cfg.get("admin-sport") or cfg.get("admin_sport") or cfg.get("adminsport")
    )
    http_port = cfg.get("admin-port") or cfg.get("admin_port") or cfg.get("adminport")
    if https_port is None and http_port is None:
        return [
            _cis_row(
                device_name,
                _CHECK_ADMIN_PORT,
                "CONFIG_MISSING",
                "Admin port fields not found in system/global response",
            )
        ]
    warnings = []
    try:
        if https_port is not None and int(https_port) == 443:
            warnings.append("HTTPS admin port is still default (443)")
        if http_port is not None and int(http_port) == 80:
            warnings.append("HTTP admin port is still default (80)")
    except (ValueError, TypeError):
        return [
            _cis_row(
                device_name,
                _CHECK_ADMIN_PORT,
                "CONFIG_MISSING",
                "Admin port value is non-numeric — cannot verify",
            )
        ]
    if warnings:
        return [_cis_row(device_name, _CHECK_ADMIN_PORT, "WARN", "; ".join(warnings))]
    parts = []
    if https_port:
        parts.append(f"HTTPS:{https_port}")
    if http_port:
        parts.append(f"HTTP:{http_port}")
    desc = f" ({', '.join(parts)})" if parts else ""
    return [
        _cis_row(
            device_name,
            _CHECK_ADMIN_PORT,
            "PASS",
            f"Admin ports changed from defaults{desc}",
        )
    ]


# ── Check: Pre-login banner (CIS) ────────────────────────────────────────────

_CHECK_BANNER = "Pre-Login Banner Enabled (CIS)"


def _run_prelogin_banner(
    device_name: str, device_data: dict, params: dict
) -> list[dict]:
    cfg = device_data.get("system_global", {})
    if not cfg:
        return [
            _cis_row(
                device_name,
                _CHECK_BANNER,
                "FAIL",
                "system/global could not be retrieved",
            )
        ]
    val = str(
        cfg.get("pre-login-banner")
        or cfg.get("pre_login_banner")
        or cfg.get("preloginbanner")
        or "disable"
    ).lower()
    if val != "enable":
        return [
            _cis_row(
                device_name,
                _CHECK_BANNER,
                "FAIL",
                "Pre-login banner is disabled — enable it to display a legal/acceptable-use notice",
            )
        ]
    return [_cis_row(device_name, _CHECK_BANNER, "PASS", "Pre-login banner is enabled")]


# ── Check: Timezone explicitly set (CIS) ─────────────────────────────────────

_CHECK_TIMEZONE = "Timezone Explicitly Configured (CIS)"


def _run_timezone_set(device_name: str, device_data: dict, params: dict) -> list[dict]:
    cfg = device_data.get("system_global", {})
    if not cfg:
        return [
            _cis_row(
                device_name,
                _CHECK_TIMEZONE,
                "CONFIG_MISSING",
                "system/global could not be retrieved",
            )
        ]
    tz = cfg.get("timezone")
    if tz is None or str(tz).strip() == "":
        return [
            _cis_row(
                device_name,
                _CHECK_TIMEZONE,
                "CONFIG_MISSING",
                "Timezone not set — affects log timestamp correlation across devices",
            )
        ]
    return [_cis_row(device_name, _CHECK_TIMEZONE, "PASS", f"Timezone: {tz}")]


# ── VPN / IPsec Security Checks ───────────────────────────────────────────────

_WEAK_DH_GROUPS: frozenset[int] = frozenset({1, 2, 5})
_WEAK_VPN_TOKENS: frozenset[str] = frozenset({"des", "3des", "md5"})
_CHECK_VPN_CRYPTO = "VPN Weak Crypto (Phase1/Phase2) (CIS)"
_CHECK_VPN_PFS = "VPN Perfect Forward Secrecy (CIS)"
_CHECK_VPN_IKE = "VPN IKE Version (CIS)"


def _vpn_proposal_weak_tokens(proposal: str) -> list[str]:
    """Return deduplicated weak token names found in a proposal string."""
    seen: dict[str, None] = {}
    for token in proposal.lower().replace(",", " ").split():
        for part in token.split("-"):
            if part in _WEAK_VPN_TOKENS:
                seen[part] = None
    return list(seen)


def _vpn_dhgrp_weak(dhgrp: str) -> list[int]:
    """Return weak DH group numbers found in a space-separated dhgrp string."""
    weak = []
    for token in str(dhgrp).split():
        try:
            g = int(token)
            if g in _WEAK_DH_GROUPS:
                weak.append(g)
        except ValueError:
            pass
    return weak


def _run_vpn_weak_crypto(
    device_name: str, device_data: dict, params: dict
) -> list[dict]:
    phase1 = device_data.get("ipsec_phase1") or []
    phase2 = device_data.get("ipsec_phase2") or []
    if not phase1 and not phase2:
        return [
            _cis_row(
                device_name, _CHECK_VPN_CRYPTO, "INFO", "No IPsec tunnels configured"
            )
        ]

    weak_findings: list[str] = []
    for entry in phase1:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name", "?")
        weak_t = _vpn_proposal_weak_tokens(str(entry.get("proposal", "")))
        weak_g = _vpn_dhgrp_weak(str(entry.get("dhgrp", "")))
        parts = []
        if weak_t:
            parts.append(f"weak algo: {', '.join(weak_t)}")
        if weak_g:
            parts.append(f"weak DH group(s): {', '.join(str(g) for g in weak_g)}")
        if parts:
            weak_findings.append(f"{name} ({'; '.join(parts)})")

    for entry in phase2:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name", "?")
        weak_t = _vpn_proposal_weak_tokens(str(entry.get("proposal", "")))
        if weak_t:
            weak_findings.append(f"{name} [ph2] (weak algo: {', '.join(weak_t)})")

    total = len(phase1) + len(phase2)
    if weak_findings:
        return [
            _cis_row(
                device_name,
                _CHECK_VPN_CRYPTO,
                "FAIL",
                f"Weak crypto in {len(weak_findings)} tunnel(s): {'; '.join(weak_findings)}",
            )
        ]
    return [
        _cis_row(
            device_name,
            _CHECK_VPN_CRYPTO,
            "PASS",
            f"No weak crypto across {total} phase1/phase2 entries",
        )
    ]


def _run_vpn_pfs(device_name: str, device_data: dict, params: dict) -> list[dict]:
    phase2 = device_data.get("ipsec_phase2") or []
    if not phase2:
        return [
            _cis_row(
                device_name,
                _CHECK_VPN_PFS,
                "INFO",
                "No IPsec phase2 tunnels configured",
            )
        ]
    no_pfs = [
        str(e.get("name", "?"))
        for e in phase2
        if isinstance(e, dict) and str(e.get("pfs", "enable")).lower() == "disable"
    ]
    if no_pfs:
        return [
            _cis_row(
                device_name,
                _CHECK_VPN_PFS,
                "WARN",
                f"PFS disabled on phase2 tunnel(s): {', '.join(no_pfs)}",
            )
        ]
    return [
        _cis_row(
            device_name,
            _CHECK_VPN_PFS,
            "PASS",
            f"PFS enabled on all {len(phase2)} phase2 tunnel(s)",
        )
    ]


def _run_vpn_ike_version(
    device_name: str, device_data: dict, params: dict
) -> list[dict]:
    phase1 = device_data.get("ipsec_phase1") or []
    if not phase1:
        return [
            _cis_row(
                device_name,
                _CHECK_VPN_IKE,
                "INFO",
                "No IPsec phase1 tunnels configured",
            )
        ]

    aggressive: list[str] = []
    ikev1_main: list[str] = []
    for entry in phase1:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name", "?")
        ver = str(entry.get("ike-version") or entry.get("ike_version") or "1")
        mode = str(entry.get("mode", "main")).lower()
        if ver == "1":
            if mode == "aggressive":
                aggressive.append(name)
            else:
                ikev1_main.append(name)

    if aggressive:
        detail = f"IKEv1 aggressive mode (PSK hash exposed pre-auth): {', '.join(aggressive)}"
        if ikev1_main:
            detail += f"; IKEv1 main mode: {', '.join(ikev1_main)}"
        return [_cis_row(device_name, _CHECK_VPN_IKE, "FAIL", detail)]
    if ikev1_main:
        return [
            _cis_row(
                device_name,
                _CHECK_VPN_IKE,
                "WARN",
                f"IKEv1 (legacy) on tunnel(s): {', '.join(ikev1_main)} — upgrade to IKEv2",
            )
        ]
    return [
        _cis_row(
            device_name,
            _CHECK_VPN_IKE,
            "PASS",
            f"All {len(phase1)} phase1 tunnel(s) use IKEv2",
        )
    ]


# ── Check registry ────────────────────────────────────────────────────────────

CHECKS: list[dict[str, Any]] = [
    {
        "key": "interface_protocols",
        "name": "Interface Protocols",
        "description": "Shows all interfaces with management access — highlights insecure protocols (HTTP, Telnet)",
        "data_keys": ["interfaces"],
        "params_schema": [],
        "run": _run_interface_protocols,
    },
    {
        "key": "ntp_config",
        "name": "NTP Configuration (CIS)",
        "description": "CIS: verify NTP sync is enabled and configured servers match expected IPs",
        "data_keys": ["ntp"],
        "params_schema": [
            {
                "key": "expected_servers",
                "label": "Expected NTP Servers",
                "type": "ip_list",
                "placeholder": "e.g. 10.1.1.1, ntp.corp.com",
                "required": False,
            }
        ],
        "run": _run_ntp_config,
    },
    {
        "key": "syslog_config",
        "name": "Syslog Configuration (CIS)",
        "description": "CIS: verify remote syslog is enabled and sending to expected server IPs",
        "data_keys": ["syslog"],
        "params_schema": [
            {
                "key": "expected_servers",
                "label": "Expected Syslog Servers",
                "type": "ip_list",
                "placeholder": "e.g. 10.2.2.1, syslog.corp.com",
                "required": False,
            }
        ],
        "run": _run_syslog_config,
    },
    # ── Admin Account Hardening ────────────────────────────────────────────────
    {
        "key": "trusted_hosts",
        "name": "Trusted Hosts on Admin Accounts (CIS)",
        "description": "CIS L1: flag any admin account with no trusted-host IP restriction (unrestricted management access)",
        "data_keys": ["admins"],
        "params_schema": [],
        "run": _run_trusted_hosts,
    },
    {
        "key": "default_admin",
        "name": "Default 'admin' Account (CIS)",
        "description": "CIS L1: flag if the built-in 'admin' account exists and is active — it should be renamed or disabled",
        "data_keys": ["admins"],
        "params_schema": [],
        "run": _run_default_admin,
    },
    {
        "key": "admin_mfa",
        "name": "Admin Two-Factor Authentication (CIS)",
        "description": "CIS L1: flag any admin account with two-factor authentication disabled",
        "data_keys": ["admins"],
        "params_schema": [],
        "run": _run_admin_mfa,
    },
    {
        "key": "idle_timeout",
        "name": "Admin Idle Timeout (CIS)",
        "description": "CIS L1: verify admin session idle timeout does not exceed the configured maximum (e.g. 10 minutes)",
        "data_keys": ["system_global"],
        "params_schema": [
            {
                "key": "max_timeout_minutes",
                "label": "Max idle timeout (minutes)",
                "type": "number",
                "placeholder": "e.g. 10",
                "required": False,
            }
        ],
        "run": _run_idle_timeout,
    },
    {
        "key": "lockout_threshold",
        "name": "Admin Lockout Threshold (CIS)",
        "description": "CIS L1: verify failed-login lockout threshold does not exceed the configured maximum (e.g. 5 attempts)",
        "data_keys": ["system_global"],
        "params_schema": [
            {
                "key": "max_attempts",
                "label": "Max failed login attempts",
                "type": "number",
                "placeholder": "e.g. 5",
                "required": False,
            }
        ],
        "run": _run_lockout_threshold,
    },
    {
        "key": "password_length",
        "name": "Password Minimum Length (CIS)",
        "description": "CIS L1: verify the password minimum-length policy meets the configured requirement (e.g. 12 characters)",
        "data_keys": ["password_policy"],
        "params_schema": [
            {
                "key": "min_length",
                "label": "Min password length",
                "type": "number",
                "placeholder": "e.g. 12",
                "required": False,
            }
        ],
        "run": _run_password_length,
    },
    # ── Logging ────────────────────────────────────────────────────────────────
    {
        "key": "log_disk",
        "name": "Local Disk Logging (CIS)",
        "description": "CIS L1: verify local disk logging is enabled on the device",
        "data_keys": ["log_disk"],
        "params_schema": [],
        "run": _run_log_disk,
    },
    {
        "key": "log_severity",
        "name": "Log Severity Level (CIS)",
        "description": "CIS L1: verify disk log severity captures at least the expected level (e.g. information)",
        "data_keys": ["log_disk"],
        "params_schema": [
            {
                "key": "max_severity",
                "label": "Maximum severity threshold",
                "type": "text",
                "placeholder": "e.g. information",
                "required": False,
            }
        ],
        "run": _run_log_severity,
    },
    {
        "key": "log_faz",
        "name": "FortiAnalyzer Logging (CIS)",
        "description": "CIS L1: verify FortiAnalyzer logging is enabled and the server IP matches expected",
        "data_keys": ["log_faz"],
        "params_schema": [
            {
                "key": "expected_servers",
                "label": "Expected FortiAnalyzer Servers",
                "type": "ip_list",
                "placeholder": "e.g. 10.2.2.10, faz.corp.com",
                "required": False,
            }
        ],
        "run": _run_log_faz,
    },
    # ── Network Services ───────────────────────────────────────────────────────
    {
        "key": "dns_servers",
        "name": "DNS Servers (CIS)",
        "description": "CIS L1: verify expected DNS server IPs are configured on the device",
        "data_keys": ["dns"],
        "params_schema": [
            {
                "key": "expected_servers",
                "label": "Expected DNS Servers",
                "type": "ip_list",
                "placeholder": "e.g. 10.3.3.1, dns.corp.com",
                "required": False,
            }
        ],
        "run": _run_dns,
    },
    {
        "key": "snmp_version",
        "name": "SNMP Version Enforcement (CIS)",
        "description": "CIS L1: flag if any SNMPv1 or SNMPv2c community is active — only SNMPv3 should be used",
        "data_keys": ["snmp_community", "snmp_sysinfo"],
        "params_schema": [],
        "run": _run_snmp_version,
    },
    {
        "key": "snmp_readonly",
        "name": "SNMP Read-Only (CIS)",
        "description": "CIS L2: flag if any SNMPv3 user has write access enabled",
        "data_keys": ["snmp_users"],
        "params_schema": [],
        "run": _run_snmp_readonly,
    },
    # ── Protocol Security ──────────────────────────────────────────────────────
    {
        "key": "tls_version",
        "name": "Minimum TLS Version (CIS)",
        "description": "CIS L1: flag if TLS 1.0 or 1.1 are permitted for HTTPS admin access",
        "data_keys": ["system_global"],
        "params_schema": [
            {
                "key": "min_tls",
                "label": "Minimum TLS version",
                "type": "text",
                "placeholder": "e.g. tlsv1-2",
                "required": False,
            }
        ],
        "run": _run_tls_version,
    },
    {
        "key": "ssh_ciphers",
        "name": "SSH Strong Ciphers (CIS)",
        "description": "CIS L2: flag if weak CBC-mode ciphers or MD5 MAC algorithms are permitted for SSH",
        "data_keys": ["system_global"],
        "params_schema": [],
        "run": _run_ssh_ciphers,
    },
    # ── Fortinet-Specific ──────────────────────────────────────────────────────
    {
        "key": "firmware_version",
        "name": "Firmware Version Compliance (CIS)",
        "description": "CIS L1: verify device firmware meets the configured minimum version (e.g. 7.4.3)",
        "data_keys": ["device_meta"],
        "params_schema": [
            {
                "key": "min_version",
                "label": "Minimum firmware version",
                "type": "text",
                "placeholder": "e.g. 7.4.3",
                "required": False,
            }
        ],
        "run": _run_firmware_version,
    },
    {
        "key": "ha_sync",
        "name": "HA Sync Status (CIS)",
        "description": "CIS L2: verify all HA members are synchronized (PASS if standalone or all in sync; FAIL if any out of sync)",
        "data_keys": ["ha_status"],
        "params_schema": [],
        "run": _run_ha_sync,
    },
    # ── Hardening ──────────────────────────────────────────────────────────────
    {
        "key": "hostname_changed",
        "name": "Hostname Changed From Default (CIS)",
        "description": "CIS L1: flag if hostname is still a factory default (FortiGate, FGT + serial pattern)",
        "data_keys": ["system_global"],
        "params_schema": [],
        "run": _run_hostname_changed,
    },
    {
        "key": "admin_port_nondefault",
        "name": "Non-Default Admin Port (CIS)",
        "description": "CIS L1: warn if admin HTTPS port is still 443 or HTTP port is still 80",
        "data_keys": ["system_global"],
        "params_schema": [],
        "run": _run_admin_port_nondefault,
    },
    {
        "key": "prelogin_banner",
        "name": "Pre-Login Banner Enabled (CIS)",
        "description": "CIS L1: fail if pre-login banner is disabled — a legal notice should be displayed",
        "data_keys": ["system_global"],
        "params_schema": [],
        "run": _run_prelogin_banner,
    },
    {
        "key": "timezone_set",
        "name": "Timezone Explicitly Configured (CIS)",
        "description": "CIS L1: flag if timezone is not set — affects log timestamp correlation across devices",
        "data_keys": ["system_global"],
        "params_schema": [],
        "run": _run_timezone_set,
    },
    # ── VPN / IPsec ────────────────────────────────────────────────────────────
    {
        "key": "vpn_weak_crypto",
        "name": "VPN Weak Crypto (Phase1/Phase2) (CIS)",
        "description": "CIS L2: flag IPsec tunnels using weak encryption (DES/3DES), weak hash (MD5), or weak DH groups (1/2/5)",
        "data_keys": ["ipsec_phase1", "ipsec_phase2"],
        "params_schema": [],
        "run": _run_vpn_weak_crypto,
    },
    {
        "key": "vpn_pfs",
        "name": "VPN Perfect Forward Secrecy (CIS)",
        "description": "CIS L2: warn if any phase2 IPsec tunnel has PFS disabled",
        "data_keys": ["ipsec_phase2"],
        "params_schema": [],
        "run": _run_vpn_pfs,
    },
    {
        "key": "vpn_ike_version",
        "name": "VPN IKE Version (CIS)",
        "description": "CIS L2: fail if any phase1 uses IKEv1 aggressive mode; warn for IKEv1 main mode",
        "data_keys": ["ipsec_phase1"],
        "params_schema": [],
        "run": _run_vpn_ike_version,
    },
]

# Serialisable metadata (no "run" key) — used by page template and API
CHECKS_META: list[dict[str, Any]] = [
    {k: v for k, v in c.items() if k != "run"} for c in CHECKS
]

_CHECKS_BY_KEY: dict[str, dict] = {c["key"]: c for c in CHECKS}


# ── Public entry point ────────────────────────────────────────────────────────


def run_checks(
    device_name: str,
    device_data: dict,
    check_keys: list[str] | None = None,
    check_params: dict | None = None,
) -> list[dict]:
    """Run the requested checks and return combined rows.

    *check_keys* defaults to all registered checks.
    *check_params* maps check key → dict of user-supplied parameter values.
    *device_data* must contain all keys required by the selected checks
    (interfaces, ntp, syslog) — callers are responsible for fetching them.
    """
    keys = check_keys if check_keys is not None else [c["key"] for c in CHECKS]
    params_map = check_params or {}
    rows: list[dict] = []
    for key in keys:
        entry = _CHECKS_BY_KEY.get(key)
        if entry:
            params = params_map.get(key, {})
            rows.extend(entry["run"](device_name, device_data, params))
    return rows
