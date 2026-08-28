"""Static severity classification for app.device_review's 26 CIS-derived checks.

The check registry (app/device_review.py CHECKS) has no explicit severity
field -- CIS L1/L2 tiering lives only in free-text descriptions. This table
is a one-time hand classification, reviewed alongside the checks themselves;
update it when a check is added, removed, or reclassified.
"""

from __future__ import annotations

SEVERITY: dict[str, str] = {
    "interface_protocols": "high",
    "ntp_config": "medium",
    "syslog_config": "medium",
    "trusted_hosts": "high",
    "default_admin": "critical",
    "admin_mfa": "critical",
    "idle_timeout": "medium",
    "lockout_threshold": "medium",
    "password_length": "high",
    "log_disk": "medium",
    "log_severity": "low",
    "log_faz": "medium",
    "dns_servers": "low",
    "snmp_version": "high",
    "snmp_readonly": "medium",
    "tls_version": "high",
    "ssh_ciphers": "high",
    "firmware_version": "high",
    "ha_sync": "critical",
    "hostname_changed": "low",
    "admin_port_nondefault": "low",
    "prelogin_banner": "low",
    "timezone_set": "low",
    "vpn_weak_crypto": "critical",
    "vpn_pfs": "high",
    "vpn_ike_version": "high",
}
