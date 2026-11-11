"""Per-device configuration reads for Device Review and PSIRT.

One table maps each ``data_key`` the checks name (see ``CHECKS_META``) to the
``FMGClient`` getter that fetches it and the empty value used when it fails.
``fetch_device_data`` keeps the long-standing behaviour (any failure becomes the
empty value); ``fetch_device_data_checked`` also says whether each key actually
failed, so the collector can avoid storing "we could not ask" as "nothing there".
"""

from __future__ import annotations

# data_key -> (FMGClient getter, empty value factory)
DATA_KEYS: dict[str, tuple[str, type]] = {
    "interfaces": ("get_device_interfaces_all_vdoms", list),
    "ntp": ("get_device_ntp", dict),
    "syslog": ("get_device_syslog", list),
    "admins": ("get_device_admins", list),
    "system_global": ("get_device_system_global", dict),
    "password_policy": ("get_device_password_policy", dict),
    "log_disk": ("get_device_log_disk", dict),
    "log_faz": ("get_device_log_faz", list),
    "dns": ("get_device_dns", dict),
    "snmp_community": ("get_device_snmp_community", list),
    "snmp_sysinfo": ("get_device_snmp_sysinfo", dict),
    "snmp_users": ("get_device_snmp_users", list),
    "ha_status": ("get_device_ha_status", dict),
    "ipsec_phase1": ("get_device_ipsec_phase1", list),
    "ipsec_phase2": ("get_device_ipsec_phase2", list),
}


def fetch_device_data(
    client, adom: str, device: str, keys: set[str], device_meta: dict | None = None
) -> dict:
    """Fetch only the device data blobs required by the selected checks."""
    data: dict = {}
    for key, (getter, empty) in DATA_KEYS.items():
        if key not in keys:
            continue
        try:
            data[key] = getattr(client, getter)(adom, device)
        except Exception:
            data[key] = empty()
    # device_meta is passed in by the caller (already fetched from the device list)
    if "device_meta" in keys:
        data["device_meta"] = device_meta or {}
    return data


def fetch_device_data_checked(
    client, adom: str, device: str, keys: set[str]
) -> dict[str, tuple[object, str | None]]:
    """``{key: (value, failure_or_None)}`` for each requested proxy-backed key.

    ``failure`` is set when FortiManager could not be asked (transport error, RPC
    error, device unreachable); the value is then the empty value and must not be
    stored. An empty value with no failure is a real answer.
    """
    out: dict[str, tuple[object, str | None]] = {}
    for key, (getter, empty) in DATA_KEYS.items():
        if key not in keys:
            continue
        with client.capture_proxy_failures() as failures:
            try:
                value, error = getattr(client, getter)(adom, device), None
            except Exception as exc:
                value, error = empty(), f"{type(exc).__name__}: {exc}"
        if failures and error is None:
            error = "; ".join(dict.fromkeys(failures))
        out[key] = (value, error)
    return out
