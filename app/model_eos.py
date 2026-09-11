"""Static FortiGate hardware end-of-support (EOS) table. Update when
Fortinet publishes new EOS dates. Mirrors app/version_eol.py's pattern for
FortiOS software EOL, but keyed by hardware platform string with an actual
end-of-support DATE rather than a fixed set of version strings, since
hardware lifecycle is naturally a "when", not a boolean.

Source: Fortinet's Product Life Cycle portal
(https://support.fortinet.com/welcome/#/lifecycle), cross-referenced via a
third-party aggregation (https://jimber.io/blog/fortigate-hardware-end-of-life-timeline/)
as of authoring (2026-09-10). This is a curated subset of commonly deployed
models, not Fortinet's full hardware catalog — verify against the official
portal before relying on this for a model not listed here.

Models are matched by exact platform_str as returned by FortiManager's
dvmdb device object (e.g. "FortiGate-100F") — the same field
app/pending_status_cache.py and app/device_review.py already read as
"platform"/"platform_str".

CRITICAL: unlike app.version_eol.is_eol() (which returns False for an
unrecognized version), is_hw_eos()/hw_eos_within() return None for a model
not in this table. Absence of data must never render as "not EOS" — that
would silently understate fleet lifecycle risk for models this table
simply hasn't been updated to include yet.
"""

from __future__ import annotations

import datetime

_HW_EOS: dict[str, datetime.date] = {
    "FortiGate-60C": datetime.date(2020, 4, 15),
    "FortiGate-40C": datetime.date(2020, 7, 1),
    "FortiGate-80C": datetime.date(2021, 4, 21),
    "FortiGate-30D": datetime.date(2021, 11, 30),
    "FortiGate-70D": datetime.date(2022, 7, 16),
    "FortiGate-500D": datetime.date(2023, 5, 8),
    "FortiGate-200D": datetime.date(2023, 5, 22),
    "FortiGate-100D": datetime.date(2023, 7, 26),
    "FortiGate-60D": datetime.date(2023, 9, 23),
    "FortiGate-300D": datetime.date(2023, 10, 11),
    "FortiGate-90D": datetime.date(2023, 10, 14),
    "FortiGate-600D": datetime.date(2024, 10, 14),
    "FortiGate-90E": datetime.date(2025, 1, 14),
    "FortiGate-240D": datetime.date(2025, 3, 13),
    "FortiGate-52E": datetime.date(2025, 4, 15),
    "FortiGate-3800D": datetime.date(2026, 1, 14),
    "FortiGate-1200D": datetime.date(2026, 4, 16),
    "FortiGate-30E": datetime.date(2026, 7, 15),
    "FortiGate-61E": datetime.date(2026, 7, 15),
    "FortiGate-70E": datetime.date(2026, 7, 15),
    "FortiGate-101E": datetime.date(2026, 7, 15),
    "FortiGate-300E": datetime.date(2026, 7, 15),
    "FortiGate-301E": datetime.date(2026, 7, 15),
    "FortiGate-500E": datetime.date(2026, 7, 15),
    "FortiGate-501E": datetime.date(2026, 7, 15),
    "FortiGate-80E": datetime.date(2026, 8, 17),
    "FortiGate-100E": datetime.date(2026, 8, 17),
    "FortiGate-50E": datetime.date(2026, 11, 14),
    "FortiGate-81E": datetime.date(2026, 11, 14),
    "FortiGate-60E": datetime.date(2026, 12, 29),
    "FortiGate-1500D": datetime.date(2026, 12, 31),
    "FortiGate-1500DT": datetime.date(2026, 12, 31),
    "FortiGate-51E": datetime.date(2027, 7, 15),
    "FortiGate-80E-POE": datetime.date(2027, 7, 15),
    "FortiGate-60E-POE": datetime.date(2027, 10, 14),
    "FortiGate-800D": datetime.date(2028, 4, 16),
    "FortiGate-900D": datetime.date(2028, 4, 16),
    "FortiGate-1000D": datetime.date(2028, 4, 16),
    "FortiGate-3200D": datetime.date(2028, 4, 16),
    "FortiGate-3600E": datetime.date(2029, 4, 15),
    "FortiGate-3601E": datetime.date(2029, 4, 15),
    "FortiGate-3400E": datetime.date(2030, 4, 16),
    "FortiGate-3401E": datetime.date(2030, 4, 16),
    "FortiGate-2000E": datetime.date(2030, 5, 2),
    "FortiGate-200E": datetime.date(2030, 10, 13),
    "FortiGate-201E": datetime.date(2030, 10, 13),
    "FortiGate-400E": datetime.date(2030, 10, 13),
    "FortiGate-401E": datetime.date(2030, 10, 13),
    "FortiGate-6300F": datetime.date(2031, 1, 13),
    "FortiGate-200F": datetime.date(2031, 3, 1),
    "FortiGate-201F": datetime.date(2031, 3, 1),
    "FortiGate-6500F": datetime.date(2031, 4, 15),
    "FortiGate-100F": datetime.date(2031, 4, 16),
    "FortiGate-101F": datetime.date(2031, 4, 16),
    "FortiGate-600F": datetime.date(2031, 5, 1),
    "FortiGate-601F": datetime.date(2031, 5, 1),
    "FortiGate-70F": datetime.date(2031, 5, 17),
    "FortiGate-1101E": datetime.date(2031, 7, 30),
    "FortiGate-1100E": datetime.date(2031, 9, 13),
}


def _normalize(model: str) -> str:
    return (model or "").strip()


def _add_months(d: datetime.date, months: int) -> datetime.date:
    total = d.month - 1 + months
    year = d.year + total // 12
    month = total % 12 + 1
    # Clamp the day for months with fewer days (e.g. Jan 31 + 1 month).
    day = min(
        d.day,
        [
            31,
            29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28,
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ][month - 1],
    )
    return datetime.date(year, month, day)


def is_hw_eos(model: str, as_of: datetime.date | None = None) -> bool | None:
    """True if model's hardware has already reached end-of-support as of
    `as_of` (default: today). None if model isn't in the table — never
    False for an unknown model."""
    eos_date = _HW_EOS.get(_normalize(model))
    if eos_date is None:
        return None
    as_of = as_of or datetime.datetime.now(tz=datetime.UTC).date()
    return as_of >= eos_date


def hw_eos_within(
    model: str, months: int, as_of: datetime.date | None = None
) -> bool | None:
    """True if model's EOS date falls within the next `months` months of
    `as_of` (default: today) — inclusive of a model already past EOS, since
    that is trivially "within" any forward-looking window. None if model
    isn't in the table — never False for an unknown model."""
    eos_date = _HW_EOS.get(_normalize(model))
    if eos_date is None:
        return None
    as_of = as_of or datetime.datetime.now(tz=datetime.UTC).date()
    return eos_date <= _add_months(as_of, months)
