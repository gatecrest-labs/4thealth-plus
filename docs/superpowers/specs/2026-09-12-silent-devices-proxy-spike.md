# Spike: silent-devices `last_log_at` field

**Date:** 2026-09-12
**Status:** resolved (partial) — connectivity proxy shipped, log-freshness deferred

## Question

The Wave 4 drill-down spec (`~/Downloads/4texecutive2.md`, prompt W4-2)
asks for a "silent devices" rollup shaped
`[{devid, devname, last_log_at}]` — devices that have stopped sending
logs. No such concept existed anywhere in this codebase before this
change (confirmed by grep for `silent`, `last_log`, `not_forwarding`,
`log_forwarding`, `checkin` across `app/` and `docs/` — zero hits).

## What shipped

`app.executive_summary_cache._build_silent_devices()` uses the one
connectivity signal already read by the existing device sweep — FMG's
`conn_status` field on `/dvmdb/adom/{adom}/device` (1 = connected to
FortiManager). A device with `conn_status != 1` is counted as "silent"
and appears in `silent_devices.details`, capped at 50, sorted by ADOM
then device name.

This is a **connectivity** proxy (is the device reachable from
FortiManager?), not a **log-freshness** check (is the device still
forwarding logs to FortiAnalyzer?). The two can disagree in both
directions: a device can be connected to FMG but have stopped logging
(e.g. a misconfigured `log_faz` setting — see the existing `log_faz`
Device Review check in `app/device_review_severity.py`), or briefly
disconnected from FMG while still logging normally.

## Why `last_log_at` is always `None`

No module in this codebase currently queries FortiAnalyzer for
per-device last-log timestamps. The closest existing FortiAnalyzer
touchpoint is `app/infra_health_cache.py`'s SNMP health poll of the
FortiAnalyzer *appliance itself* (CPU/mem/disk), not per-device log
activity. Fabricating a value here would be worse than omitting it —
same principle as `change_control.oldest_pending_change_days` (see
`app/executive_summary_cache.py`'s module docstring) and
`lifecycle.models_unknown` (`app/model_eos.py`).

## Resolution

Ship the connectivity proxy now (it's genuinely useful — an
unreachable device also isn't logging). Leave `last_log_at` as `None`
until a real FortiAnalyzer log-query API is confirmed against lab
hardware, at which point `_build_silent_devices()` should be extended
(or replaced) to use actual log timestamps instead of `conn_status`.
Candidate API: FortiAnalyzer's `/logview/adom/{adom}/logsearch` or a
per-device last-log report via FortiView — neither has been confirmed
against the lab FortiAnalyzer for this purpose (distinct from the
already-confirmed admin-access/threat-stats FortiView queries shipped
in 4tlog's P12/P13).
