# Phase 5 results: device audit snapshots (2026-11-11)

Produced by `uv run python scripts/measure_fmg_baseline.py --devices 1000 --inventory-cache --policy-store --audit-snapshots`
(raw data: `2026-11-phase5-1000.json`) and `scripts/verify_snapshot_load.py --readers 2`
(raw data: `2026-11-phase5-snapshot-load.json`). Synthetic fleet: 1,000 devices, 5 ADOMs, 15 proxy-backed data keys per device.

## Background FMG calls per hour

| Source | Phase 4 | Phase 5 | Notes |
|---|---:|---:|---|
| snapshot_cache (new) | n/a | 120.0 | steady state: one device per 10-minute batch, 20 FMG calls each (15 data keys plus the lookups around them) |
| snapshot_revisions (new) | n/a | 5.0 | one revision-list call per ADOM per hour; flags devices whose FMG config is newer than their snapshot |
| everything else | 309.5 | 309.5 | unchanged |
| **Total** | **309.5** | **434.5** | still 8.9x below the original 3,887.8/hour |

The 434.5 total is slightly above the ~400 floor the plan predicted, because one capture is 20 calls rather than 15. It is
the price of a new background job: Device Review and PSIRT never ran in the background before, so the baseline contained no
cost for them.

## What it buys

| Measure | Result |
|---|---|
| Bulk Device Review of one ADOM (200 devices), live | 4,000 proxy calls |
| Same run from snapshots | **0** FMG calls, 6,077 rows in 0.09 s |
| First capture of the whole fleet (cold) | 20,000 calls, 7 s against the synthetic FMG; spread over about 1 day by the collector (never-captured devices are captured first) |
| PSIRT workaround checks | read interfaces and admins from the store, zero proxy calls |

## Store size and latency (load check)

| Measure | Result |
|---|---|
| Capture of 1,000 devices through the collector code path | 8.7 s |
| Database size (WAL included) | 4.0 MB |
| Per-device snapshot read with 2 concurrent reader processes | p50 1.4 ms, p95 6.6 ms (10,538 reads) |
| Errors | none |

## The window trade-off (the decision for the owner)

The design spec asked for both "a 24 h max-age ceiling" and "one seventh of the fleet per night". Those conflict, so the
build defaults to option B and exposes both knobs.

| Option | Setting | snapshot_cache calls/hour | Total/hour | Worst-case data age |
|---|---|---:|---:|---|
| A. daily refresh | `AUDIT_SNAPSHOT_WINDOW_DAYS=1` | 840 | 1,154.5 | about 1 day (+ ceiling) |
| **B. default** | `AUDIT_SNAPSHOT_WINDOW_DAYS=7` | **120** | **434.5** | up to 8 days, but a changed device is refreshed within about an hour |
| C. 14-day window | `AUDIT_SNAPSHOT_WINDOW_DAYS=14` | 120 | 434.5 | up to 15 days |

Option C measures **no better than B at 1,000 devices**: the collector already captures at the minimum of one device per
batch (144 per day), which covers 1,000 devices in 7 days. A longer window only helps once `AUDIT_SNAPSHOT_BATCH_MINUTES` is
also raised (for example 20 minutes would halve the cost and need a 14-day window to cover the fleet), or on larger fleets.

## Not measured here

Against a real FortiManager: the synthetic transport answers instantly, so per-capture wall time and how the FortiManager
copes with 20 proxy calls per capture are unproven. The lab check is the same two RHEL proofs as earlier phases plus
`scripts/verify_snapshot_load.py` on the production host.
