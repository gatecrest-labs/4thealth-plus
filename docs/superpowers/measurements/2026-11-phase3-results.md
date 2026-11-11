# Phase 3 results: Config-Delta gating and hygiene package cache (2026-11-10)

Produced by
`uv run python scripts/measure_fmg_baseline.py --devices 1000 --inventory-cache --policy-store`
(raw data: `2026-11-phase3-1000.json`). Same synthetic fleet as the baseline (1,000
devices, 5 ADOMs, 80 packages/ADOM x 300 rules), `INVENTORY_CACHE` and `POLICY_STORE` on.

| Source | Baseline /h | Phase 2 /h | Phase 3 /h | Why |
|---|---:|---:|---:|---|
| exec_hygiene_sweep | 446.0 | 445.0 | **111.7** | cold sweep 445 calls; warm sweeps only list packages and objects; each package is refetched once per ~6 h (jittered) instead of every hour |
| inventory_cache | n/a | 132.0 | 132.0 | unchanged (raise `INVENTORY_REFRESH_SECS` to 600 to halve it) |
| license_status_cache | 41.9 | 41.7 | 41.7 | one proxy call per device per day |
| summary_job | 17.1 | 16.9 | 16.9 | rule counts still read policy packages live (Phase 4) |
| device_backup_cache | 0.5 | 0.2 | 0.2 | |
| pending_status / exec device / versions / map / adom | 3,382.2 | 0 | 0 | from the inventory store since Phase 2 |
| **Total** | **3,887.8** | **635.8** | **302.4** | **12.9x lower than baseline; target <= ~389 met** |

Steady state for the hygiene sweep is `warm x (60 / interval) + (cold - warm) / TTL_hours`: a
cold sweep downloads every package once, then each package is served from the cache until its
jittered TTL (6 h x 0.75..1.25) expires, so refetches spread across hourly sweeps instead of
arriving as one burst. A package whose policy list is unchanged on refetch only has its age
refreshed.

## Config-Delta gating (scheduled runs)

On the same fleet a scheduled run previews **270 of 1,000 devices** and gates 730 (in sync per
the inventory cache). The synthetic fleet is pessimistic (about 10% of devices are
`outofsync`, 10% have a modified database and some a modified package); a real fleet with
few pending changes gates far more. Each previewed device costs 4 FMG calls and holds the
per-ADOM staging lock, so the saving is mostly wall-clock time: a sequential 1,000-device
run (about 4,000 calls) becomes about 1,100. A forced full sweep still previews every device
every 24 h, so the blind window for a missed change is at most 24 h plus the inventory age
(up to ~10 min).

## What is left

Sources now: inventory refresh 44%, hygiene 37%, license 14%, summary 6%. Further cuts need
Phase 4 (policy lists in the store so the hygiene sweep and the summary rule counts stop
downloading them) or a longer `INVENTORY_REFRESH_SECS`. A verified cheap package change
marker (the `obj ver` field of `/pm/pkg/adom/<adom>` entries is unconfirmed; it needs an
owner lab spike: edit a rule and compare) would let the TTL stretch safely.

Caveats: synthetic fleet; FMG task queue, proxy throttling and version differences are not
exercised; the lab has one device.
