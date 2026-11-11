# Phase 4 results: policy and object store (2026-11-11)

Produced by `uv run python scripts/measure_fmg_baseline.py --devices 1000 --inventory-cache --policy-store`
(raw data: `2026-11-phase4-1000.json`) and `scripts/verify_policy_store_load.py --adoms 5 --packages 80 --rules 300 --readers 2`
(raw data: `2026-11-phase4-load.json`). Synthetic fleet: 1,000 devices, 5 ADOMs, 80 packages/ADOM x 300 rules.

## Background FMG calls per hour

| Source | Baseline | Phase 3 | Phase 4 | Notes |
|---|---:|---:|---:|---|
| policy_cache_packages (new) | n/a | n/a | 90.7 | cold cycle 406 calls (400 packages + 5 lists + ADOM list), then ~6 calls per 15-minute cycle; each package refetched once per ~6 h (jittered) |
| policy_cache_objects (new) | n/a | n/a | 45.0 | 6 object kinds x 5 ADOMs + 4 shared global kinds, hourly (address tables page into several calls) |
| exec_hygiene_sweep | 446.0 | 111.7 | **0** | reads the store; findings recomputed only when a package fingerprint changes |
| summary_job | 17.1 | 16.9 | **0** | rule counts from the store |
| inventory_cache | n/a | 132.0 | 132.0 | unchanged |
| license_status_cache | 41.9 | 41.7 | 41.7 | per-device proxy calls |
| everything else | 3,382.6 | 0.2 | 0.2 | |
| **Total** | **3,887.8** | **302.4** | **309.5** | background floor is flat vs Phase 3 by design |

The gain in Phase 4 is for everyone else who used to call FortiManager: Rule Review, Rule Lookup, Object /
NAT / Interface lookups, Where-Used, Hygiene runs, the unused-object finder and the scheduled Rule Hygiene,
Rule Policy and NAT reports now make **zero** FMG calls for packages, policies, policy blocks and objects (per-device
proxy reads, the `unhit` hit-count overlay, Package Change Alerts and the Rule Validation planner stay live by
design). One interactive "Where used" scan used to download every package of the ADOM; it now reads the store.

## Store size, latency and Rule Lookup (load check)

| Measure | Result |
|---|---|
| Cold write of 400 packages x 300 rules + objects (collector code path) | 2.0 s + 0.1 s |
| Database size (synthetic rules) | 2.1 MB (synthetic rules are very repetitive; see estimate below) |
| Concurrent readers (2 processes, 2,094 reads) | p50 1.0 ms, p95 6.0 ms, 0 errors |
| Rule Lookup index, 24,000 rules, built from the store | 0.30 s, 31.8 MB Python peak, 0 FMG calls |
| Rule Lookup search over those rules | 0.08 s (unit test) |

Realistic size: a FortiOS-shaped rule (~45 keys, ~1 KB JSON) compresses about 8x with zlib, so 400 packages of
300 rules is **about 15 MB** in the store (119 MB uncompressed). Plan for 15-40 MB with objects, blocks and the
cached hygiene findings. Targets met: cached searches p95 < 2 s, web worker well under 1 GB.

## Staleness (what you gave up)

Policy data is up to about 7.5 h old (6 h TTL x up to 1.25 jitter) unless a user clicks **Refresh** on a package
(served by the collector within ~10 s). During an FMG outage a row is served for up to 15 h, then readers go live.
Every package view and every scheduled report older than 15 minutes says so ("Policies as of ...").

## Caveats

Synthetic fleet: FMG task queue, proxy throttling, FortiOS version differences and real policy shapes (policy
blocks with `_policy_block`, global objects) are only approximated. The package list entries' `scope member` and
`package settings` keys are assumed present as Rule Lookup already assumes; verify on the lab FMG with a package that
has a scope. Run `scripts/verify_policy_store_load.py` on the RHEL VM once before go-live (see `docs/deployment.md`).
