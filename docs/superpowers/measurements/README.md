# Scale measurements

Results from the 1,000-FortiGate scale work (design:
`docs/superpowers/specs/2026-11-10-scale-1000-fortigates-design.md`).
Everything here is produced by scripts in `scripts/` against either the
synthetic FMG (`app/synthetic_fmg.py`) or the owner's lab FMG. Committed
files must contain no real hostnames, IPs or serials (the repo is public).

## Baseline: background-sweep FMG calls per hour (2026-11-10)

Produced by `uv run python scripts/measure_fmg_baseline.py --devices 1000`
(raw data: `2026-11-baseline-1000.json`). Synthetic fleet: 1,000 devices,
5 ADOMs, ~40% multi-VDOM, 80 packages/ADOM x 300 rules, zero latency.
Each sweep runs once; calls/hour = calls x 60 / the sweep's own interval.

| Sweep | Calls per run | Interval | Calls/hour |
|---|---:|---|---:|
| pending_status_cache | 1,670 | 30 min | 3,340.0 |
| exec_hygiene_sweep | 446 | 60 min | 446.0 |
| license_status_cache | 1,006 | daily | 41.9 |
| exec_device_sweep | 7 | 15 min | 28.0 |
| summary_job | 411 | daily | 17.1 |
| versions_cache | 6 | 30 min | 12.0 |
| adom_cache | 1 | 30 min | 2.0 |
| device_backup_cache | 11 | daily | 0.5 |
| map_cache | 6 | daily | 0.2 |
| **Total** | | | **3,887.8** |

**Target for later phases: <= ~389 calls/hour for the same sweeps (10x lower).**

Inventory (`get /dvmdb/adom/{adom}/device`) is downloaded **7 times per
cycle** across the sweeps (finding C2).

### What this baseline does and does not cover
- Covers: the scheduled background sweeps listed above.
- Does NOT cover: interactive page loads (Firewalls list/detail, search,
  Rule Review), scheduled Device Review / Rule Hygiene / NAT / Config-Delta
  reports, install previews, PSIRT assessment. Those are measured when the
  phase that changes them lands.
- Wall-clock figures (hygiene sweep ~30 s here) are CPU only; real FMG
  latency is not modelled at zero latency. Re-run with `--latency-ms 20 80`
  for a rough latency-bound estimate.
- Real FMG behaviour (task queue, proxy throttling, version differences)
  cannot be proven by the synthetic rig.

## Phase 2: inventory cache (2026-11-10)

`uv run python scripts/measure_fmg_baseline.py --devices 1000 --inventory-cache`
(raw data: `2026-11-phase2-1000.json`, write-up: `2026-11-phase2-results.md`):
3,887.8 -> 635.8 background FMG calls/hour (6.1x lower). The remaining 10x needs the
hygiene sweep reduced (Phases 3-4).

## Phase 3: Config-Delta gating and hygiene package cache (2026-11-10)

`uv run python scripts/measure_fmg_baseline.py --devices 1000 --inventory-cache --policy-store`
(raw data: `2026-11-phase3-1000.json`, write-up: `2026-11-phase3-results.md`): 635.8 -> 302.4
background FMG calls/hour (12.9x below the original 3,887.8; target <= ~389 met). A scheduled
Config-Delta run previews 270 of 1,000 synthetic devices.
