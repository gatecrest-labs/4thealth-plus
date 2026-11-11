# Phase 2 results: inventory cache (2026-11-10)

Produced by `uv run python scripts/measure_fmg_baseline.py --devices 1000 --inventory-cache`
(raw data: `2026-11-phase2-1000.json`). Same synthetic fleet as the baseline
(1,000 devices, 5 ADOMs, ~40% multi-VDOM). The collector's inventory refresh runs
first at its 5-minute interval; every other sweep then reads the store.

| Source | Baseline /h | Phase 2 /h | Why |
|---|---:|---:|---|
| pending_status_cache | 3,340.0 | 0 | one ADOM-wide `_package/status` call per ADOM, inside the inventory refresh, replaced one call per device per VDOM |
| inventory_cache (new) | n/a | 132.0 | 11 calls per 5 min: ADOM list + device list + package status for 5 ADOMs |
| exec_hygiene_sweep | 446.0 | 445.0 | unchanged: downloads every policy; Phases 3-4 |
| license_status_cache | 41.9 | 41.7 | still one proxy call per device; its device list now comes from the store |
| summary_job | 17.1 | 16.9 | rule counts still read policy packages live (Phase 4) |
| exec_device_sweep | 28.0 | 0 | from the store |
| versions_cache | 12.0 | 0 | from the store |
| adom_cache | 2.0 | 0 | from the store |
| device_backup_cache | 0.5 | 0.2 | revisions still one call per ADOM |
| map_cache | 0.2 | 0 | from the store |
| **Total** | **3,887.8** | **635.8** | **6.1x lower; target for this phase was <= 700** |

Inventory is downloaded once per cycle (was 7). Facade fallbacks during the run: 0.

What is left, in order: the hygiene sweep (70% of the remaining calls, Phase 3: once per
package, only for changed packages; Phase 4: policy store), the inventory refresh itself
(132/h; raising `INVENTORY_REFRESH_SECS` to 600 halves it), and the per-device license
proxy calls (daily, Phase 5 territory). Reaching the 10x target (<= ~389/h) needs the
hygiene sweep to fall below about 200/h.

Caveats: synthetic fleet, so FMG task queue, proxy throttling and version differences are
not exercised; the lab has one device. The Firewalls detail modal and the Rule Validation
planner remain live by design. The executive device sweep also makes live infra-target
fetches (SNMP/FMG-style) each cycle, which are not FortiManager calls and are outside
these numbers.
