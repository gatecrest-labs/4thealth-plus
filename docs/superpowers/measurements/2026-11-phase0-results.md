# Phase 0 results and go/no-go (2026-11-10)

Plan: `docs/superpowers/plans/2026-11-10-scale-phase0-foundations.md`.
Design: `docs/superpowers/specs/2026-11-10-scale-1000-fortigates-design.md` (section 7a gates).

## 1. Baseline (done)
Today's background sweeps make **3,887.8 FMG calls/hour** at 1,000 synthetic
devices; `pending_status_cache` is 3,340/h of that. Inventory is downloaded 7
times per cycle. Target for later phases: <= ~389 calls/h for the same sweeps.
Details and scope limits: `README.md`, raw data `2026-11-baseline-1000.json`.

## 2. Shared-store proof
| Where | Journal | Result |
|---|---|---|
| macOS (APFS, two processes), `verify_shared_store.py --seconds 8` | WAL | SAFE (integrity ok, 3,304 reads, 0 reader errors) |
| macOS (APFS, two processes) | DELETE | SAFE (integrity ok, 7,432 reads, 0 reader errors) |
| Docker Desktop, web + collector containers sharing `./data` | WAL | collector snapshot readable from web container; 3,421 calls, 0 errors |
| **RHEL VM, two systemd units, `4thealth` user** | WAL / DELETE | **NOT YET RUN (owner action, see below)** |

Finding fixed during the proof: two processes creating a fresh store at the
same instant could hit `database is locked` (1 of 480 simultaneous first uses
in a race test). `collector_store` now retries transient locks (0 of 960
afterwards).

Owner action on the RHEL VM (as the app user, on the real filesystem):
`sudo -u 4thealth /opt/4thealth/.venv/bin/python scripts/verify_shared_store.py --db /opt/4thealth/proof.db --seconds 10`
Expect two `SAFE` lines. If WAL reports `UNSAFE`, set `COLLECTOR_DB_JOURNAL=DELETE`
in `/opt/4thealth/.env` (both units read it) and re-run.

## 3. Lab FMG spikes: BLOCKED
`scripts/fmg_spike.py` is built and tested, but the lab FMG answered the API
token in `.env` with FMG code `-11` ("No permission for the resource") on
`GET /dvmdb/adom`, so no spike could run. Needed from the owner: a lab API
token whose admin profile can read dvmdb and policy packages, then run
`devices-fields`, `proxy-multi`, `pkg-marker` and `latency` and commit the
reports after reading them for sensitive data.

## 4. Gates applied (spec 7a), with the safe fallbacks
| Question | Status | Decision for later phases |
|---|---|---|
| WAL across the two units | Proven on macOS/Docker; RHEL pending | Phase 1+ may proceed; `COLLECTOR_DB_JOURNAL=DELETE` is the fallback |
| `fields`/`loadsub` payload savings | Unknown (blocked) | Phase 2 ships for call-count reduction regardless; add trimming when measured |
| Package change marker | Unknown (blocked) | Phase 4 uses hash + TTL (6 h forced refetch) only; add a marker if one is found |
| Multi-target proxy | Unknown (blocked) | Phase 5 uses the rolling window only; add batching if proven |
| Proxy/FMG latency | Unknown (blocked) | Re-tune interval defaults after measuring |

No gate blocks Phase 1: every fallback is safe (more FMG reads or smaller
batches, never stale or incorrect data).

## 5. Other findings
- `FMGClient._get_paged` bypassed `_post` (and so metrics, the recorder and
  any replacement transport) -- fixed.
- The synthetic FMG does not implement `GET /sys/audit-log` (change control
  cache); that sweep is outside the baseline.
- The baseline covers background sweeps only; interactive and scheduled-report
  call volume is measured when the phase that changes it lands.
