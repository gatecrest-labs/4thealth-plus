# Scale to 1,000+ FortiGates: caching and FMG-load design

Date: 2026-11-10. Branch: `develop`. Status: DRAFT for owner review. Scope chosen by owner: **Full (option C)**.
Sources: `~/Documents/4thealth-notes/scale-review-1000-devices.md` (2026-09-01), recon of current `develop`, and a devil's-advocate review (findings folded in below).

## 1. Intent

4thealth-plus will be installed as a stand-alone server (virtual RHEL VM, production) against one FortiManager managing ~1,000 FortiGates (~2,000 VDOMs, ~5 ADOMs, several hundred policy packages). It must stay fast and correct there. Today almost every tab and background job talks to FMG directly and repeatedly. Goal: FMG is read on a schedule by the collector, results are kept in a shared local store, and tabs read from that store, so interactive use costs ~zero FMG calls and background load is bounded, staggered and observable.

Production runs **without containers**: bare RHEL VM, two systemd units (`4thealth.service` gunicorn web, `4thealth-collector.service` running `python -m app.collector` with `RUN_SCHEDULERS=inline`) behind Nginx, as already documented in `docs/deployment.md` section 2.6. No Podman. Docker Compose exists only as the owner's Mac test rig, so a design that works in prod must not depend on Docker, and anything Docker-specific is test-rig-only.

Testing happens in Docker on the owner's Mac first, then on the RHEL VM. Only one real lab FMG with one device exists, so 1,000-device behaviour is proven with a synthetic generator plus staged measurement, not assumed.

## 2. Goals / non-goals / anti-goals

Goals
- Cut FMG call volume and payload size by an order of magnitude for steady-state use.
- Every cached view shows "data as of" time and can be refreshed on demand.
- Every new layer is behind an env flag with the old code path intact (rollback = flag + restart).
- Remains strictly read-only toward Fortinet devices.

Non-goals
- Postgres/Redis, multi-host/HA deployment, Kubernetes. (SQLite on one host.)
- Moving job run-history JSON files to SQLite (cut: not a scale problem).
- Serving CIS audit checks from FMG's device database instead of the live device (stale-config risk; revisit only per-field after measurement).
- A circuit breaker in the first iteration (backoff + per-process cap only).

Anti-goals (failure even if it "works")
- An audit result that looks current but is stale.
- A cache that leaks ADOM data to users not permitted to see it.
- A restart or crash that corrupts the shared store or loses the last good snapshot.

## 3. Constraints and decisions

Decided by owner: scope = Full (all phases below).

**Decided by owner (runtime):** production is systemd services on RHEL, no Podman or containers. Web and collector are two units on one host sharing one local filesystem (state under `/opt/4thealth`, owned by the `4thealth` user). Consequences: SQLite WAL works normally between the two units (no cross-container sidecar problem); SELinux only needs the normal file contexts for `/opt/4thealth` and `/var/log/4thealth` (existing `docs/deployment.md` 3.2 notes); `docs/deployment.md` gets the new units/env flags/upgrade steps; `docker-compose.yml` is kept working for Mac testing only.

**Recommendation for owner review (decision 2, auth):** use **FMG API-token auth only at scale**. Token auth means no FMG login/logout per client; the user/password path creates a real FMG admin session per `with make_client()`, and FMG caps admin sessions. Add a startup warning when username/password auth is used and the cache layers are on.

**Recommendation for owner review (decision 3, audit data):** *hybrid with provenance.* Device Review, PSIRT and scheduled audit reports read rolling per-device snapshots; every result row/report carries `collected_at` and a "snapshot" marker; snapshots older than a max-age ceiling (default 24 h, configurable) are fetched live before being used; interactive runs get a **Live** toggle and per-device Refresh; compliance verdicts are never shown without their timestamp. Nothing is served from FMG's device DB in v1.

Builder's calls (marked so they can be challenged):
- Storage: SQLite (WAL) on the local filesystem, shared by the two systemd units; the DB directory must be writable by the `4thealth` user and not on NFS. For the **Docker test rig only**: `docker-compose.yml:42,98` mounts the single file `collector_state.db`, so WAL sidecars live in each container separately; move the DB into a mounted directory for the rig (and verify on Docker Desktop virtiofs, falling back to `journal_mode=DELETE`, configurable). Also check `atomic_io` rename-over-file on the rig's other single-file mounts. Phase 0 additionally proves WAL between the two units on a real RHEL VM, including a kill -9 / restart test.
- Cache stores hold per-ADOM data, never per-user results; ADOM access (`check_adom_access`) is applied at read time. DB files mode 0600, gitignored.
- Request-path SQLite reads are indexed queries (no whole-blob `json.loads` of large datasets).

## 4. Architecture

```
FMG <-- F1 access layer (pooled session, per-process cap, backoff, metrics) <-- collector (only writer)
                                                                  |
                          shared SQLite store in ./data (inventory, packages/policies/objects, device snapshots, jobs)
                                                                  |
                 web workers (read-only, ADOM-filtered, "as of" metadata) --> tabs, external API, 4tExecutive
```

Shared layers:
- **F1 FMG access layer.** One `requests.Session` pool per process; a semaphore wrapping only `_post` (never whole operations such as `get_install_preview` polling); retry with jittered backoff on 5xx/connection errors; per-call latency/count counters surfaced on Admin. Cap is per process (web x2 + collector = 3 processes), so the collector gets the large cap and web a small one.
- **F2 Inventory cache.** One fetch per ADOM (parallel across ADOMs) of devices + VDOMs + HA + conn/conf/db status, trimmed with `fields`/`loadsub` (to be measured). Tables indexed by adom/device. Consumers migrate one at a time: summary_job, versions_cache, map_cache, pending_status_cache, executive_summary_cache, device_backup_cache, license_status_cache, adom_cache, Firewalls list, search, Device Review device list, `api_routes.devices`.
- **F3 Policy/object store.** One row per package (policies) and per object, indexed by adom/pkg; per-package fingerprint. Serves Rule Review policy table, Rule Lookup (replaces the per-process in-memory cache; the collector warms it), Object/NAT/Interface lookup, Hygiene, unused-objects, exec hygiene sweep, Package Change Alerts. Hygiene `run_checks` runs once per package (not twice) and only for changed packages.
  Change detection is **not trusted alone**: cheap ADOM-level signal where one is verified to exist, fingerprint hash of the fetched policy list, and a forced full refetch every N hours (default 6) plus Refresh-now.
- **F5 Config-Delta gating.** `bulk_preview_adom` currently previews every device. Preview only devices whose cached conf/db/pkg status is pending; unknown status fails open (preview it); concurrency 1-2 per ADOM; job time budget.
- **F4 Device audit snapshots.** Rolling window (default one seventh of the fleet per night, plus on-demand) fetching the per-device data blobs Device Review/PSIRT need (≤15 proxy calls per device today), stored per device with `collected_at` and which data_keys. Evaluate multi-target `/sys/proxy/json` batching in Phase 0.
- **F6 Job queue.** Long interactive actions (Device Review run, hygiene run) become server-side jobs with progress polling (pattern: `pending_changes_routes._write_task`), surviving tab close and not pinning web threads. Jobs run in the collector or a bounded worker, results stored.
- **F7 Boot.** Priority-ordered, jittered warm-up (ADOM list, inventory, then the rest); web serves last persisted snapshot immediately after restart.
- **F8 Freshness UI.** Every cached view shows "data as of", a stale/degraded badge, and a Refresh button (admin-throttled).

## 5. Phases (each shippable behind a flag, each with tests)

0. **Foundations and measurement**: journal-mode proof on the real RHEL VM (two systemd units) and on the Docker rig (directory mount); feature-flag scaffold; FMG call metrics; synthetic 1,000-device generator extending `app/fmg_recorder.py`/replay fixtures (latency + 5xx injection, call-count assertions); lab-FMG spikes: `fields`/`loadsub` payload savings, package change marker, multi-target proxy, per-call latency.
1. **F1** access layer.
2. **F2** inventory cache, consumer migration, **F7**, **F8** (first views).
3. **F5** preview gating; hygiene once-per-package.
4. **F3** policy/object store; Rule Lookup onto it; remaining consumers; F8 for these views.
5. **F4** audit snapshots (decision 3 behaviour).
6. **F6** job queue.
Order rationale: F1 before F2/F5; measurement before assumptions; F3 depends on the Phase 0 storage proof; F4/F6 depend on F2/F3.

Per-tab outcome: Dashboard/Map/Versions/Firewalls list/Search/Device Review device list = inventory cache. Firewalls detail (10-13 proxy calls) = on demand with short TTL. Rule Review, Rule Lookup, Hygiene, Object/NAT/Interface lookup = policy/object store. Audit Review = snapshots + job queue. Config-Delta = gated previews. Rule Validation planner = single live request, reusing cached object catalogs where safe. Zone Policy = unchanged (local).

## 6. Risks and mitigations
- Stale audit data → provenance on every row, max-age ceiling, Live toggle (decision 3).
- Missed policy changes → hash + TTL ceiling + Refresh-now; never marker-only.
- SQLite sharing between the two units (and, in the Docker test rig only, across containers / macOS virtiofs) → Phase 0 proof, configurable journal mode, crash/restart test; not NFS.
- Session limits → token auth required at scale; warn otherwise.
- ADOM leakage → store per ADOM, filter at read via `check_adom_access`; PSIRT `"*"` and search are the risky paths.
- Boot storm → F7.
- FMG ADOM workspace locks during previews → F5 gating, low concurrency, never hold the F1 cap across polling.
- Synthetic rig cannot prove FMG task queue, proxy throttling, `-11` permission failures or version differences → staged ramp on the lab FMG, FMG load observed.

## 7. Left to the builder
Table schemas and migrations, exact default intervals/caps (to be set from Phase 0 measurements), flag names, and UI placement of freshness badges, within the constraints above.

## 7a. Builder-check answers (builder's calls unless noted)
- **Status of decisions (2026-11-10):** all owner-confirmed: scope = Full; runtime = systemd units on RHEL (no containers/Podman); FMG auth = API token (password auth only warns); audit data = hybrid snapshots with 24 h ceiling and Live toggle. Acceptance targets below are the builder's recommendation, accepted unless the owner changes them. No phase is gated on an open decision.
- **"Collector":** the existing `4thealth-collector` systemd unit (`app/collector.py`, `RUN_SCHEDULERS=inline`; in the Mac rig, the `collector` compose service). F2/F3/F4 extend its scheduler set; it stays the only writer. F6 jobs run in that same service (a bounded worker pool); web only enqueues and reads. No new process.
- **"Old path intact":** a layer-level rollback switch, not dual implementations per consumer. Each flag (`INVENTORY_CACHE`, `POLICY_STORE`, `AUDIT_SNAPSHOTS`, `JOB_QUEUE`) selects cache vs. legacy fetch at one seam per consumer; legacy code is deleted one release after the layer has soaked on the RHEL server.
- **Acceptance targets (re-tuned from Phase 0 measurements):** (1) Phase 0 records today's FMG calls/hour on the 1,000-device rig as the baseline; steady state must be >=10x lower. (2) Cached pages (Dashboard, Firewalls list, Versions, Map) p95 < 1 s; searches (Rule Lookup, object/NAT/interface lookup) p95 < 2 s; neither makes FMG calls on request except explicit Refresh and Firewalls detail. (3) App-wide FMG in-flight requests <= 16; no overlapping install previews within one ADOM. (4) Memory on the rig: each web worker < ~1 GB RSS, collector < ~2 GB. (5) Cold boot serves last snapshot within 10 s; every collector cycle finishes inside its interval; 24 h soak shows no thread/pool growth; inventory data <= 10 min old 95% of the time.
- **Freshness defaults:** inventory 5-10 min (status fields drive F5), policy store 6 h forced refetch plus change detection, device snapshots 24 h ceiling. F5 treats a cached status older than 2x the inventory interval as unknown and previews the device (fail open).
- **Phase 0 go/no-go:** gates after Phase 0. WAL fails across containers: use `journal_mode=DELETE`, continue. No usable package change marker: F3 relies on hash + TTL (more FMG reads, still correct), continue. Proxy batching unavailable: F4 proceeds with rolling window only. `fields`/`loadsub` give no saving: F2 still ships for call-count reduction. A gate only blocks a phase if its stated fallback is unsafe, and then work stops for owner review.
- **F6 jobs:** stored in the shared SQLite store with owner username, ADOM scope at creation, status, progress, result; web reads only jobs the requester owns (admin sees all) and re-applies `check_adom_access` on read; owner or admin may cancel; jobs and results pruned after 7 days.
- **Parity (section 8) is out of scope for this plan**; tracked separately.

## 8. Parity with web/4thealth (separate, small; NOT part of this plan)
Re-diffed 2026-11-10 against `09e7941`: no functional gaps. Pending owner decision: port missing `help.js` text, review `docs/backup.md`/`docs/deployment.md` changes, and the new header logo. Skipping the "Device Review" tab rename (collides with Audit Review) and upstream's simplified `_vip_addr_and_detail`.
