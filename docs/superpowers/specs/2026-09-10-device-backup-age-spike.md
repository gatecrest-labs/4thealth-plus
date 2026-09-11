# Device Configuration Backup Age — Spike Result

## Context

Wave 2's P9 prompt (`~/Downloads/4texecutive2.md`) asked for two things in
4thealth-plus:

1. Hardware end-of-support (EOS) counts — shipped, see `app/model_eos.py`
   and the `"lifecycle"` key added to `GET /external/api/executive/summary`.
2. Device configuration backup age — investigate FortiManager's JSON-RPC
   revision-history endpoint for a device, implement
   `FMGClient.get_device_last_revision(adom, device)`, run it in a daily
   fleet-wide job, and expose `"device_backup"`.

This document is the spike result for (2). Per the prompt's own fallback
("if the endpoint cannot be confirmed against the lab FMG, ship Part 1 only
and write the findings here"), **(2) is not implemented in this change.**

## What was checked

- **This repo's vendored API knowledge.** Unlike PSIRT (`app/psirt/`) and
  the FortiView work, which ported a vendored FMG/FortiAnalyzer API spec
  from `~/code/github/ai/4tanalyst`, no FMG API reference for a per-device
  "revision" or "config backup" resource is vendored anywhere in this repo.
  `app/fmg_client.py` has no existing caller of anything resembling a
  device-level revision-history endpoint — the closest neighbor,
  `get_install_preview()`, deals with FortiManager's *install-preview*
  workflow (pending policy changes not yet pushed to the device), which is
  a different concept from "when was this device's configuration last
  backed up."
- **Live confirmation against the lab FMG.** `.env` in this checkout points
  `FMG_PRIMARY_HOST` at `192.168.64.2`, but that host is not reachable from
  this development environment — `curl`/`ping` both fail with no route to
  that subnet (the environment's routing table has no entry for
  `192.168.64.0/24`, only a default route). There was no way to send a real
  JSON-RPC request and inspect the actual response shape, the way
  `get_install_preview()`'s task-ID fallback ordering was originally
  reverse-engineered by capturing the FMG GUI's own traffic (see CLAUDE.md's
  Config-Delta tab section) — that method needs a reachable FMG.

## Why this isn't a small, safe guess

Two genuinely different things could plausibly be called "device
configuration backup" in FortiManager, and guessing wrong would either
silently report the wrong signal or fail confusingly on install:

1. **ADOM database revision history** — FortiManager's Device Manager >
   Revision History screen (and the believed underlying resource,
   `/dvmdb/adom/<adom>/revision`) tracks snapshots of *FortiManager's own
   database* for that ADOM: policy and object changes made through FMG.
   This is not a backup of what's actually running on the physical
   FortiGate — a device could be fully in sync with this "revision" and
   still be running configuration that diverged out-of-band (or vice
   versa), so using it as "device backup age" would misrepresent exactly
   the kind of drift `devices_out_of_sync` (from the P8 change) already
   exists to catch.
2. **Actual device configuration backup** — a periodic archive of the
   FortiGate's own running config, which some FortiManager versions expose
   via Device Manager's per-device "Configuration > Revision History" GUI
   panel. Whether that panel is backed by a documented JSON-RPC resource
   (as opposed to an internal-only API not meant for scripting), and what
   its exact URL and field names are on FMG 7.4 vs. 7.6, is unconfirmed.

Implementing `get_device_last_revision()` against a guessed URL risks
either the same 7.4-vs-7.6 the `get_install_preview()` fallback-ordering
had to handle, or — worse — silently returning ADOM-revision data under a
"backup age" label, which would be actively misleading in the executive
summary rather than merely absent.

## Recommendation

Before implementing this:

1. Get a working session against the lab FMG (or an equivalent 7.4/7.6
   instance) from an environment with real network access to it.
2. Open Device Manager > (a device) > Revision History in the FMG GUI and
   capture its own network traffic (same method used for
   `get_install_preview()`), to confirm:
   - The actual endpoint URL and HTTP method.
   - Whether it reflects the FortiGate's own backed-up config or
     FortiManager's ADOM database revision (see above) — check whether the
     timestamps track policy edits made in FMG, or independent events like
     the device checking in.
   - The field names for revision timestamp, author, and description, and
     whether "no revision yet" is representable (a device that has never
     been backed up must be distinguishable from one whose latest revision
     is merely old — this repo's convention, per `app/model_eos.py` and
     `app/psirt/`, is "unknown never renders as a false negative").
3. Confirm behavior across whichever FMG major versions this repo needs to
   support (7.4.x and 7.6.x have already diverged once, for
   `get_install_preview()`'s `preview/result` task-ID lookup order).
4. Only then implement `FMGClient.get_device_last_revision(adom, device)`,
   the daily fleet-wide job (mirroring `app/pending_status_cache.py`'s
   10-worker `ThreadPoolExecutor` batching discipline), and the
   `"device_backup"` executive-summary key:
   `{devices_backup_ok, devices_backup_stale_7d, devices_backup_never,
   collected_at}`.

## Status

Not implemented. `"device_backup"` is absent from the executive summary
payload entirely (no fabricated or always-null key) until the above is
confirmed. Part 1 (hardware EOS / `"lifecycle"`) shipped independently in
this same change and does not depend on this spike.
