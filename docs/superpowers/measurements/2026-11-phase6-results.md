# Phase 6 results: job queue (2026-11-11)

Produced by `scripts/verify_job_queue.py` (raw data: `2026-11-phase6-job-queue.json`): 5 ADOMs of a 1,000-device
synthetic fleet, two Device Review jobs per ADOM (live reads, snapshots off, so each does real work), run through the
real runner with `JOB_MAX_RUNNING=2`.

| Measure | Result |
|---|---|
| Jobs run to `done` | 10 of 10, no errors |
| Peak jobs running at once | 2 (the cap) |
| Wall time for all 10 | 9.7 s against the synthetic FMG |
| Largest result (200 devices, all checks) | 1.8 MB as JSON; compresses further in the store |

**FMG calls:** unchanged. This phase moves work off web threads and makes it survive a closed tab; it adds no
FortiManager savings and no new background load (background floor stays 434.5 calls/hour). A job makes exactly the calls
the synchronous endpoint would (zero with snapshots on, one batch of proxy reads per device with Live ticked).

**Not measured:** behaviour against a real FortiManager under the cap, and browser behaviour (reload mid-run resumes the
Device Review job; this was covered by code and a JS syntax check, not driven in a browser).
