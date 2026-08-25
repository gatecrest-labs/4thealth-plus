# Provenance

`app/psirt/` is an adapted port of the `psirt/` package from
`~/code/github/ai/4tanalyst`, following the same fork-not-dependency
pattern documented in `app/planner/VENDORED_FROM.md`.

- Source repo: `~/code/github/ai/4tanalyst`
- Source path: `psirt/`
- Ported from commit: (fill in with `git -C ~/code/github/ai/4tanalyst rev-parse HEAD` at port time)
- Port date: 2026-08-25

## Why a fork, not a dependency

The source's `psirt/workaround_checks.py` and `psirt/engine.py` call
`fortimanager_mcp.query`/`fortimanager_mcp.client` — a separate MCP-server
FortiManager client. This repo's `app/fmg_client.py` is a different,
already-authenticated client used in-process by every other feature. The
port swaps every FMG call site to the equivalent `app/fmg_client.py`
method; `models.py`, `version_match.py`, `scoring.py`, and `enrich.py` have
no FMG dependency and port close to verbatim (enrich.py: `httpx` swapped
for this repo's existing `requests` dependency).

## Syncing future changes

Same workflow as `app/planner/`'s (see the `4tanalyst-sync-workflow`
memory): run
`git -C ~/code/github/ai/4tanalyst log <last-synced-sha>..HEAD --oneline -- psirt/`
to see what changed upstream, review each change, and manually port the
relevant parts — never blindly copy, since the FMG data-access layer has
diverged by design. Update the "Ported from commit" line above after each
sync.
