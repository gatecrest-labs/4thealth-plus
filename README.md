<picture>
  <source media="(prefers-color-scheme: dark)" srcset="logo-dark.svg">
  <img alt="4tHealth+ logo" src="logo.svg" width="240">
</picture>

# 4THealth+ — Network Operations Dashboard

A read-only web dashboard for monitoring FortiManager, FortiAnalyzer, FortiAuthenticator,
and managed FortiGate firewalls. All FortiGate data flows **through FortiManager's
JSON-RPC API** — no direct device connections are made.

4THealth+ is a fork and successor of 4THealth, rebuilt as the foundation for adding
AI-assisted change analysis to the Rule Validation tab (see Roadmap below).

> **Note**: This is an independent open-source project and is not affiliated with, endorsed by, or supported by Fortinet, Inc. FortiManager is a trademark of Fortinet, Inc.

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![FortiManager](https://img.shields.io/badge/FortiManager-7.4.x%20%7C%207.6.x-red)

---

## Requirements & Compatibility

| Requirement | Version |
|---|---|
| Python | 3.11 or later |
| FortiManager | **7.4.x** or **7.6.x** (tested) |
| Browser | Any modern browser (Chrome, Firefox, Edge, Safari) |
| Docker (optional) | 20.10+ with Compose v2 |

---

## Features

| Page | What it shows |
|---|---|
| **Dashboard** | Infrastructure health cards for all devices in `infra_targets.json` — hostname, version, serial, HA mode/role, CPU %, memory %, disk |
| **Managed Network Summary** | Stat bar — total managed firewalls and total policy rules, calculated nightly by a background job |
| **Firewalls** | Per-ADOM device list with health indicator, paginated table, full-text search |
| **Device Detail** | Modal pop-up — system info, CPU/memory, interfaces, routing table, BGP/OSPF neighbors, IPsec tunnels |
| **Device Versions** | Per-ADOM version distribution chart — clickable bars filter the device list; CSV and JSON export |
| **Rule Review** | Policy viewer (full rule table with search, pagination, group expansion, export) plus nine automated hygiene checks — with a comment-based "Exempt" whitelist to permanently silence a reviewed rule |
| **Device Review** | Management-interface security audit — checks for cleartext protocols, missing secure alternatives; export as CSV, JSON, or PDF |
| **Rule Validation** | Pre-change analysis — enter requested flows, select policy packages, get per-flow verdicts; integrates zone segmentation policy checks; optional single-request **AI Assist** mode |
| **Zone Policy** | Self-contained network segmentation policy browser — query flows, browse zones and rules, validate schema, edit database (admin only) |
| **Map** | Interactive geographic map of all managed FortiGate devices, coloured by configurable US geographic region |
| **Config-Delta** | Per-device install-pending diff viewer — shows exactly which FortiOS CLI lines will change on the next install; export queue for CSV, JSON, or PDF change records |
| **Backup** | AES-256 encrypted ZIP backups of all runtime config; one-time browser download or scheduled with FTP/SFTP remote transfer |
| **Admin** | *(admin only)* Group management, tab-level and ADOM-level permissions, map region configuration, log viewer, External API management, Backup configuration |
| **Auto-refresh** | Configurable: manual, 1 min, 5 min (default), 10 min, 15 min |
| **Light / Dark mode** | Toggle in the nav bar; preference saved in `localStorage` |

---

## AI Assist

Every AI feature in the app is gated by one `ai_assist_enabled` flag (**Admin → AI Assist**), off by default, and multi-provider — Claude (default), Codex, and Ollama (local or cloud), configured server-wide via `.env`. In every case the LLM only narrates an already-computed result; it never determines a verdict, a check outcome, or a trend itself:

- **Rule Validation → AI Assist** — three modes: **Single Change** (describe one change, get a deterministic verdict from the ported change-planning engine plus an AI-written report and peer-review package), **FQDN Allowlist** (bulk vendor FQDN/wildcard allowlist requests), and **Hygiene Fix** (turns a completed Rule Hygiene run's findings into deterministic FortiOS CLI remediations, grouped by rule, with a peer-reviewable HTML report). The existing bulk CSV/XLSX table workflow is unchanged and does not use the LLM.
- **Device Review → AI Summary** — plain-English summary of a CIS check run, on-demand or in scheduled reports.
- **Config-Delta → AI Summary** — plain-English description of an install-preview diff, on-demand or in scheduled exports.
- **Rule Hygiene → AI Explain** — per-finding explanation plus a suggested remediation snippet.
- **Admin → AI Trend Summary** — narrated 7-day host-resource trend statistics.

See [docs/features.md](docs/features.md) for details on each, and [docs/configuration.md](docs/configuration.md#ai-assist-optional) for the provider environment variables.

## Roadmap

Deferred to a future phase: FortiManager read-only query tools, feedback/audit
history, `.xlsx` intake parsing, and per-request provider selection.

---

## Architecture

```
4thealth/
├── app/
│   ├── __init__.py              Flask application factory; registers blueprints, starts schedulers
│   ├── config.py                Settings loaded from .env
│   ├── auth.py                  Local bcrypt auth + optional RADIUS/AD authentication
│   ├── app_logger.py            In-memory ring-buffer logger (TRACE/DEBUG/INFO/WARN/ERROR)
│   ├── decorators.py            login_required, tab_required, admin_required, check_adom_access
│   ├── registry.py              Tab key registry; maps keys to display names and routes
│   ├── groups.py                Group CRUD, tab-permission checks, ADOM access control
│   ├── fmg_client.py            FortiManager JSON-RPC client (context-manager; auto login/logout)
│   ├── fmg_helpers.py           FMGClient factory / session helper
│   ├── hygiene.py               Rule hygiene check engine (9 checks + Exempt whitelist, read-only)
│   ├── device_review.py         Device Review check engine; add new checks here
│   ├── rule_review.py           Rule Validation — flow/policy matching, path analysis, zone integration
│   ├── zone_db.py               Zone policy DB engine — loads policy_db.json, runs queries, CRUD
│   ├── map_regions.py           Map region config — load/save map_regions.json, state validation
│   ├── map_cache.py             Background cache: device lat/lon for all ADOMs, refreshed daily
│   ├── versions_cache.py        Background cache: per-ADOM device version data
│   ├── adom_cache.py            Background cache: ADOM list from FortiManager, refreshed every 30 min
│   ├── pending_status_cache.py  Background cache: pending-changes device sync status
│   ├── infra_health_cache.py    SNMPv3 background poller for infrastructure CPU/memory health
│   ├── summary_job.py           Background job: managed firewall + rule counts, nightly APScheduler
│   ├── summary_history.py       Summary history persistence
│   ├── config_diff_scheduler.py APScheduler — Config-Delta scheduled exports
│   ├── device_review_scheduler.py APScheduler — Device Review CIS audit scheduled exports
│   ├── smtp_client.py           SMTP delivery for scheduled export emails
│   ├── atomic_io.py             Atomic JSON write helper
│   ├── security.py              API error response helpers
│   ├── radius_auth.py           RADIUS/AD authentication backend
│   ├── app_settings.py          Feature-flag settings backed by app_settings.json
│   ├── api_tokens.py            Bearer token CRUD for the External API
│   └── routes/
│       ├── auth_routes.py            /login  /logout
│       ├── dashboard_routes.py       /  /firewalls  /versions
│       ├── api_routes.py             /api/*  (JSON data endpoints)
│       ├── admin_routes.py           /admin  /admin/api/*  (admin only)
│       ├── hygiene_routes.py         /hygiene  /api/hygiene/*
│       ├── device_review_routes.py   /device-review  /api/device-review/*
│       ├── rule_review_routes.py     /rule-review  /api/rule-review/*
│       ├── zone_routes.py            /zone-policy  /api/zone/*
│       ├── map_routes.py             /map  /api/map/*
│       ├── pending_changes_routes.py /pending-changes  /api/pending-changes/*
│       └── external_api_routes.py    /external/api/*  (bearer-token, no session required)
├── wsgi.py                      WSGI entry point; wires SSL context for Gunicorn
├── manage_users.py              CLI: add / delete / list users / generate SECRET_KEY
├── pyproject.toml               Project metadata and dependencies (uv)
├── .env.example                 Template — copy to .env and fill in values
├── Dockerfile                   Container image definition
├── docker-compose.yml           Single-container stack with bind-mounted runtime data
└── docs/                        Extended documentation (see Documentation section below)
```

---

## Quick Start (macOS / local development)

[uv](https://docs.astral.sh/uv/) is the recommended dependency manager. Install once:

```bash
brew install uv
```

Then from the project root:

```bash
# 1. Install all dependencies into an isolated .venv
uv sync

# 2. Copy and configure the environment file
cp .env.example .env
# Edit .env: set SECRET_KEY, FMG_PRIMARY_HOST, and FMG_API_TOKEN

# 3. Copy and configure the group definitions
cp groups.example.json groups.json

# 4. Copy and configure the infrastructure dashboard targets
cp infra_targets.example.json infra_targets.json

# 5. Generate a strong SECRET_KEY
uv run python manage_users.py secret
# Paste the output into .env as SECRET_KEY=...

# 6. Create the first local admin account
uv run python manage_users.py add admin --role admin

# 7. Start the development server
uv run python wsgi.py
# Browse to http://localhost:5000
```

### Optional: HTTPS locally

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout certs/key.pem -out certs/cert.pem \
  -days 3650 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

uv run python wsgi.py
# Listens on https://localhost:5443
```

---

## User Management

```bash
# Add a user (prompts for password)
uv run python manage_users.py add <username> --role admin|viewer

# List all users
uv run python manage_users.py list

# Remove a user
uv run python manage_users.py delete <username>

# Generate a new SECRET_KEY value
uv run python manage_users.py secret
```

Passwords are stored as **bcrypt hashes** in `users.json` (gitignored).

Roles:
- `admin` — full access to all tabs, the Admin page, and debug API endpoints
- `viewer` — access restricted to the tabs their groups permit

> When RADIUS is enabled (`RADIUS_ENABLED=true`), `manage_users.py` accounts serve as emergency local fallback. RADIUS users do not need entries in `users.json`. See [docs/authentication.md](docs/authentication.md).

---

## Groups & Tab Permissions

Groups are managed through **Admin → Groups & Permissions**.
Definitions are stored in `groups.json` (gitignored — copy from `groups.example.json`).

1. An admin creates a group (e.g. `NOC-Team`).
2. The admin selects which **navigation tabs** the group can see.
3. Optionally, the admin restricts the group to specific **ADOMs**.
4. The admin adds members via individual local accounts or **AD / RADIUS Groups** (e.g. `4THealth-NOC`). Any RADIUS user whose `Filter-Id` or `Class` reply attribute matches is automatically treated as a member at login.
5. On next login, each member's session reflects the union of allowed tabs across all groups they belong to.

**Admins always have full access** regardless of group membership.

When a user belongs to multiple groups and at least one is unrestricted, that user has full ADOM access.

### Registering a new tab

```python
# app/registry.py
registry.register("my_new_tab", "My New Tab", "blueprint.view_function")
```

Protect the route with `@tab_required("my_new_tab")`. The new key appears immediately in the Admin group-editor checklist.

---

## Security Notes

- All FortiManager calls are **read-only** — only `get` and proxy `monitor` operations are used.
- Passwords are **bcrypt-hashed**; `users.json` is gitignored.
- The `.env` file is gitignored — never commit credentials.
- Open-redirect protection is enforced on the login `?next=` parameter.
- `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE=Lax`, and automatic `SESSION_COOKIE_SECURE` (when TLS is active) are all set.
- All `/admin/*` routes enforce the `admin` role server-side.

---

## Automated Monitoring (Ansible / AAP)

The [Ansible/](Ansible/) directory contains a playbook that runs a full health check against the production server and emails a formatted HTML report to your team.

| Check | Failure condition |
|---|---|
| **Systemd services** | `4thealth.service` or `nginx.service` not active |
| **Port listeners** | Gunicorn not on `127.0.0.1:8100`, Nginx not on `:443` |
| **HTTP reachability** | `/login` returns non-2xx/3xx |
| **TLS certificate expiry** | < 30 days remaining (warning) / < 7 days (critical) |
| **Disk space** | > 80% used (warning) / > 90% (critical) |
| **Application error logs** | 1–10 journald errors in last 60 min (warning) / > 10 (critical) |
| **API availability** | `/api/summary` returns no HTTP response |

```
Ansible/
├── 4thealth_healthcheck.yml          Main playbook
├── inventory.example.yml             Inventory reference
├── group_vars/
│   └── 4thealth_prod.yml             Default variable values
└── templates/
    └── healthcheck_email.html.j2     HTML email report template
```

---

## Documentation

| Document | Contents |
|---|---|
| [docs/configuration.md](docs/configuration.md) | All environment variables, `infra_targets.json` format, runtime data files |
| [docs/features.md](docs/features.md) | Per-tab deep-dives: Rule Review, Device Review, Rule Validation, Zone Policy, Map, External API, logging, extending the app |
| [docs/api-reference.md](docs/api-reference.md) | Complete API endpoint reference |
| [docs/deployment.md](docs/deployment.md) | Linux production deployment: OS setup, Gunicorn, Nginx, systemd (Phases 1–3) |
| [docs/authentication.md](docs/authentication.md) | RBAC, AD/LDAP setup, RADIUS/FortiAuthenticator setup, AD migration guide |
| [docs/hardening.md](docs/hardening.md) | File permissions, fail2ban, Nginx rate limiting, SELinux, master security checklist |
| [docs/operations.md](docs/operations.md) | Monitoring, updates, backup, SSL renewal |
| [container.md](container.md) | Docker and Docker Compose deployment |
| [CHANGELOG.md](CHANGELOG.md) | Version history and release notes |

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

Key points:
- One feature or fix per pull request.
- Run `uv run pytest` and `uv run flake8` before submitting.
- Update the relevant `docs/` file if your change affects user-visible behaviour.
- Never commit credentials, `.env`, or runtime data files.

To report a security vulnerability, follow the process in [SECURITY.md](SECURITY.md).

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.
