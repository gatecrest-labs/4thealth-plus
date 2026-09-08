# Configuration Reference

## Environment Variables (`.env`)

Copy `.env.example` to `.env` and fill in your values. The file is gitignored — never commit credentials.

### Core

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | *(required)* | Flask session signing key — generate with `manage_users.py secret` |
| `COOKIE_SECURE` | `auto` | `true` for HTTPS, `false` for HTTP, `auto` detects cert presence |
| `PORT` | `5000` / `5443` | Listening port (auto-selects 5443 when cert files are present) |
| `SSL_CERT` | `certs/cert.pem` | Path to TLS certificate |
| `SSL_KEY` | `certs/key.pem` | Path to TLS private key |

### FortiManager

| Variable | Default | Description |
|---|---|---|
| `FMG_PRIMARY_HOST` | *(required)* | FortiManager IP or hostname — used for all ADOM, device, and policy queries |
| `FMG_API_TOKEN` | — | Bearer token (preferred) — generate in FMG under System Settings → Administrators |
| `FMG_USERNAME` | — | API account username (fallback when no token is set) |
| `FMG_PASSWORD` | — | API account password (fallback) |
| `FMG_VERIFY_SSL` | `false` | Set `true` to validate the FortiManager TLS certificate |
| `FMG_TIMEOUT` | `30` | API request timeout in seconds |
| `FMG_SUPPRESS_INSECURE_WARNING` | `true` | Set `false` to show urllib3 SSL warnings when `FMG_VERIFY_SSL=false` |

### Health Thresholds

| Variable | Default | Description |
|---|---|---|
| `CPU_WARN` / `CPU_CRIT` | `70` / `90` | CPU % thresholds for yellow / red |
| `MEM_WARN` / `MEM_CRIT` | `75` / `90` | Memory % thresholds for yellow / red |

### Background Jobs

| Variable | Default | Description |
|---|---|---|
| `SUMMARY_REFRESH_HOUR` | `1` | Hour (0–23, server local time) the nightly summary recalculation fires |
| `SUMMARY_REFRESH_MINUTE` | `0` | Minute within that hour (default: 01:00) |
| `MAP_CACHE_INTERVAL_HOURS` | `24` | How often to re-fetch device lat/lon from FortiManager |
| `VERSIONS_CACHE_INTERVAL_MIN` | `30` | How often (in minutes) the Device Versions cache is refreshed |

### RADIUS Authentication (optional)

| Variable | Default | Description |
|---|---|---|
| `RADIUS_ENABLED` | `false` | Set `true` to enable RADIUS authentication |
| `RADIUS_HOST` | — | Primary FAC IP or hostname |
| `RADIUS_PORT` | `1812` | Primary FAC UDP port |
| `RADIUS_HOST_2` | — | Secondary FAC IP or hostname (HA failover — leave blank if unused) |
| `RADIUS_PORT_2` | `1812` | Secondary FAC UDP port |
| `RADIUS_SECRET` | — | Shared secret (same on both FACs) |
| `RADIUS_AUTH_METHOD` | `pap` | `pap` or `chap` — must match FAC client config |
| `RADIUS_TIMEOUT` | `10` | Per-server request timeout in seconds |
| `RADIUS_GROUP_ADMIN` | — | `Filter-Id` / `Class` value that maps to the `admin` role |
| `RADIUS_GROUP_VIEWER` | — | `Filter-Id` / `Class` value that maps to the `viewer` role |

### Active Directory / LDAP (optional)

| Variable | Default | Description |
|---|---|---|
| `AD_ENABLED` | `false` | Set `true` to enable AD/LDAP authentication |
| `AD_SERVER` | — | LDAP server URL, preferably `ldaps://...:636` |
| `AD_DOMAIN` | — | NetBIOS domain |
| `AD_BASE_DN` | — | Directory base DN |
| `AD_BIND_USER` | — | Full DN of service account |
| `AD_BIND_PASSWORD` | — | Service account password |
| `AD_USER_SEARCH` | — | User search OU |
| `AD_GROUP_ADMIN` | — | Full DN of admin group |
| `AD_GROUP_VIEWER` | — | Full DN of viewer group |
| `AD_VERIFY_SSL` | `false` | Validate DC TLS certificate |

### AI Assist (optional)

Powers Rule Validation's AI Assist, Audit Review's AI Summary/AI Explain/PSIRT extraction, Config-Delta's AI Summary, and the Admin AI Trend Summary. All are also gated by the `ai_assist_enabled` setting in **Admin → AI Assist** — these variables select and configure the LLM provider, they don't enable the features by themselves.

| Variable | Default | Description |
|---|---|---|
| `AI_PROVIDER` | `claude` | `claude`, `codex`, or `ollama` |
| `ANTHROPIC_API_KEY` | — | Required when `AI_PROVIDER=claude` |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-5` | Claude model name |
| `OPENAI_API_KEY` | — | Required when `AI_PROVIDER=codex` |
| `OPENAI_MODEL` | `gpt-5` | Codex/OpenAI model name |
| `OLLAMA_HOST` | — | Ollama server URL (local or cloud), required when `AI_PROVIDER=ollama` |
| `OLLAMA_MODEL` | `llama3.1` | Ollama model name |
| `OLLAMA_API_KEY` | — | Optional — set when the Ollama host requires a bearer token |

---

## Infrastructure Dashboard Targets (`infra_targets.json`)

Health cards on the Dashboard are driven by `infra_targets.json` (gitignored — copy from `infra_targets.example.json`). Each entry is a JSON object:

```json
{ "label": "Display Name", "host": "10.0.0.1", "type": "FortiManager" }
```

Valid `type` values: `FortiManager`, `FortiAnalyzer`, `FortiCollector`, `FortiAuthenticator` — or any string you choose for the badge label.

### Per-device bearer tokens

Each Fortinet appliance type generates its own API token independently. Use an optional `"token"` field per entry:

```json
[
  { "label": "FortiManager Primary",  "host": "10.0.0.1", "type": "FortiManager",  "token": "fmg-token" },
  { "label": "FortiAnalyzer Primary", "host": "10.0.0.3", "type": "FortiAnalyzer", "token": "faz-token" }
]
```

Token priority (first match wins): per-entry `"token"` → `FMG_API_TOKEN` → `FMG_USERNAME`/`FMG_PASSWORD`.

To add a device, append an entry and restart the app.

---

## Runtime Data Files

These files are gitignored and must be created from the bundled `*.example.*` templates before running the app.

| File | Source | Purpose |
|---|---|---|
| `.env` | `.env.example` | Environment variables and credentials |
| `groups.json` | `groups.example.json` | Group definitions, tab and ADOM permissions |
| `infra_targets.json` | `infra_targets.example.json` | Infrastructure dashboard device list |
| `users.json` | Created by `manage_users.py` | Local user accounts (bcrypt-hashed passwords) |
| `policy_db.json` | `policy_db.example.json` | Zone policy database (Zone Policy tab) |
| `app_settings.json` | `app_settings.example.json` | Feature flags (e.g. `external_api_enabled`) |
| `api_tokens.json` | `api_tokens.example.json` | External API bearer token hashes |
| `map_regions.json` | Built-in defaults | Map pin colour regions; created on first admin save |
| `smtp_config.json` | `smtp_config.example.json` | SMTP configuration for scheduled exports |
| `config_diff_jobs.json` | `config_diff_jobs.example.json` | Scheduled Config-Delta export jobs |
| `device_review_jobs.json` | `device_review_jobs.example.json` | Scheduled Audit Review (CIS audit) export jobs |
| `naming.yaml` | `naming.example.yaml` | Rule-naming standards used by Rule Validation's AI Assist |
| `review_requirements.yaml` | `review_requirements.example.yaml` | Approval/risk-review standards used by Rule Validation's AI Assist |
| `protocol_severity.json` | `protocol_severity.example.json` | Optional overrides for Audit Review's protocol security classification |
| `backup_config.json` | `backup_config.example.json` | Backup schedule and remote-transfer settings |
| `ai_usage.db` | Created automatically | SQLite — AI Assist call/cost history |
| `host_metrics.db` | Created automatically | SQLite — host CPU/mem/disk sample history |
| `summary_history.json` | Created automatically | Managed Network Summary history |

---

## SMTP / Scheduled Exports

SMTP settings are stored in `smtp_config.json` (gitignored; copy from `smtp_config.example.json`). All fields are configurable via **Admin → Config-Diff**.

| Field | Default | Description |
|-------|---------|-------------|
| `host` | `""` | SMTP server hostname or IP |
| `port` | `25` | SMTP port |
| `tls_mode` | `"none"` | `"none"`, `"starttls"`, or `"ssl"` |
| `username` | `""` | Optional — leave blank for unauthenticated relay |
| `password` | `""` | Optional — leave blank for unauthenticated relay |
| `from_address` | `""` | Optional sender address |
| `run_history_days` | `30` | Days of per-job run history to retain |
| `enabled` | `false` | Must be `true` for any scheduled export to send email |

Scheduled jobs are stored in `config_diff_jobs.json` (gitignored; copy from `config_diff_jobs.example.json`). Jobs are registered with APScheduler at startup and survive server restarts.
