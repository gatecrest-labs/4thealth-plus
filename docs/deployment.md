# Production Deployment Guide

Linux Server + Nginx + Gunicorn

This guide walks through deploying 4THealth+ on RHEL/Rocky/AlmaLinux or Ubuntu/Debian.

- Gunicorn as the WSGI application server
- Nginx as the TLS-terminating reverse proxy
- Systemd service management

Estimated total time: 1–2 hours for a first deployment.

For authentication setup (AD/LDAP or RADIUS), see [authentication.md](authentication.md).
For hardening and security configuration, see [hardening.md](hardening.md).
For monitoring and CI/CD, see [operations.md](operations.md).
For Docker/Compose deployment, see [../container.md](../container.md).

---

## Phase 1 — Linux Server Prerequisites

Goal: A clean server with the right OS packages, a dedicated service account, and firewall rules allowing HTTPS.

### 1.1 Supported OS

Tested on:

- Rocky Linux 9 / AlmaLinux 9 / RHEL 9
- Ubuntu 22.04 LTS / 24.04 LTS
- Debian 12

Minimum specs: 2 vCPU, 2 GB RAM, 20 GB disk.

### 1.2 OS Package Installation

```bash
# RHEL / Rocky / AlmaLinux
sudo dnf install -y git curl openssl nginx python3 python3-pip \
    gcc python3-devel openldap-devel cyrus-sasl-devel

# Ubuntu / Debian
sudo apt-get update
sudo apt-get install -y git curl openssl nginx python3 python3-pip \
    build-essential python3-dev libldap2-dev libsasl2-dev libssl-dev
```

### 1.3 Install uv (Python package manager)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh

uv --version 2>/dev/null || export PATH="$HOME/.local/bin:$PATH"
uv --version
```

Copy `uv` system-wide so it is available when running commands as other users:

```bash
sudo cp ~/.local/bin/uv /usr/local/bin/uv
sudo cp ~/.local/bin/uvx /usr/local/bin/uvx
sudo chmod 755 /usr/local/bin/uv /usr/local/bin/uvx
```

### 1.4 Create a Dedicated Service Account

```bash
sudo useradd --system --shell /sbin/nologin --home /opt/4thealth \
    --create-home 4thealth

# Give your admin user sudo-free read access to the app directory
sudo usermod -aG 4thealth $USER
```

### 1.5 Firewall Rules

First check which firewall is active on your server:

```bash
sudo systemctl status firewalld
sudo systemctl status ufw 2>/dev/null
sudo iptables -L INPUT --line-numbers 2>/dev/null | head -5
```

If `iptables` INPUT policy is `ACCEPT` with no rules, there is no host-based firewall — skip this section and rely on network-level controls.

```bash
# RHEL / Rocky / AlmaLinux with firewalld active
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --reload

# Ubuntu (ufw)
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp
sudo ufw reload

# Verify the app can reach FortiManager (outbound HTTPS on port 443)
curl -k https://<your-fortimanager-ip>/jsonrpc --max-time 5
```

---

## Phase 2 — Application Deployment

Goal: Deploy the application code, configure the environment, generate SSL credentials, add a production user, and verify the app starts.

### 2.1 Clone or Copy the Repository

> `useradd --create-home` in Phase 1.4 already created `/opt/4thealth`. Do **not** run `mkdir` again — clone directly into that directory.

```bash
# Option A - git clone as your own user, then fix ownership (recommended)
sudo rm -rf /opt/4thealth
git clone <your-repo-url> /tmp/4thealth
sudo mv /tmp/4thealth /opt/4thealth
sudo chown -R 4thealth:4thealth /opt/4thealth

# Option B - git clone over HTTPS with a personal access token
sudo rm -rf /opt/4thealth
git clone https://<username>:<PAT>@github.com/<org>/<repo>.git /tmp/4thealth
sudo mv /tmp/4thealth /opt/4thealth
sudo chown -R 4thealth:4thealth /opt/4thealth

# Option C - copy from dev machine
rsync -avz --exclude '.venv' --exclude '__pycache__' --exclude 'certs' \
    /path/to/4thealth/ user@server:/opt/4thealth/
sudo chown -R 4thealth:4thealth /opt/4thealth
```

### 2.2 Install Python Dependencies

```bash
sudo -u 4thealth /usr/local/bin/uv sync --extra prod --project /opt/4thealth
```

> Always pass `--project /opt/4thealth` and the full path `/usr/local/bin/uv` — the `4thealth` home directory is mode `750` and cannot be entered by your own account.

### 2.3 Configure Environment Variables

```bash
sudo -u 4thealth cp /opt/4thealth/.env.example /opt/4thealth/.env
sudo chmod 640 /opt/4thealth/.env
sudo chown 4thealth:4thealth /opt/4thealth/.env
sudo -u 4thealth nano /opt/4thealth/.env
```

Minimum required changes in `.env`:

```dotenv
SECRET_KEY=<generate below>
FMG_PRIMARY_HOST=<FortiManager primary IP>
FMG_API_TOKEN=<bearer token from FortiManager>
COOKIE_SECURE=true
PORT=8100
```

### 2.3a Configure Infrastructure Dashboard Targets

```bash
sudo -u 4thealth cp /opt/4thealth/infra_targets.example.json /opt/4thealth/infra_targets.json
sudo chmod 640 /opt/4thealth/infra_targets.json
sudo chown 4thealth:4thealth /opt/4thealth/infra_targets.json
sudo -u 4thealth nano /opt/4thealth/infra_targets.json
```

Generate a strong `SECRET_KEY`:

```bash
sudo -u 4thealth /usr/local/bin/uv run --project /opt/4thealth python /opt/4thealth/manage_users.py secret
```

### 2.4 Generate a TLS Certificate

**Option A — Self-signed (internal/lab use):**

```bash
sudo mkdir -p /opt/4thealth/certs
sudo openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout /opt/4thealth/certs/key.pem \
  -out /opt/4thealth/certs/cert.pem \
  -days 3650 \
  -subj "/CN=4thealth.yourdomain.com" \
  -addext "subjectAltName=DNS:4thealth.yourdomain.com,IP:<server-ip>"
sudo chown -R 4thealth:4thealth /opt/4thealth/certs
sudo chmod 600 /opt/4thealth/certs/key.pem
```

**Option B — Internal CA / corporate cert:**

- Place cert at `/opt/4thealth/certs/cert.pem`
- Place key at `/opt/4thealth/certs/key.pem`
- Or update `SSL_CERT` / `SSL_KEY` in `.env`

**Option C — Let's Encrypt (public DNS only):**

```bash
sudo dnf install -y certbot python3-certbot-nginx
# or
sudo apt-get install -y certbot python3-certbot-nginx

sudo certbot --nginx -d 4thealth.yourdomain.com
```

### 2.5 Create Initial User Accounts

```bash
sudo -u 4thealth /usr/local/bin/uv run --project /opt/4thealth python /opt/4thealth/manage_users.py add admin --role admin
sudo -u 4thealth /usr/local/bin/uv run --project /opt/4thealth python /opt/4thealth/manage_users.py add readonly --role viewer
```

Keep at least one local admin account in `users.json` for emergency access, even if AD/RADIUS authentication is enabled.

### 2.6 Create the Systemd Service

Create `/etc/systemd/system/4thealth.service`:

```ini
[Unit]
Description=4THealth Dashboard
After=network.target

[Service]
Type=simple
User=4thealth
Group=4thealth
WorkingDirectory=/opt/4thealth
EnvironmentFile=/opt/4thealth/.env
Environment=TZ=America/Chicago
ExecStart=/opt/4thealth/.venv/bin/gunicorn \
    --workers 2 \
    --threads 4 \
    --worker-class gthread \
    --bind 127.0.0.1:8100 \
    --timeout 130 \
    --access-logfile /var/log/4thealth/access.log \
    --error-logfile /var/log/4thealth/error.log \
    wsgi:app
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

> **Worker class:** The `gthread` worker class is required. The default `sync` worker forks child processes — background threads (summary job, map cache, ADOM cache) do not transfer to forked workers. Use `--workers 2 --threads 4 --worker-class gthread`; increase `--threads` for more concurrency rather than `--workers`.
>
> **Timezone note:** `Environment=TZ=America/Chicago` is required on RHEL/Rocky systems where `/etc/localtime` reports a conflicting timezone name. Set to the canonical IANA name for your server's timezone (verify with `timedatectl`).
>
> **Timeout:** `--timeout 130` matches the FMG client's worst-case paginated request ceiling (120 s) plus a 10 s buffer. Nginx's `proxy_read_timeout 140s` sits 10 s above Gunicorn so Nginx never cuts the upstream connection before Gunicorn returns a proper error.

Then run:

```bash
sudo mkdir -p /var/log/4thealth
sudo chown 4thealth:4thealth /var/log/4thealth

sudo systemctl daemon-reload
sudo systemctl enable 4thealth
sudo systemctl start 4thealth
sudo systemctl status 4thealth

# Tail logs
sudo journalctl -u 4thealth -f
```

> **Background scheduler placement:** The web unit above does not set
> `RUN_SCHEDULERS`, so it defaults to `off` — this web process starts no
> background jobs (executive summary sweep, device review, rule hygiene,
> PSIRT re-assessment, change control, infra health, backups, etc.). Those
> now run in a separate `python -m app.collector` process so the executive
> summary and every other cache it reads stay consistent across Gunicorn's
> worker processes and survive a web restart (see
> `~/Documents/4thealth-notes/scale-review-1000-devices.md` section C1, and
> `container.md`'s Docker Compose `web`/`collector` split, which this
> systemd approach mirrors). Create a parallel unit,
> `/etc/systemd/system/4thealth-collector.service`:
>
> ```ini
> [Unit]
> Description=4THealth Dashboard — Collector
> After=network.target
>
> [Service]
> Type=simple
> User=4thealth
> Group=4thealth
> WorkingDirectory=/opt/4thealth
> EnvironmentFile=/opt/4thealth/.env
> Environment=TZ=America/Chicago
> Environment=RUN_SCHEDULERS=inline
> ExecStart=/opt/4thealth/.venv/bin/python -m app.collector
> Restart=on-failure
> RestartSec=5
>
> [Install]
> WantedBy=multi-user.target
> ```
>
> ```bash
> sudo systemctl daemon-reload
> sudo systemctl enable 4thealth-collector
> sudo systemctl start 4thealth-collector
> sudo journalctl -u 4thealth-collector -f
> ```
>
> **The `Environment=RUN_SCHEDULERS=inline` line above is required — do not
> rely on `app/collector.py` to set it for you.** `app/collector.py` does
> set `os.environ["RUN_SCHEDULERS"] = "inline"` at its own top, but that
> line runs too late to matter: `python -m app.collector` imports the
> parent `app` package first (executing `app/__init__.py`, which reads
> `RUN_SCHEDULERS` from the environment at that moment) *before*
> `collector.py`'s own code ever runs. Without the `Environment=` line
> here, `Config.RUN_SCHEDULERS` is permanently baked in as `"off"` and the
> collector unit runs with zero background jobs — no error, no crash, just
> a process that sits idle forever while looking healthy in `systemctl
> status`. Verify a running unit is actually scheduling anything with
> `systemctl status 4thealth-collector` (thread count) or by checking that
> `host_metrics.db` / `login_events.db` timestamps keep advancing.
>
> **Single-process (no separate collector unit):** for a small bare-metal
> deployment that doesn't want a second systemd unit, set
> `RUN_SCHEDULERS=inline` in `/opt/4thealth/.env` and skip the collector
> unit entirely — the one web process then runs every scheduler itself, as
> it always did before this split (the old single-process behaviour).

### 2.7 Smoke Test (before Nginx)

```bash
curl -sk http://127.0.0.1:8100/login | grep -i 4thealth
```

---

## Phase 3 — Nginx Reverse Proxy + TLS Termination

Goal: Nginx handles TLS on port 443, proxies requests to Gunicorn on `127.0.0.1:8100`, and redirects port 80 to 443.

### 3.1 Nginx Configuration

Create `/etc/nginx/conf.d/4thealth.conf`:

```nginx
# HTTP -> HTTPS redirect
server {
    listen 80;
    server_name 4thealth.yourdomain.com;
    return 301 https://$host$request_uri;
}

# HTTPS reverse proxy
server {
    listen 443 ssl http2;
    server_name 4thealth.yourdomain.com;

    ssl_certificate     /opt/4thealth/certs/cert.pem;
    ssl_certificate_key /opt/4thealth/certs/key.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;

    location / {
        proxy_pass         http://127.0.0.1:8100;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_read_timeout 140s;
        proxy_connect_timeout 10s;
    }

    location /static/ {
        alias /opt/4thealth/app/static/;
        expires 1h;
        add_header Cache-Control "public, immutable";
    }

    location ~ /\.(env|git)      { deny all; return 404; }
    location /users.json          { deny all; return 404; }
    location /infra_targets.json  { deny all; return 404; }
    location /policy_db.json      { deny all; return 404; }
    location /app_settings.json   { deny all; return 404; }
    location /api_tokens.json     { deny all; return 404; }
}
```

```bash
# Allow nginx to read the app's static files
sudo usermod -aG 4thealth nginx
sudo nginx -t
sudo systemctl enable nginx
sudo systemctl restart nginx
```

### 3.2 SELinux (RHEL/Rocky only)

```bash
sudo setsebool -P httpd_can_network_connect 1
sudo restorecon -Rv /opt/4thealth/certs/
```

### 3.3 Verify End-to-End

```bash
curl -sk https://4thealth.yourdomain.com/login | grep -i 4thealth

openssl s_client -connect 4thealth.yourdomain.com:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -dates
```

---

## Updating an Existing Installation

```bash
cd /opt/4thealth
sudo -u 4thealth git pull origin main
```

**Run `uv sync` only if `pyproject.toml` changed** (check `git diff HEAD~1 pyproject.toml`):

```bash
sudo -u 4thealth /usr/local/bin/uv sync --extra prod --project /opt/4thealth
```

**Copy any new example config files** (first time a new gitignored config is introduced):

```bash
# Only needed once per new file — skip if the file already exists
[ -f smtp_config.json ]        || cp smtp_config.example.json smtp_config.json
[ -f config_diff_jobs.json ]   || cp config_diff_jobs.example.json config_diff_jobs.json
```

**Restart the service** (always required to load new Python modules and scheduler changes):

```bash
sudo systemctl restart 4thealth
sudo systemctl status 4thealth
```

### What requires `uv sync`?

| Change | Needs `uv sync`? | Needs restart? |
|--------|-----------------|----------------|
| Python file changes | No | Yes |
| New/changed `pyproject.toml` dependency | Yes | Yes |
| Template or JS/CSS changes | No | No (served directly) |
| New gitignored config file (`.example.json`) | No | No (copy manually, configure via UI) |
