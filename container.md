# 4THealth+ — Container Deployment Guide

## Should You Containerize?

**Yes — 4THealth+ is a good candidate for Docker.** The app is a single Python process
with no compiled native dependencies, no GPU, and no OS-level daemons. Containerizing it
gives you:

- A reproducible image that deploys identically on any Linux host with Docker installed
- Simpler dependency isolation (no system Python, no uv on the server)
- Easy rollback (tag images by version, pull the old tag to roll back)
- A natural fit for Docker Compose so you can add services later without touching the host

**What changes:** runtime data files (`policy_db.json`, `users.json`, `.env`,
`infra_targets.json`, `certs/`) are mounted as volumes so they survive container
rebuilds. The app code and Python dependencies are baked into the image.

---

## Should You Add a Database for Zone Policy Data?

**Not yet — but here is when you should.**

The current `policy_db.json` holds 33 zones and 161 policies, totalling ~500 KB. At
this scale a database adds more operational surface (connection strings, migrations,
backups, init scripts) than it removes. The JSON file is already written atomically by
`zone_db.py`, is trivially backed up with `cp`, and loads entirely into memory on each
request in under 5 ms.

**Revisit a database when any of these are true:**

| Signal | Why it matters |
|--------|----------------|
| Policy count exceeds ~2 000 | In-memory load and JSON serialisation become measurable |
| Multiple app instances need to write the database concurrently | JSON file writes are not safe under concurrent writers in separate processes |
| You need audit history (who changed what, when) | A relational DB gives you that for free; JSON does not |
| You want full-text or spatial IP subnet queries | SQLite/Postgres handle these natively |

**If you do add a database**, use a separate container (see [Option B — Two Containers
with SQLite](#option-b--two-containers-with-sqlite) below). Do not bundle a database
process inside the app container — that couples two independent lifecycles and breaks
horizontal scaling later.

---

## Option A — Docker Compose (recommended now)

Two containers, `web` and `collector`, are built from the same image and share the
same data-file volumes (JSON files and the app's SQLite databases). `web` runs
Gunicorn behind Nginx (or directly, if you terminate TLS at a load balancer) and
starts no background schedulers; `collector` runs `python -m app.collector` and
owns every scheduled sweep (executive summary, device review, rule hygiene,
PSIRT re-assessment, change control, infra health, backups, etc.). This split
exists so the executive summary and every other cache it reads stay consistent
across Gunicorn's own worker processes and survive a `web` restart — both
processes read and write through `app/collector_store.py` (SQLite, WAL mode)
instead of relying on a single process's in-memory copy. See
`~/Documents/4thealth-notes/scale-review-1000-devices.md` section C1 for the
full rationale.

A single-process deployment (one process, in-memory schedulers, no `collector`
container) is still available for local development — set `RUN_SCHEDULERS=inline`
and run the app directly rather than via `docker compose`; see Step 3 below.

### Directory layout

```
fortigate-health/
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── .env                    ← volume-mounted (gitignored)
├── users.json              ← volume-mounted
├── groups.json             ← volume-mounted (copy from groups.example.json)
├── infra_targets.json      ← volume-mounted
├── policy_db.json          ← volume-mounted
├── certs/                  ← volume-mounted
├── app/
├── wsgi.py
└── pyproject.toml
```

### Step 1 — Create `.dockerignore`

Create `.dockerignore` in the project root to keep the image lean:

```
.venv/
__pycache__/
*.pyc
*.pyo
certs/
.env
users.json
groups.json
infra_targets.json
policy_db.json
ansible/
*.md
*.html
.git/
.claude/
```

This prevents secrets and runtime data files from being baked into the image layer.

### Step 2 — Create `Dockerfile`

```dockerfile
FROM python:3.12-slim

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency manifests first for better layer caching
COPY pyproject.toml uv.lock ./

# Install production dependencies into the project virtualenv
RUN uv sync --extra prod --no-dev

ENV PATH="/app/.venv/bin:$PATH"

# Copy application source
COPY wsgi.py manage_users.py ./
COPY app/ app/

# Create non-root user matching the service account convention
RUN useradd --system --no-create-home --shell /sbin/nologin appuser \
    && mkdir -p /app/certs \
    && chown -R appuser:appuser /app

ENV HOME=/tmp
USER appuser

EXPOSE 8100

CMD ["gunicorn", \
     "--workers", "2", \
     "--threads", "4", \
     "--worker-class", "gthread", \
     "--bind", "0.0.0.0:8100", \
     "--timeout", "120", \
     "--worker-tmp-dir", "/dev/shm", \
     "--certfile", "certs/cert.pem", \
     "--keyfile", "certs/key.pem", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "wsgi:app"]
```

> **Why `--access-logfile -` and `--error-logfile -`:** In containers, stdout/stderr are
> captured by Docker's logging driver (`docker logs`, `journald`, CloudWatch, etc.).
> Writing to files inside the container is pointless and wastes disk. Log forwarding is
> handled at the Docker level.

> **Why `--certfile`/`--keyfile`:** TLS is terminated inside Gunicorn directly, so no
> Nginx proxy is needed. The cert files are bind-mounted read-only from the host at
> runtime — they are never baked into the image.

### Step 3 — Create `docker-compose.yml`

See the repo's own `docker-compose.yml` for the full, current `web` + `collector`
split with every volume mount. In outline:

```yaml
services:
  web:
    build: .
    image: 4thealth-plus:latest
    container_name: 4thealth-plus-web
    restart: unless-stopped
    command: >
      gunicorn --workers 2 --threads 4 --worker-class gthread
      --bind 0.0.0.0:8100 --timeout 120 --worker-tmp-dir /dev/shm
      --certfile certs/cert.pem --keyfile certs/key.pem
      --access-logfile - --error-logfile - wsgi:app
    ports:
      - "8100:8100"
    env_file:
      - .env
    volumes:
      - ./users.json:/app/users.json:rw
      - ./groups.json:/app/groups.json:rw
      - ./infra_targets.json:/app/infra_targets.json:ro
      - ./policy_db.json:/app/policy_db.json:rw
      - ./collector_state.db:/app/collector_state.db:rw
      - ./certs:/app/certs:ro
      # ...plus every other data file the app reads/writes — see docker-compose.yml
    healthcheck:
      test: ["CMD", "python3", "-c",
             "import urllib.request, ssl; urllib.request.urlopen('https://localhost:8100/login', context=ssl._create_unverified_context(), timeout=5)"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 15s

  collector:
    build: .
    image: 4thealth-plus:latest
    container_name: 4thealth-plus-collector
    restart: unless-stopped
    command: ["python", "-m", "app.collector"]
    env_file:
      - .env
    volumes:
      # Same data-file volumes as `web` (minus the port and healthcheck) —
      # both processes must see the same files.
      - ./users.json:/app/users.json:rw
      - ./collector_state.db:/app/collector_state.db:rw
      # ...see docker-compose.yml for the full list
```

> **Volume mount notes:**
> - `users.json`, `groups.json`, and `policy_db.json` are `:rw` — the app writes to all three (user management, group/permission changes, and zone edits)
> - `infra_targets.json` is `:ro` — it is only read at startup; edit it on the host and restart
> - `certs/` is `:ro` — TLS certificates are never modified by the app
> - `collector_state.db` is the shared SQLite (WAL-mode) store both `web` and `collector` read/write through — mount it on both services
> - `.env` is passed via `env_file` rather than mounted — Docker reads it as environment variables, which is the correct pattern
> - `web`'s `env_file` does not need `RUN_SCHEDULERS` set — it defaults to off/no schedulers. `collector` sets `RUN_SCHEDULERS=inline` on itself internally (inside `app/collector.py`), overriding whatever `.env` says, so no compose-level `environment:` override is needed for either service.

> **Backup directory:** The default backup directory is `/var/backups/4thealth/` inside the container.
> Mount a host directory or named volume here so archives survive container restarts.
> Alternatively, set `backup_dir` in `backup_config.json` to any path that is already mounted.

### Step 4 — Adjust `.env` for the container

Open `.env` and update:

```dotenv
SECRET_KEY=<64-char hex>
FMG_PRIMARY_HOST=<your-fortimanager-ip>
FMG_API_TOKEN=<your token>
FMG_VERIFY_SSL=false

# TLS: point to the mounted cert paths inside the container
SSL_CERT=certs/cert.pem
SSL_KEY=certs/key.pem
COOKIE_SECURE=true

PORT=8100

# Thresholds (optional)
CPU_WARN=70
CPU_CRIT=90
MEM_WARN=75
MEM_CRIT=90

# Nightly summary job
SUMMARY_REFRESH_HOUR=1
SUMMARY_REFRESH_MINUTE=0

# Map (Beta) — how often to re-fetch device lat/lon from FortiManager (default 24 h)
# MAP_CACHE_INTERVAL_HOURS=24
```

### Step 4a — Enable FortiAuthenticator RADIUS (optional)

No rebuild is required — RADIUS is configured entirely through `.env`.

**On FortiAuthenticator:**

1. Go to **Authentication → RADIUS Service → Clients** and add a new client:
   - IP address: this server's IP
   - Secret: a strong shared secret (copy it to `RADIUS_SECRET` in `.env`)
2. Create two user groups, e.g. `4THealth-Admins` and `4THealth-Viewers`.
3. In your RADIUS policy, add a **Reply Attribute**:
   - Attribute: `Filter-Id`
   - Value: the group name (one policy per group, or use a dynamic attribute)

**In `.env`**, uncomment and fill in the RADIUS block:

```dotenv
RADIUS_ENABLED=true
RADIUS_HOST=<fortiauth-ip>
RADIUS_PORT=1812
RADIUS_SECRET=<shared-secret>
RADIUS_TIMEOUT=10
RADIUS_GROUP_ADMIN=4THealth-Admins
RADIUS_GROUP_VIEWER=4THealth-Viewers
```

Then restart the container to pick up the new env vars:

```bash
docker compose up -d
```

**How it works:**
- Login tries RADIUS first. If FortiAuthenticator accepts the credentials and
  returns a `Filter-Id` matching `RADIUS_GROUP_ADMIN`, the user gets admin role;
  matching `RADIUS_GROUP_VIEWER` gets viewer role.
- Local accounts in `users.json` always work regardless of this setting — use
  them as break-glass admin access if RADIUS is unreachable.

**For a Linux (non-Docker) install**, the same `.env` changes apply. Restart
the app with `docker compose up -d` or `systemctl restart 4thealth` as appropriate.

---

### Step 5 — Prepare runtime data files

These files must exist on the **host** before the first `docker compose up`, because
Docker bind-mounts them into the container at startup. If they are missing, Docker
creates them as empty directories — which will cause the app to crash.

```bash
# Verify all four exist
ls -la users.json groups.json infra_targets.json policy_db.json

# If groups.json is missing, start from the example
cp groups.example.json groups.json
# Edit groups.json: rename groups, set tab permissions, add members, configure ADOM access

# If users.json is missing, create the first admin account now
uv run python manage_users.py add admin --role admin

# If infra_targets.json is missing, start from the example
cp infra_targets.example.json infra_targets.json

# If policy_db.json is missing, start from the example
cp policy_db.example.json policy_db.json
# Edit policy_db.json: add your real zones (with subnets) and segmentation policies

# Generate TLS certs if you don't have them already
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout certs/key.pem -out certs/cert.pem \
  -days 3650 \
  -subj "/CN=4thealth.yourdomain.com" \
  -addext "subjectAltName=DNS:4thealth.yourdomain.com"
```

### Step 6 — Build and start

```bash
# Build the image
docker compose build

# Start in background
docker compose up -d

# Tail logs
docker compose logs -f

# Smoke test
curl -sk https://localhost:8100/login | grep -i 4thealth
```

### Step 7 — User management inside a running container

```bash
# Add a user
docker compose exec app python manage_users.py add alice --role viewer

# List users
docker compose exec app python manage_users.py list

# Generate a new SECRET_KEY
docker compose exec app python manage_users.py secret
```

---

## Option B — Two Containers with SQLite

> **Use this when you are ready to migrate zone data out of JSON.**
> This is the natural next step, not a requirement today.

SQLite is the right first database choice for this app:

- Zero additional infrastructure — SQLite is a file, not a server process
- The database file lives in a named Docker volume, surviving container rebuilds
- No connection string, no authentication, no port to open
- Migrations are simple SQL files run at startup
- If you later need concurrent writers or full Postgres features, migrating from SQLite to Postgres is straightforward

This option uses two containers: the app container plus a lightweight init container
that runs database migrations on startup.

### Architecture

```
┌─────────────────────────────┐
│  app container              │
│  Gunicorn + Flask           │
│  reads/writes zone.db       │──── named volume: zone_data
└─────────────────────────────┘          │
                                         │
┌─────────────────────────────┐          │
│  db-init container (exits)  │          │
│  runs migrations at start   │──────────┘
└─────────────────────────────┘
```

### What would need to change in the code

`app/zone_db.py` currently reads and writes `policy_db.json` directly. To use SQLite,
you would replace the `load_db()` / `save_db()` functions with SQLite reads and writes
using Python's built-in `sqlite3` module. The rest of `zone_db.py` (query logic,
validation, CRUD) does not need to change — it works on Python dicts that the I/O
layer provides.

A minimal schema:

```sql
CREATE TABLE IF NOT EXISTS zones (
    name        TEXT PRIMARY KEY,
    domain      TEXT NOT NULL DEFAULT 'Default',
    is_shared   INTEGER NOT NULL DEFAULT 0,
    description TEXT NOT NULL DEFAULT '',
    subnets     TEXT NOT NULL DEFAULT '[]',   -- JSON array
    children    TEXT NOT NULL DEFAULT '[]',   -- JSON array
    parents     TEXT NOT NULL DEFAULT '[]'    -- JSON array
);

CREATE TABLE IF NOT EXISTS policies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_set  TEXT NOT NULL,
    from_zone   TEXT NOT NULL,
    to_zone     TEXT NOT NULL,
    access_type TEXT NOT NULL,
    severity    TEXT NOT NULL,
    services    TEXT NOT NULL DEFAULT '[]',   -- JSON array
    description TEXT NOT NULL DEFAULT ''
);
```

This preserves the current data model exactly — `subnets`, `children`, `parents`, and
`services` stay as JSON arrays stored in TEXT columns. You gain atomic writes,
concurrent reads, and a natural path to audit logging (add a `changes` table) without
restructuring the app's internal data model.

### docker-compose.yml for Option B

```yaml
services:
  db-init:
    image: python:3.12-slim
    volumes:
      - zone_data:/data
      - ./db/init.sql:/init.sql:ro
    command: >
      sh -c "python3 -c \"
      import sqlite3, sys
      db = sqlite3.connect('/data/zone.db')
      db.executescript(open('/init.sql').read())
      db.close()
      print('DB init complete')
      \""
    restart: "no"

  app:
    build: .
    image: 4thealth:latest
    container_name: 4thealth
    restart: unless-stopped
    depends_on:
      db-init:
        condition: service_completed_successfully
    ports:
      - "8100:8100"
    env_file:
      - .env
    environment:
      - ZONE_DB_PATH=/data/zone.db
    volumes:
      - ./users.json:/app/users.json:rw
      - ./infra_targets.json:/app/infra_targets.json:ro
      - ./certs:/app/certs:ro
      - zone_data:/data

volumes:
  zone_data:
```

The app reads `ZONE_DB_PATH` from the environment instead of hardcoding
`policy_db.json`. The `db-init` service runs once, creates the schema if it does not
exist, and exits — `depends_on: condition: service_completed_successfully` ensures the
app does not start until the schema is ready.

### Migrating from policy_db.json to SQLite

Write a one-time migration script that reads the existing `policy_db.json` and inserts
all rows into the new database:

```python
#!/usr/bin/env python3
"""migrate_to_sqlite.py — run once to seed zone.db from policy_db.json"""
import json, sqlite3, sys
from pathlib import Path

src = Path("policy_db.json")
dst = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("zone.db")

db_json = json.loads(src.read_text())
con = sqlite3.connect(dst)

con.execute("""CREATE TABLE IF NOT EXISTS zones (
    name TEXT PRIMARY KEY, domain TEXT, is_shared INTEGER,
    description TEXT, subnets TEXT, children TEXT, parents TEXT
)""")
con.execute("""CREATE TABLE IF NOT EXISTS policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_set TEXT, from_zone TEXT, to_zone TEXT,
    access_type TEXT, severity TEXT, services TEXT, description TEXT
)""")

for name, z in db_json["zones"].items():
    con.execute("INSERT OR REPLACE INTO zones VALUES (?,?,?,?,?,?,?)", (
        name, z.get("domain","Default"), int(z.get("is_shared", False)),
        z.get("description",""),
        json.dumps(z.get("subnets",[])),
        json.dumps(z.get("children",[])),
        json.dumps(z.get("parents",[])),
    ))

for p in db_json["policies"]:
    con.execute("INSERT INTO policies (policy_set,from_zone,to_zone,access_type,severity,services,description) VALUES (?,?,?,?,?,?,?)", (
        p.get("policy_set",""), p.get("from_zone",""), p.get("to_zone",""),
        p.get("access_type",""), p.get("severity",""),
        json.dumps(p.get("services",[])), p.get("description",""),
    ))

con.commit()
con.close()
print(f"Migrated {len(db_json['zones'])} zones and {len(db_json['policies'])} policies to {dst}")
```

Run it once before starting the containers:

```bash
python3 migrate_to_sqlite.py zone.db
# Copy to the volume mount path your compose file expects
mkdir -p data && cp zone.db data/zone.db
```

---

## Reverse Proxy in Front of the Container

Whether you use Option A or B, you should not expose the container's port 8100 directly
to users. Put Nginx (or your existing load balancer) in front of it.

### Using the host's Nginx (no separate proxy container)

If the server already runs Nginx for other services, bind the container to
`127.0.0.1:8100` (not `0.0.0.0:8100`) so it is not reachable from outside:

```yaml
# docker-compose.yml
ports:
  - "127.0.0.1:8100:8100"
```

Then add a standard Nginx vhost (same as production.md Phase 3):

```nginx
server {
    listen 443 ssl http2;
    server_name 4thealth.yourdomain.com;

    ssl_certificate     /opt/4thealth/certs/cert.pem;
    ssl_certificate_key /opt/4thealth/certs/key.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

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
        proxy_read_timeout 120s;
    }
    location /static/ {
        alias /opt/4thealth/app/static/;
        expires 1h;
    }
    location ~ /\.(env|git)      { deny all; return 404; }
    location /users.json          { deny all; return 404; }
    location /policy_db.json      { deny all; return 404; }
    location /infra_targets.json  { deny all; return 404; }
}
server {
    listen 80;
    server_name 4thealth.yourdomain.com;
    return 301 https://$host$request_uri;
}
```

In this case, set `COOKIE_SECURE=true` in `.env` and remove the `certs/` volume mount
from the compose file — TLS is terminated at Nginx, not inside the container.

### Using an Nginx proxy container (fully self-contained stack)

If you want everything in one `docker compose up`:

```yaml
services:
  app:
    build: .
    image: 4thealth:latest
    container_name: 4thealth-app
    restart: unless-stopped
    expose:
      - "8100"          # internal only, not mapped to host
    env_file: .env
    volumes:
      - ./users.json:/app/users.json:rw
      - ./groups.json:/app/groups.json:rw
      - ./infra_targets.json:/app/infra_targets.json:ro
      - ./policy_db.json:/app/policy_db.json:rw

  proxy:
    image: nginx:alpine
    container_name: 4thealth-proxy
    restart: unless-stopped
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx/4thealth.conf:/etc/nginx/conf.d/default.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - app
```

Create `nginx/4thealth.conf`:

```nginx
server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl http2;
    server_name _;

    ssl_certificate     /etc/nginx/certs/cert.pem;
    ssl_certificate_key /etc/nginx/certs/key.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;

    location / {
        proxy_pass         http://app:8100;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_read_timeout 120s;
    }
    location /static/ {
        proxy_pass http://app:8100/static/;
    }
    location ~ /\.(env|git)      { deny all; return 404; }
    location /users.json          { deny all; return 404; }
    location /policy_db.json      { deny all; return 404; }
    location /infra_targets.json  { deny all; return 404; }
}
```

> Docker Compose creates an internal network automatically. The `app` service is
> reachable from `proxy` at `http://app:8100` — no IP address needed.

---

## Updating the Application

```bash
# Pull latest code
git pull

# Rebuild image with new code baked in
docker compose build

# Restart with new image (zero-downtime if you add a load balancer later)
docker compose up -d

# Confirm the new container is running
docker compose ps
docker compose logs -f --tail=50
```

No data is lost on rebuild — all mutable files (`users.json`, `policy_db.json`) are
bind-mounted from the host and are never inside the image.

---

## Backup

```bash
# Stop writes temporarily (optional but safest for policy_db.json)
docker compose pause app

cp policy_db.json policy_db.json.bak.$(date +%Y%m%d)
cp users.json users.json.bak.$(date +%Y%m%d)
cp groups.json groups.json.bak.$(date +%Y%m%d)
cp infra_targets.json infra_targets.json.bak.$(date +%Y%m%d)

docker compose unpause app
```

For Option B (SQLite), back up the volume:

```bash
docker compose pause app
docker run --rm -v 4thealth_zone_data:/data -v $(pwd):/backup \
    alpine cp /data/zone.db /backup/zone.db.bak.$(date +%Y%m%d)
docker compose unpause app
```

---

## Security Checklist

- [ ] `.env` is not committed to git (it is in `.gitignore`)
- [ ] `SECRET_KEY` is a 64-char random hex string
- [ ] `policy_db.json`, `users.json`, and `groups.json` are bind-mounted, not baked into the image
- [ ] Container port is bound to `127.0.0.1:8100`, not `0.0.0.0:8100`, when Nginx is on the host
- [ ] `COOKIE_SECURE=true` in `.env`
- [ ] TLS certificates are mounted read-only (`:ro`)
- [ ] Gunicorn is running with `gthread` worker class (required for background summary job and map cache)
- [ ] The `appuser` inside the container is a non-root system account
- [ ] `docker compose logs` are forwarded to your central log system (journald, syslog, etc.)

---

## Quick Reference

```bash
# Build image
docker compose build

# Start stack
docker compose up -d

# Stop stack
docker compose down

# View logs
docker compose logs -f

# Restart app only
docker compose restart app

# Open a shell in the running container
docker compose exec app /bin/bash

# Add a user
docker compose exec app python manage_users.py add <username> --role admin|viewer

# List users
docker compose exec app python manage_users.py list

# Generate SECRET_KEY
docker compose exec app python manage_users.py secret

# Health check
curl -sk https://localhost/api/health
```
