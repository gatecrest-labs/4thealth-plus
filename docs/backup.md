# Backup and Restore Guide

This guide covers what to back up, how to do it manually per deployment type, and how to restore 4THealth+ on a new server.

The application code itself lives in git — only runtime data (secrets, user accounts, config, certificates, and persistent state) needs backing up.

---

## What to Back Up

All of these files are gitignored. None exist in the repository; you created them during initial setup.

| File | Contains | Critical? |
|------|----------|-----------|
| `.env` | `SECRET_KEY`, FortiManager credentials, SMTP settings, all env vars | Yes — without it the app won't start |
| `users.json` | Local user accounts with bcrypt-hashed passwords | Yes — required for login |
| `groups.json` | Group definitions, tab permissions, ADOM access lists | Yes — restores access control |
| `certs/cert.pem` | TLS certificate | Yes (if self-signed or corp CA; skip if Let's Encrypt) |
| `certs/key.pem` | TLS private key | Yes (same caveat) |
| `infra_targets.json` | Infrastructure dashboard device list | Yes — restores infra tab |
| `policy_db.json` | Zone policy database | Yes — all zone/subnet/policy data |
| `app_settings.json` | Feature flags (external API toggle) | Yes |
| `api_tokens.json` | Hashed bearer tokens for external API clients | Yes — external integrations will break without it |
| `smtp_config.json` | SMTP relay settings | Yes if scheduled exports are in use |
| `config_diff_jobs.json` | Scheduled Config-Delta export jobs + run history | Yes if scheduled jobs are configured |
| `device_review_jobs.json` | Scheduled Audit Review audit jobs + run history | Yes if scheduled jobs are configured |
| `summary_history.json` | Nightly firewall/rule count history | No — regenerates on next nightly run |

**Linux-only extras (not in the app directory):**

| File | Contains |
|------|----------|
| `/etc/systemd/system/4thealth.service` | Systemd unit file |
| `/etc/nginx/conf.d/4thealth.conf` | Nginx reverse proxy config |

---

## RHEL / Rocky / AlmaLinux / Ubuntu — Production Backup

The app runs as the `4thealth` system user from `/opt/4thealth`.

The backup is a shell script that you create once on the server, then schedule to run automatically via cron. The steps below walk through the full setup.

### Step 1 — Create the backup script

SSH into the server and create the script file:

```bash
sudo nano /opt/4thealth/backup.sh
```

Paste this content into the file, then save and exit (`Ctrl+O`, `Enter`, `Ctrl+X`):

```bash
#!/bin/bash
BACKUP_DATE=$(date +%Y%m%d)
BACKUP_FILE="/root/4thealth-backup-${BACKUP_DATE}.tar.gz"

sudo tar -czf "$BACKUP_FILE" \
  -C /opt/4thealth \
  .env \
  users.json \
  groups.json \
  certs/ \
  infra_targets.json \
  policy_db.json \
  app_settings.json \
  api_tokens.json \
  smtp_config.json \
  config_diff_jobs.json \
  device_review_jobs.json \
  summary_history.json \
  --ignore-failed-read

# Add systemd and nginx configs
sudo tar -rzf "$BACKUP_FILE" \
  /etc/systemd/system/4thealth.service \
  /etc/nginx/conf.d/4thealth.conf \
  2>/dev/null || true

echo "Backup written to $BACKUP_FILE"
ls -lh "$BACKUP_FILE"
```

> `--ignore-failed-read` silently skips any file that doesn't exist yet (e.g. if `smtp_config.json` was never created).

Make the script executable:

```bash
sudo chmod +x /opt/4thealth/backup.sh
```

You can test it runs correctly right now:

```bash
sudo /opt/4thealth/backup.sh
ls -lh /root/4thealth-backup-*.tar.gz
```

### Step 2 — Copy the backup off-server

Pick a destination for the archives and update the copy command to match. Common options:

```bash
# Copy to a remote backup host
scp /root/4thealth-backup-*.tar.gz user@backup-host:/backups/

# Copy to a mounted network share
rsync -av /root/4thealth-backup-*.tar.gz /mnt/nas/backups/4thealth/
```

Add your chosen copy command to the end of `backup.sh` so the archive is transferred automatically each time the script runs.

### Step 3 — Schedule with cron (runs nightly)

Open the root crontab:

```bash
sudo crontab -e
```

Add this line to run the script nightly at 02:30 and prune archives older than 30 days:

```
30 2 * * * /opt/4thealth/backup.sh && find /root -name '4thealth-backup-*.tar.gz' -mtime +30 -delete
```

Save and exit. Verify the cron entry was saved:

```bash
sudo crontab -l
```

From this point the backup runs automatically every night — no further manual action needed.

---

## Docker / Docker Compose — Manual Backup

The Docker deployment mounts runtime files from the host directory where `docker-compose.yml` lives (e.g. `/opt/4thealth` or wherever you cloned the repo).

### Create a backup archive

```bash
# Stop the container first to ensure files are not mid-write
APP_DIR="/opt/4thealth"   # adjust if your compose directory is elsewhere
BACKUP_DATE=$(date +%Y%m%d)
BACKUP_FILE="/root/4thealth-backup-${BACKUP_DATE}.tar.gz"

docker compose -f "$APP_DIR/docker-compose.yml" stop

tar -czf "$BACKUP_FILE" \
  --ignore-failed-read \
  -C "$APP_DIR" \
  .env \
  users.json \
  groups.json \
  certs/ \
  infra_targets.json \
  policy_db.json \
  app_settings.json \
  api_tokens.json \
  smtp_config.json \
  config_diff_jobs.json \
  device_review_jobs.json \
  summary_history.json \
  docker-compose.yml

docker compose -f "$APP_DIR/docker-compose.yml" start

echo "Backup written to $BACKUP_FILE"
ls -lh "$BACKUP_FILE"
```

> Stopping the container before archiving avoids a partially-written `policy_db.json` if an admin edit was in flight.

### Backup without downtime

If a brief stop is unacceptable, back up while running — the risk of a torn write is low since all JSON files are written atomically (temp file + rename):

```bash
APP_DIR="/opt/4thealth"
BACKUP_DATE=$(date +%Y%m%d)

tar -czf "/root/4thealth-backup-${BACKUP_DATE}.tar.gz" \
  --ignore-failed-read \
  -C "$APP_DIR" \
  .env users.json groups.json certs/ infra_targets.json \
  policy_db.json app_settings.json api_tokens.json \
  smtp_config.json config_diff_jobs.json device_review_jobs.json \
  summary_history.json docker-compose.yml
```

---

## Restore on a New Server

These steps assume you have a backup archive from one of the procedures above.

### Step 1 — Set up the new server

Follow the full deployment guide for your target platform:

- **Linux:** [deployment.md](deployment.md) through Phase 2.4 (stop before creating users — `users.json` will be restored from backup).
- **Docker:** [../container.md](../container.md) through the image pull / build step.

### Step 2 — Transfer the backup archive

```bash
# From the old server or a file share
scp /root/4thealth-backup-<date>.tar.gz user@new-server:/tmp/
```

### Step 3 — Restore files (Linux)

```bash
ARCHIVE="/tmp/4thealth-backup-<date>.tar.gz"

# Extract app-level files into /opt/4thealth
sudo tar -xzf "$ARCHIVE" \
  --strip-components=0 \
  -C /opt/4thealth \
  --exclude='etc'

# Restore systemd and nginx configs (paths are absolute inside the archive)
sudo tar -xzf "$ARCHIVE" \
  etc/systemd/system/4thealth.service \
  etc/nginx/conf.d/4thealth.conf \
  -C / 2>/dev/null || true

# Fix ownership
sudo chown -R 4thealth:4thealth /opt/4thealth
sudo chmod 600 /opt/4thealth/certs/key.pem
sudo chmod 600 /opt/4thealth/.env

# Reload and start
sudo systemctl daemon-reload
sudo systemctl enable 4thealth
sudo systemctl restart 4thealth
sudo nginx -t && sudo systemctl restart nginx
```

### Step 3 — Restore files (Docker)

```bash
APP_DIR="/opt/4thealth"   # wherever docker-compose.yml lives
ARCHIVE="/tmp/4thealth-backup-<date>.tar.gz"

# Extract everything into the app directory
tar -xzf "$ARCHIVE" -C "$APP_DIR"

# Fix permissions on secrets
chmod 600 "$APP_DIR/.env"
chmod 600 "$APP_DIR/certs/key.pem"

# Start the container
docker compose -f "$APP_DIR/docker-compose.yml" up -d
```

### Step 4 — Verify

```bash
# Linux
sudo systemctl status 4thealth
curl -sk https://localhost/login | grep -i 4thealth

# Docker
docker compose ps
curl -sk https://localhost:8100/login | grep -i 4thealth
```

Log in with an account from the restored `users.json` and confirm:

- The correct ADOMs appear in the ADOM selector
- Zone Policy tab loads data (confirms `policy_db.json` restored)
- Infrastructure tab shows devices (confirms `infra_targets.json` restored)
- Admin → Scheduled shows existing jobs (confirms `config_diff_jobs.json` / `device_review_jobs.json` restored)

---

## TLS Certificate Notes

| Cert type | Back up? | Notes |
|-----------|----------|-------|
| Self-signed (generated with `openssl req -x509`) | Yes | Back up both `cert.pem` and `key.pem` — cannot be reissued |
| Corporate / internal CA | Yes | The key cannot be re-exported; back up the key or re-request from your CA on restore |
| Let's Encrypt (`certbot`) | No | Skip — re-run `certbot` on the new server; cert auto-renews |

If you cannot recover a self-signed cert, generate a new one on the new server and re-add it to any browser trust stores or client systems that pinned the old cert:

```bash
sudo openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout /opt/4thealth/certs/key.pem \
  -out /opt/4thealth/certs/cert.pem \
  -days 3650 \
  -subj "/CN=4thealth.yourdomain.com" \
  -addext "subjectAltName=DNS:4thealth.yourdomain.com,IP:<new-server-ip>"
sudo chown 4thealth:4thealth /opt/4thealth/certs/*.pem
sudo chmod 600 /opt/4thealth/certs/key.pem
```
