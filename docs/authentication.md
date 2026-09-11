# Authentication Guide

4THealth+ supports three authentication methods that can be combined:

| Method | When to use |
|---|---|
| **Local bcrypt** | Always available; emergency fallback; required for the first admin account |
| **Active Directory / LDAP** | Direct LDAP bind to domain controllers |
| **RADIUS (FortiAuthenticator)** | Preferred in environments where FAC is already deployed for VPN/SSO |

Local accounts in `users.json` serve as a fallback for all remote auth methods. Always keep at least one local `admin` account.

---

## Role-Based Access Control (RBAC)

4THealth+ ships with a fully-implemented RBAC system — no code changes are required.

### How It Works

- **Roles:** `admin` (full access) or `viewer` (tab-based access).
- **Sessions:** Role is stored in the signed Flask session cookie at login. Clients cannot tamper with it — `SECRET_KEY` cryptographically signs and verifies the cookie on every request.
- **Route protection:** Every page route uses `@login_required`. Admin-only routes additionally enforce `@admin_required`. Tab-access routes use `@tab_required("<tab_key>")`.

### Role and Tab Summary

| Role | Dashboard | Firewalls | Device Versions | Rule Review | Rule Validation | Zone Policy | Audit Review | Map (Beta) | Admin page | Raw/Debug endpoints |
|------|-----------|-----------|-----------------|-------------|-----------------|-------------|---------------|------------|------------|---------------------|
| admin | Always | Always | Always | Always | Always | Always | Always | Always | YES | YES |
| viewer | Per group | Per group | Per group | Per group | Per group | Per group | Per group | Per group | NO | NO |

Viewer tab access is the **union** of all tabs granted by the groups the user belongs to, configured in **Admin → Groups & Permissions**.

### Verifying RBAC

1. Log in as a `viewer` with no group memberships — the nav bar should show no content tabs.
2. Add the viewer to a group with Dashboard access. On next login the Dashboard tab should appear.
3. While logged in as a viewer, browse directly to `/admin` — expect HTTP 403.
4. While logged in as a viewer, call `/api/infrastructure/raw` — expect HTTP 403.
5. Log in as an `admin` — all tabs and raw endpoints should be accessible.

### Session Configuration

Already set in `app/config.py`:

```python
SESSION_COOKIE_HTTPONLY = True      # JS cannot read the cookie
SESSION_COOKIE_SAMESITE = "Lax"    # CSRF mitigation
SESSION_COOKIE_SECURE   = True      # Set automatically when TLS is detected
PERMANENT_SESSION_LIFETIME = 3600  # 1-hour session expiry
```

In production behind Nginx, ensure `COOKIE_SECURE=true` is set in `.env`.

---

## Active Directory / LDAP Authentication

### Phase 4.1 — Install python-ldap

```bash
cd /opt/4thealth
sudo nano /opt/4thealth/pyproject.toml  # Add "python-ldap>=3.4" to [project] dependencies
sudo -u 4thealth uv sync --extra prod
```

### Phase 4.2 — Add AD Configuration to .env

```dotenv
AD_ENABLED=true
AD_SERVER=ldaps://your-dc.yourdomain.com:636
AD_DOMAIN=YOURDOMAIN
AD_BASE_DN=DC=yourdomain,DC=com
AD_BIND_USER=CN=svc_4thealth,OU=Service Accounts,DC=yourdomain,DC=com
AD_BIND_PASSWORD=<service-account-password>
AD_USER_SEARCH=OU=Users,DC=yourdomain,DC=com
AD_GROUP_ADMIN=CN=4THealth-Admins,OU=Security Groups,DC=yourdomain,DC=com
AD_GROUP_VIEWER=CN=4THealth-Viewers,OU=Security Groups,DC=yourdomain,DC=com
AD_VERIFY_SSL=false
```

### Phase 4.3 — Update app/config.py

Add inside `Config`:

```python
AD_ENABLED       = os.environ.get("AD_ENABLED", "false").lower() == "true"
AD_SERVER        = os.environ.get("AD_SERVER", "")
AD_DOMAIN        = os.environ.get("AD_DOMAIN", "")
AD_BASE_DN       = os.environ.get("AD_BASE_DN", "")
AD_BIND_USER     = os.environ.get("AD_BIND_USER", "")
AD_BIND_PASSWORD = os.environ.get("AD_BIND_PASSWORD", "")
AD_USER_SEARCH   = os.environ.get("AD_USER_SEARCH", "")
AD_GROUP_ADMIN   = os.environ.get("AD_GROUP_ADMIN", "")
AD_GROUP_VIEWER  = os.environ.get("AD_GROUP_VIEWER", "")
AD_VERIFY_SSL    = os.environ.get("AD_VERIFY_SSL", "false").lower() == "true"
```

### Phase 4.4 — Update app/auth.py

Update `app/auth.py` to add LDAP/AD authentication:

Key integration points:
- `authenticate(username, password)` — attempt AD bind first; fall back to local bcrypt on failure
- `get_user_role(username)` — resolve role from AD group membership (`AD_GROUP_ADMIN` / `AD_GROUP_VIEWER`)
- Keep at least one local `admin` entry in `users.json` as an emergency fallback

### Phase 4.5 — Create AD Security Groups

```powershell
New-ADGroup -Name "4THealth-Admins"  -GroupScope Global -GroupCategory Security
New-ADGroup -Name "4THealth-Viewers" -GroupScope Global -GroupCategory Security

Add-ADGroupMember -Identity "4THealth-Admins"  -Members "jsmith"
Add-ADGroupMember -Identity "4THealth-Viewers" -Members "bjones","mlee"

New-ADUser -Name "svc_4thealth" `
  -SamAccountName "svc_4thealth" `
  -UserPrincipalName "svc_4thealth@yourdomain.com" `
  -AccountPassword (ConvertTo-SecureString "StrongPassword123!" -AsPlainText -Force) `
  -Enabled $true `
  -PasswordNeverExpires $true `
  -Description "4THealth LDAP bind account - read-only"
```

### Phase 4.6 — Test AD Authentication

```bash
ldapsearch -x -H ldaps://your-dc.yourdomain.com:636 \
  -D "CN=svc_4thealth,OU=Service Accounts,DC=yourdomain,DC=com" \
  -w "StrongPassword123!" \
  -b "OU=Users,DC=yourdomain,DC=com" \
  "(sAMAccountName=jsmith)" dn memberOf

sudo systemctl restart 4thealth
sudo journalctl -u 4thealth -n 30
```

---

## Migrating Local Groups to Active Directory

When you enable AD authentication, the `users.json` member lists inside `groups.json` are no longer authoritative — AD resolves membership dynamically at login.

### Pre-migration Checklist

- [ ] AD authentication is working (`AD_ENABLED=true`).
- [ ] Each AD group that should map to an app group exists in Active Directory.
- [ ] You have at least one local admin fallback account.

### Step 1 — Match Group Names to AD Group Names

Two common mapping strategies:

**Strategy A — name groups to match AD group SAMAccountNames**

```
groups.json group name:  "4THealth-NOC"
AD group SAMAccountName: "4THealth-NOC"
```

Update your AD auth code so that after a successful bind it reads the user's `memberOf` attribute, extracts the `CN=` part of each group DN, and passes those CN values to `get_allowed_tabs(username)`.

**Strategy B — keep generic group names, map AD groups to roles only**

Keep two groups (`admin`, `viewer`) in `groups.json` and rely solely on the `AD_GROUP_ADMIN` / `AD_GROUP_VIEWER` env-vars to assign the role.

### Step 2 — Update app/groups.py for AD Membership Lookup

```python
def get_allowed_tabs(username: str, ad_groups: list[str] | None = None) -> set[str]:
    """ad_groups: list of CN values resolved from AD memberOf, or None for local auth."""
    from app.auth import _load_users
    users = _load_users()
    user_entry = users.get(username, {})
    if user_entry.get("role") == "admin":
        return set(KNOWN_TABS.keys())

    with _lock:
        groups = _load()

    if ad_groups is not None:
        tabs: set[str] = set()
        for group_name in ad_groups:
            g = groups.get(group_name)
            if g:
                tabs.update(g.get("allowed_tabs", []))
        return tabs

    tabs = set()
    for g in groups.values():
        if username in g.get("members", []):
            tabs.update(g.get("allowed_tabs", []))
    return tabs
```

Pass `ad_groups=<resolved_cns>` from `auth_routes.py` at login time.

### Step 3–6 — Complete Migration

- **Step 3:** Clear stale member lists via Admin UI (optional hygiene — ignored when `ad_groups` is passed).
- **Step 4:** Back up `groups.json` before changes: `cp groups.json groups.json.bak.$(date +%Y%m%d)`
- **Step 5:** Test with a non-admin AD account — confirm expected tabs appear and `/admin` returns 403.
- **Step 6:** Keep the local `admin` account in `users.json`. Emergency runbook: if AD is down, set `AD_ENABLED=false`, restart the service, log in with the local admin account, re-enable after AD recovery.

---

## FortiAuthenticator RADIUS Authentication

FAC handles the AD bind and group lookups internally — the app only needs to speak RADIUS. Preferred in environments where direct LDAP access to domain controllers is restricted or where FAC is already deployed.

**How it works:**

1. 4THealth+ sends a RADIUS Access-Request (username + password) to FAC.
2. FAC validates credentials against AD and resolves the user's AD groups.
3. FAC returns a RADIUS Access-Accept with a `Filter-Id` or `Class` attribute carrying the role group name.
4. 4THealth+ reads that attribute, maps it to `admin` or `viewer`, and proceeds with the normal session setup.

### FAC-1 — FortiAuthenticator Configuration

#### FAC-1.1 Add the RADIUS NAS Client

**Authentication → RADIUS Service → Clients → Create New**

| Field | Value |
|---|---|
| Name | `4thealth-prod` |
| Client IP/Subnet | `<4THealth server IP>` |
| Secret | `<generate a strong shared secret>` |
| Authentication method | PAP (or CHAP — must match `RADIUS_AUTH_METHOD` in `.env`) |

#### FAC-1.2 Connect FAC to Active Directory

**Authentication → Remote Auth Servers → LDAP → Create New**

| Field | Value |
|---|---|
| Name | `AD-Corp` |
| Server name/IP | `your-dc.yourdomain.com` |
| Server port | `636` (LDAPS) or `389` |
| Distinguished name | `DC=yourdomain,DC=com` |
| Bind type | Regular |
| Username | `CN=svc_4thealth,OU=Service Accounts,DC=yourdomain,DC=com` |
| Password | `<service account password>` |

Test the connection using the **Test** button before saving.

#### FAC-1.3 Create RADIUS User Groups

**Authentication → User Groups → Create New** — repeat for each role.

Group 1 (admin role):

| Field | Value |
|---|---|
| Name | `4THealth-Admins` |
| Type | RADIUS |
| Remote servers | Select `AD-Corp` |
| Remote group filter | `CN=4THealth-Admins,OU=Security Groups,DC=yourdomain,DC=com` |

Group 2 (viewer role):

| Field | Value |
|---|---|
| Name | `4THealth-Viewers` |
| Type | RADIUS |
| Remote servers | Select `AD-Corp` |
| Remote group filter | `CN=4THealth-Viewers,OU=Security Groups,DC=yourdomain,DC=com` |

#### FAC-1.4 Configure RADIUS Policy

**Authentication → RADIUS Service → Policies → Create New**

| Field | Value |
|---|---|
| Name | `4thealth-policy` |
| NAS client | `4thealth-prod` |
| Users/Groups | Add both `4THealth-Admins` and `4THealth-Viewers` |

Under **Reply Attributes**, add one entry per group:

| Group | Attribute | Value |
|---|---|---|
| `4THealth-Admins` | `Filter-Id` | `4THealth-Admins` |
| `4THealth-Viewers` | `Filter-Id` | `4THealth-Viewers` |

> Set the default action to **Reject** so users not in either group cannot authenticate.

#### FAC-1.5 Test from the FAC CLI

```bash
diagnose radius-test auth <NAS-client-name> <username> <password>
```

A successful response shows `Access-Accept` with `Filter-Id = 4THealth-Admins` (or Viewers).

### FAC-2 — Linux Server Configuration

#### FAC-2.1 Install the RADIUS Client Library

```bash
cd /opt/4thealth
sudo -u 4thealth uv add pyrad
```

Commit the updated `pyproject.toml` and `uv.lock`.

#### FAC-2.2 Add RADIUS Variables to `.env`

```dotenv
RADIUS_ENABLED=true
RADIUS_HOST=<Primary FAC IP>
RADIUS_PORT=1812
RADIUS_HOST_2=<Secondary FAC IP>   # HA failover — leave blank if unused
RADIUS_PORT_2=1812
RADIUS_SECRET=<shared secret from FAC-1.1>
RADIUS_AUTH_METHOD=pap
RADIUS_TIMEOUT=10
RADIUS_GROUP_ADMIN=4THealth-Admins
RADIUS_GROUP_VIEWER=4THealth-Viewers
```

Both `RADIUS_HOST` and `RADIUS_HOST_2` use the same shared secret. On a primary FAC timeout, the app automatically retries the secondary FAC before falling back to local `users.json` accounts.

#### FAC-2.5 Map RADIUS Users to 4THealth+ Groups

RADIUS-authenticated users are not listed in `users.json`. Tab and ADOM permissions are resolved at login time using the AD group names returned by FAC.

**Recommended — AD Group membership (no per-user config):**

1. Log in as a local admin.
2. Go to **Admin → Groups & Permissions**.
3. Open (or create) the group that should cover these users (e.g. `NOC-Team`).
4. In the **AD / RADIUS Groups** field, type the exact group name that FortiAuthenticator returns (e.g. `4THealth-NOC`) and press **Enter**.
5. Save the group.

To verify the exact string FAC sends, run `radtest -x` and look for the `Filter-Id` or `Class` line in the `Access-Accept` response.

**Per-user fallback:** You can still add individual AD `sAMAccountName` values to a group's **Members** list. Both mechanisms work simultaneously.

#### FAC-2.6 Smoke Test

```bash
# Verify FAC is reachable from the server (UDP 1812)
nc -zu <FAC-IP> 1812 && echo "RADIUS port reachable" || echo "BLOCKED"

# Test a full authentication round-trip
sudo dnf install -y freeradius-utils   # or apt-get install freeradius-utils
radtest <ad-username> <password> <FAC-IP> 0 <shared-secret>
# Expected: Received Access-Accept

sudo systemctl restart 4thealth
sudo journalctl -u 4thealth -f
```

A successful login will log:
```
auth: Login successful  username=jsmith  role=admin
```

### FAC-3 — Fallback and Recovery

| Scenario | Behaviour |
|---|---|
| Primary FAC unreachable | App automatically retries `RADIUS_HOST_2` (if configured); falls through to local auth when all servers fail |
| Secondary FAC unreachable | Falls through to local `users.json` bcrypt auth |
| Both FACs unreachable | Local `users.json` bcrypt auth only |
| User not in any FAC group | FAC sends Access-Reject; app falls through to local auth |
| AD outage (FAC cannot reach DC) | FAC sends Access-Reject; fallback to local auth |
| `RADIUS_ENABLED=false` | RADIUS path skipped entirely; pure local bcrypt |

Emergency recovery: set `RADIUS_ENABLED=false` in `.env` and restart with `sudo systemctl restart 4thealth`.

### FAC-4 — Security Checklist

- [ ] RADIUS shared secret is at least 32 random characters and stored only in `.env` (mode `640`)
- [ ] FAC RADIUS policy default action is **Reject**
- [ ] FAC client IP is locked to the 4THealth+ server IP — no wildcard `/0` subnet
- [ ] UDP port 1812 is open from the 4THealth+ server to both FAC IPs and closed from everywhere else
- [ ] `RADIUS_AUTH_METHOD` matches the FAC client config (both PAP, or both CHAP)
- [ ] Local `admin` account in `users.json` is retained as an emergency fallback
- [ ] `RADIUS_TIMEOUT` is set low enough (10 s) so failover latency is predictable
- [ ] FAC is configured to log all authentication attempts for audit trail
- [ ] AD group names added to 4THealth+ groups match exactly what FAC sends (verify with `radtest -x`)
