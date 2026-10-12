# Production Deployment

The production deployment guide has been moved to the `docs/` folder.

| Document | Contents |
|---|---|
| [docs/deployment.md](docs/deployment.md) | Linux server setup, Gunicorn, Nginx, systemd (Phases 1–3) |
| [docs/authentication.md](docs/authentication.md) | RBAC, AD/LDAP, RADIUS/FortiAuthenticator, AD migration |
| [docs/hardening.md](docs/hardening.md) | File permissions, fail2ban, rate limiting, security checklist |
| [docs/operations.md](docs/operations.md) | Monitoring, updates, backup, SSL renewal |

## Deprecated: standalone RADIUS

`RADIUS_ENABLED` (the built-in RADIUS / FortiAuthenticator client) is deprecated and will be
removed in a later release. Enabling it logs a deprecation warning at startup. Sign in through
4tSuite's central login (RADIUS/LDAP/TACACS+) instead; local bcrypt accounts remain as break-glass.

## Migrating to 4tSuite

SSO sessions are admins when the user is a member of the 4thealth-plus group named by
`SSO_ADMIN_GROUP` (default `administrators`). The role is re-derived on every request, so removing a
user from that group drops admin on their next request. An empty value, or a group that does not
exist, makes no SSO user an admin.

Rollout order (no lockout):

1. Map: from the 4tSuite repo, dry-run the migration tool against this app's `groups.json`,
   review the output, then apply:
   `python -m tools.migrate_radius_groups --source /path/to/groups.json` then add `--apply`.
   Add a 4tSuite group for your RADIUS admin string that grants the `SSO_ADMIN_GROUP` group here,
   and create that group in 4thealth-plus if it is missing.
2. Verify: sign in as a RADIUS test user through 4tSuite and compare tabs and ADOMs with a
   standalone login for the same user.
3. Only then set `RADIUS_ENABLED=false`. To roll back, set it back to `true`.
