# No-Tabs-Assigned UX Parity with 4tlog Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An authenticated user (local or SSO) with zero `allowed_tabs` sees 4tlog's friendly "Your account has no tabs assigned. Contact an administrator." warning inside the normal authenticated shell, instead of landing back on what looks like the plain anonymous sign-in page.

**Architecture:** Two small, additive changes to existing files — a `flash()` call added to each of `auth_routes.py`'s two login success paths, and `login.html` rewritten to extend `base.html` instead of being a standalone page. No new modules, no route changes, no schema change.

**Tech Stack:** Python 3, Flask, Jinja2, pytest, bcrypt.

**Spec:** `docs/superpowers/specs/2026-09-29-no-tabs-assigned-ux-parity-design.md`

## Global Constraints

- TDD throughout: every changed behavior gets a failing test before its implementation.
- Zero changes to 4tlog, 4tSuite, or 4tExecutive — this plan touches only 4thealth-plus.
- Flash message text and category must match 4tlog's exactly: `"Your account has no tabs assigned. Contact an administrator."`, category `"warning"`.
- No CSS changes — `app/static/css/style.css:203-235`'s `.login-page`/`.login-card`/`.login-title`/`.login-subtitle` rules already work identically on a `<div>` as they did on `<body>`.
- Run tests with `uv run pytest tests/` from the repo root.

## Review Focus

- **A user with at least one allowed tab must NOT see the warning banner** — the flash is conditional on `not allowed`, not unconditional; a naive implementation might flash on every login.
- **A user with `?next=` set AND zero allowed tabs (local login only)** — the existing `next_url` early-return must still take priority and skip the flash, matching 4tlog's own existing precedent exactly (not a new edge case this plan invents).
- **The SSO path and the local-login path must both get the fix** — it would be easy to fix only `sso_login()` (the path 4tSuite's live testing actually exercised) and miss the identical gap in `login()`'s local-auth success branch.
- **The authenticated topbar must actually render, not just the flash message** — a fix that only adds the `flash()` call without converting `login.html` to extend `base.html` would still show the message on a page with no session-aware chrome, missing half of what "parity with 4tlog" means.
- **A fully anonymous visitor to `/login` (no session at all) must see unchanged behavior** — the template conversion must not accidentally require a session to render the plain sign-in form.

---

## Task 1: Add the missing flash calls

**Files:**
- Modify: `app/routes/auth_routes.py`
- Test: `tests/test_login_no_tabs.py` (created here, extended by Task 2)

**Interfaces:**
- Consumes: nothing new — `flash` is already imported at the top of `auth_routes.py` (used elsewhere in the file for `"Invalid credentials."` etc.).
- Produces: nothing new consumed elsewhere — this is a route-body change only.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_login_no_tabs.py`:

```python
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _keypair():
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def _mint(priv_pem, *, audience="4thealth-plus", issuer="4tsuite", sub="alice"):
    now = int(time.time())
    claims = {
        "sub": sub, "aud": audience, "iss": issuer,
        "iat": now, "nbf": now, "exp": now + 300,
    }
    return jwt.encode(claims, priv_pem, algorithm="EdDSA")


@pytest.fixture
def app(tmp_path, monkeypatch):
    import app.auth as auth_mod
    import app.groups as groups_mod
    import app.sso_verify as sso_mod

    monkeypatch.setattr(groups_mod, "GROUPS_FILE", tmp_path / "groups.json")
    monkeypatch.setattr(auth_mod, "USERS_FILE", tmp_path / "users.json")
    priv_pem, pub_pem = _keypair()
    key_path = tmp_path / "sso_public_key.pem"
    key_path.write_bytes(pub_pem)
    monkeypatch.setattr(sso_mod, "PUBLIC_KEY_PATH", key_path)

    from app import create_app

    app = create_app(test_config={"TESTING": True})
    app.config["_TEST_PRIV_KEY"] = priv_pem
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def test_sso_login_with_zero_allowed_tabs_flashes_the_no_tabs_warning(app, client):
    import app.groups as groups_mod

    groups_mod.create_group("no-tabs-group", members=["alice"], allowed_tabs=[])

    token = _mint(app.config["_TEST_PRIV_KEY"], sub="alice")
    response = client.get(f"/sso/login?token={token}", follow_redirects=True)

    assert response.status_code == 200
    assert b"Your account has no tabs assigned. Contact an administrator." in response.data


def test_local_login_with_zero_allowed_tabs_flashes_the_no_tabs_warning(app, client):
    import app.auth as auth_mod
    import app.groups as groups_mod

    auth_mod.add_user("bob", "Sup3r!Secret123", role="viewer")
    groups_mod.create_group("no-tabs-group", members=["bob"], allowed_tabs=[])

    response = client.post(
        "/login",
        data={"username": "bob", "password": "Sup3r!Secret123"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Your account has no tabs assigned. Contact an administrator." in response.data


def test_login_with_next_url_and_zero_allowed_tabs_does_not_flash(app, client):
    """`/login` itself is excluded by _safe_redirect's own deny-list
    (`url != "/login"`), so this test uses a different relative path to
    actually exercise the early-return branch. It checks the redirect
    target and the session's flash queue directly, rather than rendered
    page content, so it doesn't depend on `/some/relative/path` being a
    real, renderable route."""
    import app.auth as auth_mod
    import app.groups as groups_mod

    auth_mod.add_user("carol", "Sup3r!Secret123", role="viewer")
    groups_mod.create_group("no-tabs-group", members=["carol"], allowed_tabs=[])

    response = client.post(
        "/login?next=/some/relative/path",
        data={"username": "carol", "password": "Sup3r!Secret123"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["Location"] == "/some/relative/path"
    with client.session_transaction() as sess:
        flashes = sess.get("_flashes", [])
    assert not any("no tabs assigned" in msg for _cat, msg in flashes)


def test_login_with_at_least_one_tab_does_not_flash_the_no_tabs_warning(app, client):
    import app.groups as groups_mod

    groups_mod.create_group("operators", members=["alice"], allowed_tabs=["dashboard"])

    token = _mint(app.config["_TEST_PRIV_KEY"], sub="alice")
    response = client.get(f"/sso/login?token={token}", follow_redirects=True)

    assert response.status_code == 200
    assert b"Your account has no tabs assigned. Contact an administrator." not in response.data
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_login_no_tabs.py -v`
Expected: `test_sso_login_with_zero_allowed_tabs_flashes_the_no_tabs_warning`
and `test_local_login_with_zero_allowed_tabs_flashes_the_no_tabs_warning`
FAIL (no flash message exists yet — the redirected-to page won't contain
the text). `test_login_with_next_url_and_zero_allowed_tabs_does_not_flash`
and `test_login_with_at_least_one_tab_does_not_flash_the_no_tabs_warning`
PASS already (nothing to flash in either case, before or after the fix).

- [ ] **Step 3: Implement**

In `app/routes/auth_routes.py`, in `login()`, change:

```python
            next_url = request.args.get("next", "").strip()
            if next_url and _safe_redirect(next_url):
                return redirect(next_url)
            return redirect(_first_allowed_url(allowed))
```

to:

```python
            next_url = request.args.get("next", "").strip()
            if next_url and _safe_redirect(next_url):
                return redirect(next_url)
            if not allowed:
                flash(
                    "Your account has no tabs assigned. Contact an administrator.",
                    "warning",
                )
            return redirect(_first_allowed_url(allowed))
```

And in `sso_login()`, change:

```python
    app_log("INFO", "auth", "SSO login successful", username=username)
    from app import login_metrics as _lm

    _lm.record_event(True)
    return redirect(_first_allowed_url(allowed))
```

to:

```python
    app_log("INFO", "auth", "SSO login successful", username=username)
    from app import login_metrics as _lm

    _lm.record_event(True)
    if not allowed:
        flash(
            "Your account has no tabs assigned. Contact an administrator.",
            "warning",
        )
    return redirect(_first_allowed_url(allowed))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_login_no_tabs.py -v`
Expected: all 4 tests pass.

- [ ] **Step 5: Run the full test suite to check for regressions**

Run: `uv run pytest tests/ -v`
Expected: all tests pass, no regressions (this task only adds `flash()`
calls behind an `if not allowed` guard that was previously always false
for every existing passing test — those tests all configure users with
at least one tab, or don't reach this code path at all).

- [ ] **Step 6: Commit**

```bash
git add app/routes/auth_routes.py tests/test_login_no_tabs.py
git commit -m "feat: flash a warning when login resolves to zero allowed tabs

Matches 4tlog's existing behavior -- a successful local or SSO login
with no group granting any tab now tells the user why, instead of
silently redirecting back to what looks like a fresh login page."
```

---

## Task 2: Convert `login.html` to extend `base.html`

**Files:**
- Modify: `app/templates/login.html`
- Test: `tests/test_login_no_tabs.py` (adds to the file Task 1 created)

**Interfaces:**
- Consumes: `base.html`'s existing `{% block title %}`/`{% block content %}` structure and its `{% if session.get('user') %}<header class="topbar">...{% endif %}` block (unmodified by this task).
- Produces: nothing new consumed elsewhere.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_login_no_tabs.py`:

```python
def test_sso_login_with_zero_allowed_tabs_shows_the_authenticated_topbar(app, client):
    import app.groups as groups_mod

    groups_mod.create_group("no-tabs-group", members=["alice"], allowed_tabs=[])

    token = _mint(app.config["_TEST_PRIV_KEY"], sub="alice")
    response = client.get(f"/sso/login?token={token}", follow_redirects=True)

    assert response.status_code == 200
    assert b'<span class="nav-user">alice</span>' in response.data
    assert b'action="/logout"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_login_no_tabs.py::test_sso_login_with_zero_allowed_tabs_shows_the_authenticated_topbar -v`
Expected: FAIL — `login.html` doesn't extend `base.html` yet, so the
topbar markup doesn't exist anywhere in the response.

- [ ] **Step 3: Implement**

Replace `app/templates/login.html` in full:

```html
{% extends "base.html" %}
{% block title %}Login — 4THealth+{% endblock %}
{% block content %}
<div class="login-page">
  <div class="login-card">
    <h1 class="login-title">&#128274; 4THealth+</h1>
    <p class="login-subtitle">Network Operations Dashboard</p>
    <form method="post" action="{{ url_for('auth.login') }}" autocomplete="off">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
      <div class="form-group">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" class="form-control"
               autocomplete="username" required autofocus />
      </div>
      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" class="form-control"
               autocomplete="current-password" required />
      </div>
      <button type="submit" class="btn btn-primary btn-block">Sign In</button>
    </form>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_login_no_tabs.py -v`
Expected: all 5 tests in this file pass.

- [ ] **Step 5: Run the full test suite to check for regressions**

Run: `uv run pytest tests/ -v`
Expected: all tests pass. `tests/test_smoke.py` (the only other file
referencing `/login`) must still pass — read it first if this fails, to
confirm it doesn't assert on `login.html`'s old standalone-page markup
(e.g. a literal `<!DOCTYPE html>` check tied to that specific page)
rather than just a 200 status.

- [ ] **Step 6: Manual visual check (no automated test for this)**

Run the app locally (`uv run python wsgi.py`, per this repo's `CLAUDE.md`)
and visually confirm in a browser:
1. A fully anonymous visit to `/login` still shows the plain centered
   sign-in card, no topbar (unchanged from before this plan).
2. Log in as a user with zero tabs (or hit a real `/sso/login?token=...`
   URL for such a user). Confirm the topbar now appears above the
   sign-in card, with the warning banner between them, and that clicking
   Logout works.

- [ ] **Step 7: Commit**

```bash
git add app/templates/login.html
git commit -m "feat: login.html extends base.html for topbar/flash parity with 4tlog"
```
