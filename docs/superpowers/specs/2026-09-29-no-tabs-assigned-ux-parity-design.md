# No-Tabs-Assigned UX Parity with 4tlog — Design

Date: 2026-09-29
Status: approved for planning

## Problem

4thealth-plus and 4tlog both onboarded 4tSuite SSO login and share nearly
identical `auth_routes.py`/`base.html` scaffolding, but they diverge in one
concrete, user-visible way: what happens when a successful login (local or
SSO) resolves to zero `allowed_tabs`.

**4tlog** (`~/code/github/web/4tlog/app/routes/auth_routes.py`): flashes
`"Your account has no tabs assigned. Contact an administrator."` (category
`"warning"`) before redirecting to `_first_allowed_url([])`, which falls
back to `/login`. Its `login.html` extends `base.html`, so the resulting
page shows the normal authenticated topbar (username, logout, theme
toggle) with the flashed banner in the main content area — the user
clearly sees they're logged in, just with nothing to do yet.

**4thealth-plus** (`app/routes/auth_routes.py`): does the same lookup and
redirect, but never flashes anything, and its `login.html` is a
self-contained standalone page (`<!DOCTYPE html>...<body class="login-page">`)
that never extends `base.html` at all. The result: an authenticated user
with zero tabs lands back on what looks like the plain anonymous sign-in
form — no indication they're logged in, no explanation why they have
nothing to do, no logout button visible (though `POST /logout` still
works if they know the URL).

This was confirmed by live testing from 4tSuite on 2026-09-29 (logged in
`4tsuite/Docs/4tsuite-implementation.md` §9) as one of two access-control
UX findings; this spec closes it for 4thealth-plus specifically (4tlog
already has the correct behavior — nothing to change there).

## Root cause (both are needed; neither alone fixes it)

1. `auth_routes.py`'s `login()` and `sso_login()` never call `flash(...)`
   when `allowed` is empty — 4tlog's equivalent functions do, immediately
   before their final `redirect(_first_allowed_url(allowed))` call.
2. `templates/login.html` is a full standalone HTML document, not a
   `{% extends "base.html" %}` template — so even once a flash message
   exists, there is nowhere for `base.html`'s
   `{% if session.get('user') %}<header class="topbar">...{% endif %}`
   block to render, since `login()`/`sso_login()`'s redirect target never
   goes through `base.html` at all today.

## Scope

- Add the missing `flash(...)` calls to `login()` and `sso_login()` in
  `app/routes/auth_routes.py`, verbatim matching 4tlog's message text and
  category (`"warning"`), so downstream automation or a future shared
  test suite across the two apps can rely on identical copy.
- Rewrite `app/templates/login.html` to extend `base.html`, keeping its
  visual content (title, subtitle, form fields, submit button) but
  dropping the page's own `<!DOCTYPE>`/`<head>`/`<body>` wrapper, its own
  duplicate flashed-messages block (base.html's `<main>` already renders
  one), and its own inline theme-toggle button/script.

## Non-goals

- **Keeping a theme toggle reachable on the fully-anonymous login page**
  (before any session exists, `base.html`'s topbar — which owns the only
  theme toggle button — doesn't render). 4tlog's own converted
  `login.html` has the exact same limitation; this spec matches that
  existing, already-shipped precedent rather than inventing a new
  anonymous-page theme toggle 4tlog doesn't have either. If this is later
  judged worth fixing, it's a shared 4tlog+4thealth-plus follow-up, not
  scope creep on this specific parity fix.
- **Changing 4tlog.** 4tlog already has the correct behavior; this spec
  makes no changes there.
- **Changing what determines `allowed_tabs`** (group membership,
  `sub_app_grants` push-sync from 4tSuite, RADIUS/AD group mapping). This
  spec only changes what happens once `allowed` is known to be empty.
- **The bare `403 Forbidden` a completely invalid/unverifiable SSO token
  already produces** (`sso_login()`'s `if username is None: abort(403)`
  branch) — that's a different, already-correct failure mode (the token
  itself didn't verify, no session was ever established) and is
  unrelated to the zero-`allowed_tabs` case this spec addresses.

## Implementation

**`app/routes/auth_routes.py`**, in `login()`'s success branch, immediately
before the final `return redirect(_first_allowed_url(allowed))` (matching
4tlog's exact placement — after the `next_url` early-return check, so an
explicit `?next=` redirect target still takes priority and doesn't also
flash a message the user may never see if they land somewhere else
entirely):

```python
            if not allowed:
                flash(
                    "Your account has no tabs assigned. Contact an administrator.",
                    "warning",
                )
            return redirect(_first_allowed_url(allowed))
```

In `sso_login()`, immediately before its own final
`return redirect(_first_allowed_url(allowed))`:

```python
    if not allowed:
        flash(
            "Your account has no tabs assigned. Contact an administrator.",
            "warning",
        )
    return redirect(_first_allowed_url(allowed))
```

**`app/templates/login.html`**, replaced in full to extend `base.html`
(mirroring 4tlog's own already-converted `login.html` structure exactly —
no theme toggle, no duplicate flash block, same `login-page`/`login-card`
div-wrapper classes the existing CSS (`app/static/css/style.css:203-235`)
already defines and currently applies via the standalone page's
`<body class="login-page">`):

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

No CSS changes: `.login-page { display:flex; align-items:center;
justify-content:center; min-height:100vh; }` already exists and applies
identically whether the class sits on `<body>` or on a `<div>` inside
`<main>` — the only visible difference is that when the authenticated
topbar renders (the zero-tabs case this spec fixes), the login card sits
below the topbar rather than dead-center in the full viewport, which is
the same minor, already-accepted cosmetic behavior 4tlog's identical
structure already has.

## Error handling & edge cases

- **A user with `next_url` set AND zero allowed tabs** (local login only
  — `sso_login()` has no `next_url` concept): matches 4tlog's exact
  existing behavior — the `next_url` redirect takes priority and no flash
  is shown. Not a new edge case this spec introduces; inherited as-is
  from 4tlog's own precedent.
- **A user who is still fully anonymous** (never authenticated,
  `session.get('user')` is falsy) visiting `/login` directly: renders
  exactly as before — the same form, just via `base.html`'s
  `{% else %}`-equivalent (topbar block simply doesn't render when there's
  no session user). No behavior change for this case.
- **The existing self-contained page's `themeToggle` JS** is removed
  entirely along with the standalone `<script>` block — `base.html`
  already owns theme persistence/toggling globally (`localStorage`-backed,
  applied on every page via its own inline script), so no functionality
  is lost for any authenticated user; only the fully-anonymous page loses
  the toggle, per the Non-goals section above.

## Testing strategy

New file `tests/test_login_no_tabs.py`, modeled on `tests/test_sso_login.py`'s
existing `app`/`client` fixture pattern (real Ed25519 keypair, real
`groups.create_group`, no mocking of Flask internals):

- `test_sso_login_with_zero_allowed_tabs_flashes_the_no_tabs_warning` — a
  user authenticated via SSO whose group(s) grant no tabs at all gets the
  exact flash message/category on the page the redirect lands on.
- `test_sso_login_with_zero_allowed_tabs_shows_the_authenticated_topbar` —
  the same response includes the session username in a `nav-user` element
  and a working logout form, proving `login.html` now extends `base.html`
  and the topbar's session-gated block renders.
- `test_local_login_with_zero_allowed_tabs_flashes_the_no_tabs_warning` —
  same assertion via the local-login POST path (`authenticate()` needs a
  real or fixture-backed local user; check `app/auth.py`'s test doubles
  used elsewhere in this suite for the correct fixture approach before
  writing this test, since `test_sso_login.py` doesn't cover local login
  at all today).
- `test_login_with_next_url_and_zero_allowed_tabs_does_not_flash` — pins
  the inherited-from-4tlog edge case above so a future refactor doesn't
  silently change it.
- A user WITH at least one allowed tab does **not** see the warning
  banner (regression guard — confirms the flash is conditional, not
  unconditional).

## Global constraints carried over from this repo's existing conventions

- TDD throughout: every changed behavior gets a failing test before its
  implementation, matching `tests/test_sso_login.py`'s existing pattern.
- Zero changes to 4tlog, 4tSuite, or 4tExecutive — this spec touches only
  4thealth-plus.
- No new dependencies.
- Run tests with `uv run pytest tests/` from the repo root, per this
  repo's established convention (matching `pyproject.toml`'s `dev`
  dependency group).
