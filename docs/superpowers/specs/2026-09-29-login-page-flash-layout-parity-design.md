# Login Page Flash/Scroll Layout Fix — Design (dual-repo)

Date: 2026-09-29
Status: approved for planning

**Implemented identically in two repos:**
- `~/code/github/web/4tlog` (`gatecrest-labs/4tLog`, confirmed via `git remote -v`)
- This repo, 4thealth-plus (`gatecrest-labs/4thealth-plus`)

Both repos need the exact same two-file change (`app/templates/base.html`,
`app/templates/login.html`) plus the exact same one-line CSS change
(`app/static/css/style.css`). Confirmed byte-for-byte identical in both
repos as of 2026-09-29: `base.html`'s `<main>` block (lines 48-55 in
4thealth-plus, 49-56 in 4tlog), `login.html`'s post-conversion structure,
and the `.login-page` CSS rule (lines 202-208 in both).

## Problem

Both apps converted `login.html` from a standalone page to one that
extends `base.html`, as part of the 2026-09-29 no-tabs-assigned UX parity
fix (4thealth-plus's `docs/superpowers/specs/2026-09-29-no-tabs-assigned-ux-parity-design.md`).
That fix's own final review surfaced two cosmetic regressions shared by
both apps, since both already had the identical `base.html` structure
before that fix (4tlog first, 4thealth-plus converted to match):

1. **Flash/error banners moved outside the login card.** `base.html`'s
   `<main>` renders `get_flashed_messages()` once, unconditionally,
   before `{% block content %}`. Before the conversion, each app's
   standalone `login.html` rendered its own flash loop *inside*
   `.login-card`. Now every flash (invalid credentials, rate-limited,
   the no-tabs-assigned warning) renders full-width above the card
   instead of inside it — a visible layout change for the most common
   anonymous-login-failure flow.
2. **The login page scrolls slightly.** `.login-page { min-height: 100vh }`
   used to sit directly on `<body>` with no surrounding padding. Now it's
   nested inside `<main class="main-content">`, which has
   `padding: 1.5rem 2rem` (confirmed identical in both repos) — 3rem of
   combined top+bottom padding pushes the total document height to
   `100vh + 3rem`, causing an unnecessary scrollbar on the login page.

## Scope

- `app/templates/base.html` (both repos): wrap the existing flash-render
  block in a new named block, `{% block flashes %}...{% endblock %}`, so
  a child template can override it to suppress the default (outside-card)
  rendering without needing any other structural change to `base.html`.
- `app/templates/login.html` (both repos): override `{% block flashes %}{% endblock %}`
  (empty — suppresses the base default), and render the exact same flash
  loop inside `.login-card`, right after the subtitle, matching the
  visual position each app's original standalone page used to have.
- `app/static/css/style.css` (both repos): change `.login-page`'s
  `min-height: 100vh` to `min-height: calc(100vh - 3rem)`, canceling out
  `.main-content`'s known 3rem of vertical padding exactly.

## Non-goals

- **Changing `.main-content`'s padding itself.** That padding is used
  consistently across every other page in both apps (dashboards, admin
  panels, etc.) — changing it to accommodate the login page specifically
  would be the wrong end of the fix. `calc(100vh - 3rem)` on the
  login-page-specific class is the targeted, non-disruptive fix.
- **Introducing a shared/vendored base template between the two repos.**
  Both apps deliberately keep independent template copies (matching the
  broader 4tSuite ecosystem's "no shared library between apps" design
  principle) — this fix is applied twice, once per repo, not factored
  into a shared dependency.
- **Any other page's flash rendering.** Only `login.html` overrides the
  new `{% block flashes %}` block; every other page keeps the default
  `base.html` behavior (flash above `{% block content %}`) unchanged.

## Implementation

### `app/templates/base.html` (both repos)

Change:

```html
<main class="main-content">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% for cat, msg in messages %}
    <div class="alert alert-{{ cat }}">{{ msg }}</div>
    {% endfor %}
  {% endwith %}
  {% block content %}{% endblock %}
</main>
```

to:

```html
<main class="main-content">
  {% block flashes %}
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% for cat, msg in messages %}
    <div class="alert alert-{{ cat }}">{{ msg }}</div>
    {% endfor %}
  {% endwith %}
  {% endblock %}
  {% block content %}{% endblock %}
</main>
```

### `app/templates/login.html` — 4tlog

Replace in full:

```html
{% extends "base.html" %}
{% block title %}Login — 4tlog{% endblock %}
{% block flashes %}{% endblock %}
{% block content %}
<div class="login-page">
  <div class="login-card">
    <h1 class="login-title">4tlog</h1>
    <p class="login-subtitle">FortiAnalyzer Log Search</p>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for cat, msg in messages %}
      <div class="alert alert-{{ cat }}">{{ msg }}</div>
      {% endfor %}
    {% endwith %}
    <form method="post" action="{{ url_for('auth.login') }}">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
      <div class="form-group">
        <label for="username">Username</label>
        <input type="text" class="form-control" id="username" name="username" autofocus required />
      </div>
      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" class="form-control" id="password" name="password" required />
      </div>
      <button type="submit" class="btn btn-primary btn-block">Log In</button>
    </form>
  </div>
</div>
{% endblock %}
```

### `app/templates/login.html` — 4thealth-plus

Replace in full:

```html
{% extends "base.html" %}
{% block title %}Login — 4THealth+{% endblock %}
{% block flashes %}{% endblock %}
{% block content %}
<div class="login-page">
  <div class="login-card">
    <h1 class="login-title">&#128274; 4THealth+</h1>
    <p class="login-subtitle">Network Operations Dashboard</p>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for cat, msg in messages %}
      <div class="alert alert-{{ cat }}">{{ msg }}</div>
      {% endfor %}
    {% endwith %}
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

### `app/static/css/style.css` (both repos)

Change:

```css
.login-page {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
}
```

to:

```css
.login-page {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: calc(100vh - 3rem);
}
```

## Error handling & edge cases

- **A page other than `login.html` extending `base.html`:** unaffected —
  none of them override `{% block flashes %}`, so Jinja renders the
  block's default content (the original unconditional flash render)
  exactly as before this change.
- **Multiple simultaneous flash messages on the login page:** unaffected
  — the loop logic is unchanged, just relocated inside `.login-card`.
- **The authenticated "zero tabs" case** (the scenario the no-tabs-parity
  fix introduced): the flash now correctly renders inside the card, below
  the subtitle, above the (still-rendered, matching that fix's own
  accepted non-goal) sign-in form — visually consistent with the
  anonymous-failure case this fix restores.

## Testing strategy

Per repo, one new test confirming the flash renders inside the card
(not above it in `<main>`), plus a scroll/height assertion is out of
scope for an HTTP-response-body test (no real browser/CSS engine in
`pytest` + Flask test client) — the CSS fix's correctness is verified by
inspection/diff review only, matching how the original conversion's own
CSS claims were verified in the prior plan's design spec.

**4tlog** (new file `tests/test_login_flash_placement.py`, modeled on
`tests/test_sso_login.py`'s existing fixture pattern):
- A flash message (e.g. from a failed local login) appears after
  `<div class="login-card">` and before `</div>` closing that same card
  — not before `<div class="login-card">` (which would mean it's still
  rendering in `base.html`'s default position, outside the card).

**4thealth-plus** (extend the existing `tests/test_login_no_tabs.py`,
which already has the JWT-minting/groups fixtures this needs):
- The existing `test_sso_login_with_zero_allowed_tabs_flashes_the_no_tabs_warning`
  test's assertion (`b"...no tabs assigned..." in response.data`) already
  passes regardless of *where* on the page the text appears — add one new,
  more specific test confirming it appears between the card's opening tag
  and the form, not before the card.

## Global constraints carried over from the no-tabs-ux-parity plan's conventions

- TDD throughout: every changed behavior gets a failing test before its
  implementation, in each repo independently.
- Each repo gets its own branch, its own commits, its own test run — no
  shared commit spans both repos (they're unrelated git histories).
- No dependency changes in either repo.
- Run tests with `uv run pytest tests/` from each repo's own root.
