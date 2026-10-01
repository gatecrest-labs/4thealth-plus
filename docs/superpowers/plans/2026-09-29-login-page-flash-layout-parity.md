# Login Page Flash/Scroll Layout Fix Implementation Plan (dual-repo)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Flash/error messages on the login page render inside `.login-card` again (not full-width above it), and the login page no longer has extra scroll — in both 4tlog and 4thealth-plus, which share byte-for-byte identical `base.html`/CSS structure here.

**Architecture:** A new named Jinja block (`{% block flashes %}`) in `base.html` that `login.html` overrides to suppress the default flash position and re-render the same flashes inside the card instead. One CSS constant change (`min-height: 100vh` → `calc(100vh - 3rem)`) cancels out `.main-content`'s known padding. Two independent repos, two independent tasks — no shared code, no shared commit.

**Tech Stack:** Flask, Jinja2, pytest, uv (both repos).

**Spec:** `docs/superpowers/specs/2026-09-29-login-page-flash-layout-parity-design.md` (this file's own repo, 4thealth-plus — the spec covers both repos; read it once, it applies to both tasks below)

## Global Constraints

- TDD throughout: every changed behavior gets a failing test before its implementation, independently in each repo.
- Each repo gets its own branch, its own commits — never mix commits across the two repos.
- No dependency changes in either repo.
- Only `login.html` overrides the new `{% block flashes %}` — every other template keeps `base.html`'s default (unconditional, pre-`{% block content %}`) flash rendering unchanged.
- Run tests with `uv run pytest tests/` from each repo's own root.

## Review Focus

- **A flash triggered by a failed local login must render inside `.login-card`, not before it** — the most common real-world trigger of this bug (wrong password), and the one a person would notice first.
- **Every other page that extends `base.html` (dashboards, admin panels, etc.) must keep showing flashes in their original position** — only `login.html` should behave differently after this change. This is verified by construction, not by a new test: Jinja's block-inheritance means any template that does not itself declare `{% block flashes %}` automatically renders the parent's default content unchanged (the same reasoning already applies to the CSS `min-height` fix below, verified by review rather than an automated test, since neither pytest nor the Flask test client executes CSS/layout). No other template in either repo is touched by this plan, so none can have acquired an override — confirmed by `grep -rn "block flashes" app/templates/` returning only `login.html` after Task 1/2 Step 4, which each task's Step 6/7 full-suite run implicitly re-confirms (a stray override elsewhere would change some other page's rendered flash position and surface as a failure in that page's own existing tests, if any exist).
- **The CSS fix must exactly cancel `.main-content`'s padding, not overshoot or undershoot it** — confirmed identical `padding: 1.5rem 2rem` (3rem total vertical) in both repos before writing `calc(100vh - 3rem)`.
- **4tlog and 4thealth-plus must end up with the same net effect even though their `login.html` files have different visible text/attributes** — the fix is structural (block override + flash relocation), not a copy-paste of one app's exact file into the other.
- **A page with no flash messages at all must render identically to before** — an empty `{% block flashes %}{% endblock %}` on `login.html` plus an empty flash loop inside the card must produce no stray empty `<div>` or extra whitespace that changes the page's visual baseline when nothing is flashed.

---

## Task 1: 4tlog — flash block + CSS fix

**Repo:** `~/code/github/web/4tlog`

**Files:**
- Modify: `app/templates/base.html`
- Modify: `app/templates/login.html`
- Modify: `app/static/css/style.css`
- Test: `tests/test_login_flash_placement.py` (new file)

**Interfaces:**
- Consumes: nothing new — this is a template/CSS-only change.
- Produces: nothing consumed elsewhere.

- [ ] **Step 1: Write the failing test**

Create `tests/test_login_flash_placement.py`, modeled on
`tests/test_auth_routes.py`'s existing `app`/`client` fixtures and
`_csrf` helper:

```python
import os

import pytest


@pytest.fixture
def app(tmp_path, monkeypatch):
    os.environ.setdefault("SECRET_KEY", "test-secret")
    import app.auth as auth_mod
    import app.groups as groups_mod

    monkeypatch.setattr(auth_mod, "USERS_FILE", tmp_path / "users.json")
    monkeypatch.setattr(groups_mod, "GROUPS_FILE", tmp_path / "groups.json")
    auth_mod.add_user("alice", "Str0ng!Passw0rd", role="admin")

    from app import create_app

    return create_app()


@pytest.fixture
def client(app):
    return app.test_client()


def _csrf(client):
    client.get("/login")
    with client.session_transaction() as sess:
        return sess.get("_csrf_token", "")


def test_flash_message_renders_inside_the_login_card_not_above_it(client):
    csrf = _csrf(client)
    response = client.post(
        "/login",
        data={"username": "alice", "password": "wrong", "csrf_token": csrf},
    )

    html = response.data.decode()
    assert response.status_code == 401
    card_start = html.index('<div class="login-card">')
    flash_pos = html.index('class="alert alert-danger"')
    card_end = html.index("</form>", card_start)  # form is always after the flash, inside the card
    assert card_start < flash_pos < card_end


def test_login_page_with_no_flash_has_no_alert_div(client):
    response = client.get("/login")

    assert response.status_code == 200
    assert b'class="alert' not in response.data
```

- [ ] **Step 2: Run tests to verify the first one fails**

Run: `uv run pytest tests/test_login_flash_placement.py -v`
Expected: `test_flash_message_renders_inside_the_login_card_not_above_it` FAILS
— the flash currently renders in `<main>`, before `<div class="login-card">`
even appears in the HTML, so `html.index('<div class="login-card">')`
succeeds but the flash's position relative to it is wrong (it comes
*before* `card_start`, not after) — the test's own `assert card_start <
flash_pos` catches this as a failure, not an exception. Confirm the
failure message shows `flash_pos < card_start` is true (i.e. the
assertion fails because flash comes first). `test_login_page_with_no_flash_has_no_alert_div`
PASSES already (nothing flashed, nothing to fail on).

- [ ] **Step 3: Implement the `base.html` block wrap**

In `app/templates/base.html`, change:

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

- [ ] **Step 4: Implement the `login.html` override**

Replace `app/templates/login.html` in full:

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

- [ ] **Step 5: Implement the CSS fix**

In `app/static/css/style.css`, change:

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

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/test_login_flash_placement.py -v`
Expected: both tests pass.

- [ ] **Step 7: Run the full test suite to check for regressions**

Run: `uv run pytest tests/ -v`
Expected: all tests pass, no regressions (this only adds a Jinja block
level and relocates a flash loop; no route/Python logic changed).

- [ ] **Step 8: Commit**

```bash
git add app/templates/base.html app/templates/login.html app/static/css/style.css tests/test_login_flash_placement.py
git commit -m "fix: render login page flashes inside the card, fix extra scroll

base.html's flash block now renders inside login.html's login-card
instead of full-width above it, and the login-page's min-height
accounts for main-content's padding so the page no longer scrolls
unnecessarily.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018JZiidWvgesrS69oyaXw41"
```

---

## Task 2: 4thealth-plus — flash block + CSS fix

**Repo:** this repo (4thealth-plus)

**Files:**
- Modify: `app/templates/base.html`
- Modify: `app/templates/login.html`
- Modify: `app/static/css/style.css`
- Test: `tests/test_login_no_tabs.py` (extended — already has the fixtures this needs)

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing consumed elsewhere.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_login_no_tabs.py` (the file already has `_get_csrf_token`,
`app`/`client` fixtures, and `app.auth`/`app.groups` imports established):

```python
def test_flash_message_renders_inside_the_login_card_not_above_it(app, client):
    import app.auth as auth_mod

    auth_mod.add_user("dave", "Sup3r!Secret123", role="viewer")
    csrf_token = _get_csrf_token(client)

    response = client.post(
        "/login",
        data={"username": "dave", "password": "wrong-password", "csrf_token": csrf_token},
    )

    html = response.data.decode()
    assert response.status_code == 401
    card_start = html.index('<div class="login-card">')
    flash_pos = html.index('class="alert alert-danger"')
    card_end = html.index("</form>", card_start)
    assert card_start < flash_pos < card_end


def test_login_page_with_no_flash_has_no_alert_div(client):
    response = client.get("/login")

    assert response.status_code == 200
    assert b'class="alert' not in response.data
```

- [ ] **Step 2: Run tests to verify the first one fails**

Run: `uv run pytest tests/test_login_no_tabs.py::test_flash_message_renders_inside_the_login_card_not_above_it -v`
Expected: FAIL — the flash currently renders in `<main>`, before
`<div class="login-card">`, so `flash_pos < card_start`, failing the
`card_start < flash_pos` assertion (not an exception).

Run: `uv run pytest tests/test_login_no_tabs.py::test_login_page_with_no_flash_has_no_alert_div -v`
Expected: PASSES already.

- [ ] **Step 3: Implement the `base.html` block wrap**

In `app/templates/base.html`, change:

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

- [ ] **Step 4: Implement the `login.html` override**

Replace `app/templates/login.html` in full:

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

- [ ] **Step 5: Implement the CSS fix**

In `app/static/css/style.css`, change:

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

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/test_login_no_tabs.py -v`
Expected: all 8 tests in this file pass (6 pre-existing + 2 new).

- [ ] **Step 7: Run the full test suite to check for regressions**

Run: `uv run pytest tests/ -q`
Expected: all tests pass except the already-known,
pre-existing-and-unrelated `tests/test_pending_status_cache.py::test_get_cache_status_initial`
environmental flake (documented in this repo's git history as unrelated
to the no-tabs-assigned UX work — only reproduces when run against a
checkout with real accumulated collector snapshot data, not in a clean
worktree). If running in a clean worktree (no such ambient data), that
test should also pass and the suite should be 100% green.

- [ ] **Step 8: Commit**

```bash
git add app/templates/base.html app/templates/login.html app/static/css/style.css tests/test_login_no_tabs.py
git commit -m "fix: render login page flashes inside the card, fix extra scroll

base.html's flash block now renders inside login.html's login-card
instead of full-width above it, and the login-page's min-height
accounts for main-content's padding so the page no longer scrolls
unnecessarily. Mirrors the identical fix applied to 4tlog.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_018JZiidWvgesrS69oyaXw41"
```
