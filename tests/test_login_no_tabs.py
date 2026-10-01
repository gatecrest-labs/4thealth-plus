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


def _get_csrf_token(client):
    """This app enforces a session-bound CSRF check on every POST
    (app/security.py::validate_csrf_request), unconditionally -- even
    under TESTING=True. A GET to /login calls ensure_csrf_token(), which
    seeds session["_csrf_token"]; read it back and pass it as the POST's
    csrf_token form field."""
    client.get("/login")
    with client.session_transaction() as sess:
        return sess["_csrf_token"]


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

    csrf_token = _get_csrf_token(client)
    response = client.post(
        "/login",
        data={"username": "bob", "password": "Sup3r!Secret123", "csrf_token": csrf_token},
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

    csrf_token = _get_csrf_token(client)
    response = client.post(
        "/login?next=/some/relative/path",
        data={"username": "carol", "password": "Sup3r!Secret123", "csrf_token": csrf_token},
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


def test_sso_login_with_zero_allowed_tabs_shows_the_authenticated_topbar(app, client):
    import app.groups as groups_mod

    groups_mod.create_group("no-tabs-group", members=["alice"], allowed_tabs=[])

    token = _mint(app.config["_TEST_PRIV_KEY"], sub="alice")
    response = client.get(f"/sso/login?token={token}", follow_redirects=True)

    assert response.status_code == 200
    assert b'<span class="nav-user">alice</span>' in response.data
    assert b'action="/logout"' in response.data


def test_anonymous_login_page_shows_no_authenticated_topbar(client):
    """Pins the base.html gating (`{% if session.get('user') %}`) this
    change now depends on: a visitor with no session at all must never
    see the topbar, regardless of how login.html itself is structured."""
    response = client.get("/login")

    assert response.status_code == 200
    assert b'class="topbar"' not in response.data
    assert b'action="/logout"' not in response.data


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
