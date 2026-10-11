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
    import app.groups as groups_mod
    import app.sso_verify as sso_mod

    monkeypatch.setattr(groups_mod, "GROUPS_FILE", tmp_path / "groups.json")
    priv_pem, pub_pem = _keypair()
    key_path = tmp_path / "sso_public_key.pem"
    key_path.write_bytes(pub_pem)
    monkeypatch.setattr(sso_mod, "PUBLIC_KEY_PATH", key_path)

    groups_mod.create_group("operators", members=["alice"], allowed_tabs=["dashboard"])

    from app import create_app

    app = create_app(test_config={"TESTING": True})
    app.config["_TEST_PRIV_KEY"] = priv_pem
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def test_sso_login_with_valid_token_establishes_session(app, client):
    token = _mint(app.config["_TEST_PRIV_KEY"], sub="alice")
    response = client.get(f"/sso/login?token={token}", follow_redirects=False)
    assert response.status_code == 302
    with client.session_transaction() as sess:
        assert sess["user"] == "alice"
        assert sess["role"] == "sso"
        assert "dashboard" in sess["allowed_tabs"]


def test_sso_login_with_invalid_token_returns_403(client):
    response = client.get("/sso/login?token=not-a-real-token")
    assert response.status_code == 403


def test_sso_login_with_wrong_audience_returns_403(app, client):
    token = _mint(app.config["_TEST_PRIV_KEY"], audience="4texecutive", sub="alice")
    response = client.get(f"/sso/login?token={token}")
    assert response.status_code == 403


def test_sso_login_does_not_establish_a_session_on_failure(client):
    client.get("/sso/login?token=garbage")
    with client.session_transaction() as sess:
        assert "user" not in sess


def test_sso_session_survives_a_second_authenticated_request(app, client):
    """Regression test for app/decorators.py::_revalidate_session(): a
    session for a username absent from users.json (true for any SSO-only
    user) is cleared and the request rejected (401 for /api/ paths) unless
    session["role"] is truthy. A session["role"] = None mistake would pass
    the first request (the redirect) and only fail on this second one.

    Uses GET /api/summary (tab_required("dashboard"), matching the
    "operators" group's allowed_tabs set up in the app fixture above) as
    a real, already-existing tab_required-gated route -- confirm during
    implementation that this route's own view body doesn't need
    fixtures/mocking beyond what this test provides; swap to another
    tab_required("dashboard") route under app/routes/api_routes.py if it
    does. The revalidation check this test targets always runs before the
    view body, so even a view-body failure would surface as a 500, never
    the 401 this test asserts against."""
    token = _mint(app.config["_TEST_PRIV_KEY"], sub="alice")
    client.get(f"/sso/login?token={token}")

    response = client.get("/api/summary")

    assert response.status_code == 200
    with client.session_transaction() as sess:
        assert sess.get("user") == "alice"


BANNER = "Your account has no tabs assigned. Contact an administrator."


def test_zero_grant_sso_user_lands_on_no_access_page_with_banner(app, client):
    token = _mint(app.config["_TEST_PRIV_KEY"], sub="mallory")
    response = client.get(f"/sso/login?token={token}", follow_redirects=True)
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert BANNER in body
    assert "mallory" in body  # nav shows the signed-in user
    assert "/logout" in body  # working logout form


def test_zero_grant_sso_user_hitting_root_is_not_given_a_bare_403(app, client):
    token = _mint(app.config["_TEST_PRIV_KEY"], sub="mallory")
    client.get(f"/sso/login?token={token}")
    response = client.get("/", follow_redirects=True)
    assert response.status_code == 200
    assert BANNER in response.get_data(as_text=True)


def test_zero_grant_user_still_cannot_reach_real_tabs(app, client):
    token = _mint(app.config["_TEST_PRIV_KEY"], sub="mallory")
    client.get(f"/sso/login?token={token}")
    for path in ("/firewalls", "/versions"):
        response = client.get(path, follow_redirects=False)
        assert response.status_code in (302, 403), path
        if response.status_code == 302:
            assert "/no-access" in response.headers["Location"] or "/login" in response.headers["Location"]


def test_no_access_page_requires_a_session(client):
    response = client.get("/no-access", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


# ---------------------------------------------------------------------------
# 4tSuite revocation of SSO-established sessions
# ---------------------------------------------------------------------------


def _login_sso(app, client, sub="alice"):
    client.get(f"/sso/login?token={_mint(app.config['_TEST_PRIV_KEY'], sub=sub)}")


def _explode(username, login_at):
    raise AssertionError("checker must not run for sessions without sso_login_at")


def _local_login(app, client, monkeypatch, username="alice"):
    monkeypatch.setattr(
        "app.routes.auth_routes.authenticate", lambda u, p: ("viewer", [])
    )
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "t"
    response = client.post(
        "/login",
        data={"username": username, "password": "pw", "csrf_token": "t"},
        follow_redirects=False,
    )
    assert response.status_code == 302


def test_sso_login_records_login_time(app, client):
    _login_sso(app, client)
    with client.session_transaction() as sess:
        assert isinstance(sess["sso_login_at"], float)


def test_revoked_sso_session_is_cleared(app, client):
    state = {"valid": True}
    app.extensions["tsuite_session_checker"] = lambda u, t: state["valid"]
    _login_sso(app, client)
    assert client.get("/", follow_redirects=False).status_code == 200
    state["valid"] = False
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
    with client.session_transaction() as sess:
        assert "user" not in sess


def test_revoked_sso_session_gets_401_on_api(app, client):
    app.extensions["tsuite_session_checker"] = lambda u, t: False
    _login_sso(app, client)
    response = client.get("/api/summary")
    assert response.status_code == 401
    assert response.get_json()["error"] == "Not authenticated"


def test_checker_receives_username_and_login_time(app, client):
    seen = []
    app.extensions["tsuite_session_checker"] = lambda u, t: seen.append((u, t)) or True
    _login_sso(app, client)
    client.get("/")
    assert seen and seen[0][0] == "alice" and isinstance(seen[0][1], float)


def test_no_checker_leaves_sso_sessions_alone(app, client):
    app.extensions["tsuite_session_checker"] = None
    _login_sso(app, client)
    assert client.get("/", follow_redirects=False).status_code == 200


def test_local_session_is_never_checked(app, client):
    app.extensions["tsuite_session_checker"] = _explode
    with client.session_transaction() as sess:
        sess["user"] = "alice"
        sess["role"] = "sso"
        sess["ad_groups"] = []
        sess["login_at"] = int(time.time())
    assert client.get("/", follow_redirects=False).status_code == 200


def test_sso_then_logout_then_local_login_is_never_checked(app, client, monkeypatch):
    _login_sso(app, client)
    with client.session_transaction() as sess:
        assert "sso_login_at" in sess
        sess["_csrf_token"] = "t"
    assert (
        client.post("/logout", data={"csrf_token": "t"}).status_code == 302
    )
    _local_login(app, client, monkeypatch)
    with client.session_transaction() as sess:
        assert sess["user"] == "alice"
        assert "sso_login_at" not in sess
    app.extensions["tsuite_session_checker"] = _explode
    assert client.get("/", follow_redirects=False).status_code == 200


def test_sso_then_direct_local_login_drops_sso_marker(app, client, monkeypatch):
    _login_sso(app, client)
    _local_login(app, client, monkeypatch)
    with client.session_transaction() as sess:
        assert sess["user"] == "alice"
        assert "sso_login_at" not in sess
    app.extensions["tsuite_session_checker"] = _explode
    assert client.get("/", follow_redirects=False).status_code == 200
