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

    assert response.status_code != 401
    with client.session_transaction() as sess:
        assert sess.get("user") == "alice"
