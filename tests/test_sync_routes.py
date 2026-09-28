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


def _mint(priv_pem, *, audience="4thealth-plus", issuer="4tsuite", scope="groups_push", sub="_service:4tsuite"):
    now = int(time.time())
    claims = {
        "sub": sub, "aud": audience, "iss": issuer, "scope": scope,
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

    groups_mod.create_group("operators", members=[], allowed_tabs=["dashboard"])

    from app import create_app

    app = create_app(test_config={"TESTING": True})
    app.config["_TEST_PRIV_KEY"] = priv_pem
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def _token(app):
    return _mint(app.config["_TEST_PRIV_KEY"])


def test_push_add_membership_without_a_prior_csrf_session_succeeds(app, client):
    """Proves the /4tsuite/ CSRF exemption works: no GET /login ever ran,
    so no CSRF session token exists -- if the exemption were missing this
    request would be rejected by the CSRF check before reaching the route."""
    response = client.post(
        "/4tsuite/groups",
        json={"group": "operators", "username": "dave", "member": True},
        headers={"Authorization": f"Bearer {_token(app)}"},
    )
    assert response.status_code == 204

    import app.groups as groups_mod
    assert groups_mod.get_group("operators")["members"] == ["dave"]


def test_push_remove_membership(app, client):
    import app.groups as groups_mod
    groups_mod.add_group_member("operators", "dave")

    response = client.post(
        "/4tsuite/groups",
        json={"group": "operators", "username": "dave", "member": False},
        headers={"Authorization": f"Bearer {_token(app)}"},
    )
    assert response.status_code == 204
    assert groups_mod.get_group("operators")["members"] == []


def test_push_without_a_valid_token_returns_403(client):
    response = client.post(
        "/4tsuite/groups",
        json={"group": "operators", "username": "dave", "member": True},
        headers={"Authorization": "Bearer not-a-real-token"},
    )
    assert response.status_code == 403


def test_push_rejects_a_login_token_lacking_the_groups_push_scope(app, client):
    login_token = jwt.encode(
        {
            "sub": "alice", "aud": "4thealth-plus", "iss": "4tsuite",
            "iat": int(time.time()), "nbf": int(time.time()), "exp": int(time.time()) + 300,
        },
        app.config["_TEST_PRIV_KEY"],
        algorithm="EdDSA",
    )
    response = client.post(
        "/4tsuite/groups",
        json={"group": "operators", "username": "dave", "member": True},
        headers={"Authorization": f"Bearer {login_token}"},
    )
    assert response.status_code == 403


def test_push_rejects_a_service_sentinel_username(app, client):
    response = client.post(
        "/4tsuite/groups",
        json={"group": "operators", "username": "_service:4tsuite", "member": True},
        headers={"Authorization": f"Bearer {_token(app)}"},
    )
    assert response.status_code == 400


def test_push_to_unknown_group_returns_400(app, client):
    response = client.post(
        "/4tsuite/groups",
        json={"group": "nonexistent", "username": "dave", "member": True},
        headers={"Authorization": f"Bearer {_token(app)}"},
    )
    assert response.status_code == 400
