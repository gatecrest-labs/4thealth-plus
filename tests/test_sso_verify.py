import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.sso_verify import verify_service_token, verify_token


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


def _mint(priv_pem, *, audience="4thealth-plus", issuer="4tsuite", scope=None, sub="alice"):
    now = int(time.time())
    claims = {
        "sub": sub,
        "aud": audience,
        "iss": issuer,
        "iat": now,
        "nbf": now,
        "exp": now + 300,
    }
    if scope is not None:
        claims["scope"] = scope
    return jwt.encode(claims, priv_pem, algorithm="EdDSA")


@pytest.fixture
def keys(tmp_path, monkeypatch):
    priv_pem, pub_pem = _keypair()
    key_path = tmp_path / "sso_public_key.pem"
    key_path.write_bytes(pub_pem)
    monkeypatch.setattr("app.sso_verify.PUBLIC_KEY_PATH", key_path)
    return priv_pem


def test_verify_token_accepts_a_valid_login_token(keys):
    token = _mint(keys, sub="alice")
    assert verify_token(token) == "alice"


def test_verify_token_rejects_a_token_carrying_a_scope_claim(keys):
    token = _mint(keys, scope="groups_push")
    assert verify_token(token) is None


def test_verify_token_rejects_wrong_audience(keys):
    token = _mint(keys, audience="4texecutive")
    assert verify_token(token) is None


def test_verify_token_returns_none_when_public_key_file_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr("app.sso_verify.PUBLIC_KEY_PATH", tmp_path / "does-not-exist.pem")
    priv_pem, _ = _keypair()
    token = _mint(priv_pem)
    assert verify_token(token) is None


def test_verify_service_token_accepts_matching_scope(keys):
    token = _mint(keys, scope="groups_push", sub="_service:4tsuite")
    claims = verify_service_token(token, expected_scope="groups_push")
    assert claims is not None
    assert claims["scope"] == "groups_push"


def test_verify_service_token_rejects_wrong_scope(keys):
    token = _mint(keys, scope="groups_push", sub="_service:4tsuite")
    assert verify_service_token(token, expected_scope="something_else") is None


def test_verify_service_token_rejects_login_token_with_no_scope(keys):
    token = _mint(keys, sub="alice")
    assert verify_service_token(token, expected_scope="groups_push") is None
