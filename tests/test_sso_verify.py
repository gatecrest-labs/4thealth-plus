import base64
import datetime
import hashlib
import json
import time

import jwt
import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed448, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import sso_verify
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


def test_verify_token_returns_none_when_public_key_path_is_a_directory(tmp_path, monkeypatch):
    """Regression test: when this app runs standalone (no 4tSuite
    integration configured), docker-compose's bind mount for this path has
    no host file to mount and Docker substitutes an empty directory instead
    of leaving the path absent. This must fail closed the same as a
    genuinely missing file, not raise IsADirectoryError."""
    key_path = tmp_path / "sso_public_key.pem"
    key_path.mkdir()
    monkeypatch.setattr("app.sso_verify.PUBLIC_KEY_PATH", key_path)
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


def _new_key():
    private = Ed25519PrivateKey.generate()
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, public_pem


def _token(private, sub="alice"):
    now = datetime.datetime.now(datetime.UTC)
    return jwt.encode(
        {
            "sub": sub,
            "aud": sso_verify.APP_ID,
            "iss": "4tsuite",
            "iat": now,
            "nbf": now,
            "exp": now + datetime.timedelta(minutes=5),
        },
        private,
        algorithm="EdDSA",
    )


def test_bundle_verifies_a_token_signed_by_either_key(tmp_path, monkeypatch):
    (k1, p1), (k2, p2) = _new_key(), _new_key()
    bundle = tmp_path / "sso_public_key.pem"
    bundle.write_bytes(p1 + p2)
    monkeypatch.setattr(sso_verify, "PUBLIC_KEY_PATH", bundle)
    assert sso_verify.verify_token(_token(k1)) == "alice"
    assert sso_verify.verify_token(_token(k2)) == "alice"


def test_token_from_a_key_not_in_the_file_fails(tmp_path, monkeypatch):
    (_, p1), (k2, _) = _new_key(), _new_key()
    only_first = tmp_path / "sso_public_key.pem"
    only_first.write_bytes(p1)
    monkeypatch.setattr(sso_verify, "PUBLIC_KEY_PATH", only_first)
    assert sso_verify.verify_token(_token(k2)) is None


def test_single_pem_file_still_works(tmp_path, monkeypatch):
    k, p = _new_key()
    single = tmp_path / "sso_public_key.pem"
    single.write_bytes(p)
    monkeypatch.setattr(sso_verify, "PUBLIC_KEY_PATH", single)
    assert sso_verify.verify_token(_token(k)) == "alice"


def test_empty_or_missing_key_file_fails_closed(tmp_path, monkeypatch):
    k, _ = _new_key()
    empty = tmp_path / "empty.pem"
    empty.write_bytes(b"")
    for path in (empty, tmp_path / "missing.pem"):
        monkeypatch.setattr(sso_verify, "PUBLIC_KEY_PATH", path)
        assert sso_verify.verify_token(_token(k)) is None


def test_garbage_key_file_fails_closed(tmp_path, monkeypatch):
    k, _ = _new_key()
    junk = tmp_path / "junk.pem"
    junk.write_bytes(
        b"-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----\n"
    )
    monkeypatch.setattr(sso_verify, "PUBLIC_KEY_PATH", junk)
    assert sso_verify.verify_token(_token(k)) is None


def test_directory_at_key_path_fails_closed(tmp_path, monkeypatch):
    # Docker bind-mounts an empty directory when the host file is absent.
    k, _ = _new_key()
    directory = tmp_path / "sso_public_key.pem"
    directory.mkdir()
    monkeypatch.setattr(sso_verify, "PUBLIC_KEY_PATH", directory)
    assert sso_verify.verify_token(_token(k)) is None


def _kid(private):
    raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return hashlib.sha256(raw).hexdigest()[:16]


def _token_with(private, headers=None, exp_delta=datetime.timedelta(minutes=5)):
    now = datetime.datetime.now(datetime.UTC)
    return jwt.encode(
        {
            "sub": "alice",
            "aud": sso_verify.APP_ID,
            "iss": "4tsuite",
            "iat": now,
            "nbf": now,
            "exp": now + exp_delta,
        },
        private,
        algorithm="EdDSA",
        headers=headers,
    )


def _use(tmp_path, monkeypatch, *pems):
    path = tmp_path / "sso_public_key.pem"
    path.write_bytes(b"".join(pems))
    monkeypatch.setattr(sso_verify, "PUBLIC_KEY_PATH", path)


def _pem(public_key):
    return public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def test_kid_selects_key_and_wrong_signature_does_not_fall_through(
    tmp_path, monkeypatch
):
    (ka, pa), (kb, pb) = _new_key(), _new_key()
    _use(tmp_path, monkeypatch, pa, pb)
    forged = _token_with(kb, headers={"kid": _kid(ka)})
    assert sso_verify.verify_token(forged) is None


def test_correct_kid_verifies(tmp_path, monkeypatch):
    (_, pa), (kb, pb) = _new_key(), _new_key()
    _use(tmp_path, monkeypatch, pa, pb)
    assert (
        sso_verify.verify_token(_token_with(kb, headers={"kid": _kid(kb)})) == "alice"
    )


def test_unknown_kid_falls_back_to_every_key(tmp_path, monkeypatch):
    (_, pa), (kb, pb) = _new_key(), _new_key()
    _use(tmp_path, monkeypatch, pa, pb)
    token = _token_with(kb, headers={"kid": "0123456789abcdef"})
    assert sso_verify.verify_token(token) == "alice"


def test_expired_token_with_correct_kid_fails(tmp_path, monkeypatch):
    k, p = _new_key()
    _use(tmp_path, monkeypatch, p)
    token = _token_with(
        k, headers={"kid": _kid(k)}, exp_delta=datetime.timedelta(minutes=-10)
    )
    assert sso_verify.verify_token(token) is None


def _hand_signed(private, header):
    # PyJWT refuses to *encode* a non-string kid, so build the JWS by hand.
    def b64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=")

    now = int(datetime.datetime.now(datetime.UTC).timestamp())
    payload = {
        "sub": "alice",
        "aud": sso_verify.APP_ID,
        "iss": "4tsuite",
        "iat": now,
        "nbf": now,
        "exp": now + 300,
    }
    signing_input = (
        b64(json.dumps({"alg": "EdDSA", "typ": "JWT", **header}).encode())
        + b"."
        + b64(json.dumps(payload).encode())
    )
    return (signing_input + b"." + b64(private.sign(signing_input))).decode()


def test_non_string_kid_header_never_raises(tmp_path, monkeypatch):
    # Depending on PyJWT, a non-string kid is either rejected up front (None)
    # or treated as absent (verifies via fallback). It must never raise.
    k, p = _new_key()
    _use(tmp_path, monkeypatch, p)
    for bad in (["a"], {"a": 1}, 7, None):
        token = _hand_signed(k, {"kid": bad})
        assert sso_verify.verify_token(token) in ("alice", None)


def test_rsa_block_is_skipped_in_a_bundle(tmp_path, monkeypatch):
    rsa_pub = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    ).public_key()
    k, p = _new_key()
    _use(tmp_path, monkeypatch, _pem(rsa_pub), p)
    assert sso_verify.verify_token(_token(k)) == "alice"


def test_rsa_only_bundle_fails_closed(tmp_path, monkeypatch):
    rsa_pub = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    ).public_key()
    k, _ = _new_key()
    _use(tmp_path, monkeypatch, _pem(rsa_pub))
    assert sso_verify.verify_token(_token(k)) is None


def test_ed448_block_does_not_break_the_bundle(tmp_path, monkeypatch):
    ed448_pub = ed448.Ed448PrivateKey.generate().public_key()
    (k, p), (other, _) = _new_key(), _new_key()
    _use(tmp_path, monkeypatch, _pem(ed448_pub), p)
    assert sso_verify.verify_token(_token(k)) == "alice"
    assert sso_verify.verify_token(_token(other)) is None


def test_list_kid_from_a_lenient_pyjwt_falls_back_without_raising(
    tmp_path, monkeypatch
):
    # Simulates a PyJWT that returns whatever the header holds: an unhashable
    # kid must be treated as absent, not blow up the dict lookup.
    k, p = _new_key()
    _use(tmp_path, monkeypatch, p)
    monkeypatch.setattr(
        sso_verify.jwt, "get_unverified_header", lambda token: {"kid": ["a"]}
    )
    assert sso_verify.verify_token(_token(k)) == "alice"


def test_key_parser_errors_skip_the_block(tmp_path, monkeypatch):
    k, p = _new_key()
    _use(tmp_path, monkeypatch, p)
    for exc in (UnsupportedAlgorithm("nope"), TypeError("odd")):

        def boom(block, exc=exc):
            raise exc

        monkeypatch.setattr(sso_verify.serialization, "load_pem_public_key", boom)
        assert sso_verify.verify_token(_token(k)) is None


def test_other_pyjwt_errors_fail_closed(tmp_path, monkeypatch):
    k, p = _new_key()
    _use(tmp_path, monkeypatch, p)

    def boom(*args, **kwargs):
        raise jwt.exceptions.InvalidKeyError("bad key")

    monkeypatch.setattr(sso_verify.jwt, "decode", boom)
    assert sso_verify.verify_token(_token(k)) is None
