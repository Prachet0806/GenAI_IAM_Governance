"""OIDC signature, issuer, audience, expiry, and required-claim checks."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from common import auth


def _keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_key


def test_oidc_access_token_validation_rejects_invalid_claims_and_signatures(monkeypatch):
    issuer = "https://issuer.example.test/"
    audience = "iam-governance-api"
    private_key, public_key = _keypair()
    other_private_key, _ = _keypair()
    monkeypatch.setenv("OIDC_ISSUER", issuer)
    monkeypatch.setenv("OIDC_AUDIENCE", audience)
    monkeypatch.setenv("OIDC_JWKS_URL", "https://issuer.example.test/.well-known/jwks.json")

    class FakeJwksClient:
        def get_signing_key_from_jwt(self, _token):
            return SimpleNamespace(key=public_key)

    monkeypatch.setattr(auth, "_jwks_client", lambda _url: FakeJwksClient())
    now = datetime.now(timezone.utc)
    valid = {
        "iss": issuer,
        "aud": audience,
        "sub": "reviewer-subject",
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }
    accepted = jwt.encode(valid, private_key, algorithm="RS256")
    assert auth.verify_access_token(accepted)["sub"] == "reviewer-subject"

    invalid_cases = []
    invalid_issuer = {**valid, "iss": "https://attacker.example.test/"}
    invalid_cases.append(jwt.encode(invalid_issuer, private_key, algorithm="RS256"))
    invalid_audience = {**valid, "aud": "another-api"}
    invalid_cases.append(jwt.encode(invalid_audience, private_key, algorithm="RS256"))
    expired = {**valid, "exp": now - timedelta(minutes=1)}
    invalid_cases.append(jwt.encode(expired, private_key, algorithm="RS256"))
    invalid_cases.append(jwt.encode(valid, other_private_key, algorithm="RS256"))
    for missing in ("iss", "aud", "sub", "exp"):
        missing_claim = {key: value for key, value in valid.items() if key != missing}
        invalid_cases.append(jwt.encode(missing_claim, private_key, algorithm="RS256"))

    for token in invalid_cases:
        with pytest.raises(auth.AuthenticationError):
            auth.verify_access_token(token)


def test_oidc_access_token_configuration_requires_https(monkeypatch):
    monkeypatch.setenv("OIDC_ISSUER", "http://issuer.example.test/")
    monkeypatch.setenv("OIDC_AUDIENCE", "iam-governance-api")
    monkeypatch.setenv("OIDC_JWKS_URL", "https://issuer.example.test/jwks")
    with pytest.raises(auth.AuthenticationError, match="HTTPS JWKS"):
        auth.verify_access_token("not-a-token")
