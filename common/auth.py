"""OIDC access-token validation for the reviewer API."""

import os
from functools import lru_cache
from urllib.parse import urlparse


class AuthenticationError(Exception):
    pass


class AuthorizationError(Exception):
    pass


@lru_cache(maxsize=4)
def _jwks_client(url: str):
    from jwt import PyJWKClient

    return PyJWKClient(url, cache_jwk_set=True, lifespan=300, timeout=5)


def verify_access_token(token: str) -> dict:
    issuer = os.getenv("OIDC_ISSUER", "").strip()
    audience = os.getenv("OIDC_AUDIENCE", "").strip()
    jwks_url = os.getenv("OIDC_JWKS_URL", "").strip()
    parsed = urlparse(jwks_url)
    issuer_url = urlparse(issuer)
    if (
        issuer_url.scheme != "https"
        or not issuer_url.netloc
        or not audience
        or parsed.scheme != "https"
        or not parsed.netloc
    ):
        raise AuthenticationError(
            "OIDC issuer, audience, and HTTPS JWKS URL must be configured"
        )
    try:
        import jwt

        signing_key = _jwks_client(jwks_url).get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256", "ES256"],
            audience=audience,
            issuer=issuer,
            options={"require": ["exp", "iss", "aud", "sub"]},
            leeway=30,
        )
        if not isinstance(claims.get("sub"), str) or not claims["sub"].strip():
            raise AuthenticationError("Token subject is invalid")
        return claims
    except AuthenticationError:
        raise
    except Exception:
        raise AuthenticationError("Access token validation failed") from None


def require_group(claims: dict, group_name: str, *, claim_name: str | None = None):
    if not group_name:
        raise AuthorizationError("Required reviewer group is not configured")
    key = claim_name or os.getenv("OIDC_GROUP_CLAIM", "groups")
    groups = claims.get(key, [])
    if isinstance(groups, str):
        groups = [groups]
    if not isinstance(groups, list) or group_name not in groups:
        raise AuthorizationError("Required group membership is missing")
