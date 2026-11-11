"""OIDC access-token validation for the reviewer API."""

import os
import re
from functools import lru_cache
from urllib.parse import urlparse


class AuthenticationError(Exception):
    pass


class AuthorizationError(Exception):
    pass


def validate_account_scope_configuration() -> None:
    """Fail startup when a shared environment has no account boundary."""
    environment = os.getenv("APP_ENV", "").strip().lower()
    account_claim = os.getenv("OIDC_ACCOUNT_SCOPE_CLAIM", "").strip()
    if environment in {"staging", "production"} and not account_claim:
        raise RuntimeError(
            "OIDC_ACCOUNT_SCOPE_CLAIM must be configured in staging and production"
        )


def require_verified_reviewer_assignment() -> None:
    """Keep unverified subject entry out of shared environments until a directory is wired."""
    environment = os.getenv("APP_ENV", "").strip().lower()
    local_opt_in = (
        environment == "development"
        and os.getenv("OIDC_ALLOW_UNVERIFIED_REVIEWER_ASSIGNMENTS", "")
        .strip().lower() == "true"
    )
    if not local_opt_in:
        raise AuthorizationError(
            "Reviewer assignment requires identity-provider directory verification"
        )


def validate_account_scope_claim(claims: dict) -> None:
    """Reject authenticated API requests without a valid tenant-scope claim."""
    identity = identity_summary(claims)
    if identity["scope_mode"] == "unconfigured":
        raise AuthorizationError("A valid account-scope claim is required")


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
    if not has_group(claims, group_name, claim_name=claim_name):
        raise AuthorizationError("Required group membership is missing")


def has_group(claims: dict, group_name: str, *, claim_name: str | None = None) -> bool:
    if not group_name:
        return False
    key = claim_name or os.getenv("OIDC_GROUP_CLAIM", "groups")
    groups = claims.get(key, [])
    if isinstance(groups, str):
        groups = [groups]
    return isinstance(groups, list) and group_name in groups


def identity_summary(claims: dict) -> dict:
    """Return a safe, normalized identity/permission projection for the UI."""
    claim_name = os.getenv("OIDC_GROUP_CLAIM", "groups")
    raw_groups = claims.get(claim_name, [])
    if isinstance(raw_groups, str):
        groups = {raw_groups}
    elif isinstance(raw_groups, list) and all(isinstance(value, str) for value in raw_groups):
        groups = set(raw_groups)
    else:
        groups = set()
    role_groups = {
        "reviewer": os.getenv("REVIEWER_GROUP", ""),
        "campaign_admin": os.getenv("CAMPAIGN_ADMIN_GROUP", ""),
        "remediation_approver": os.getenv("REMEDIATION_APPROVER_GROUP", ""),
        "remediation_operator": os.getenv("REMEDIATION_OPERATOR_GROUP", ""),
        "auditor": os.getenv("AUDITOR_GROUP", ""),
    }
    roles = sorted(role for role, group in role_groups.items() if group and group in groups)
    permissions_by_role = {
        "reviewer": ["reviews:read_assigned", "reviews:decide"],
        "campaign_admin": ["campaigns:manage", "source_coverage:read", "ai_jobs:retry"],
        "remediation_approver": ["remediation:approve", "remediation:read"],
        "remediation_operator": ["remediation:reconcile", "remediation:read"],
        "auditor": ["audit:read", "exports:read"],
    }
    permissions = sorted({
        permission
        for role in roles
        for permission in permissions_by_role[role]
    })
    account_claim = os.getenv("OIDC_ACCOUNT_SCOPE_CLAIM", "").strip()
    environment = os.getenv("APP_ENV", "").strip().lower()
    global_scope_enabled = (
        environment == "development"
        and os.getenv("OIDC_ALLOW_GLOBAL_SCOPE", "").strip().lower() == "true"
    )
    account_scopes: list[str] = []
    scope_mode = "unconfigured"
    if account_claim:
        raw_scopes = claims.get(account_claim)
        values = [raw_scopes] if isinstance(raw_scopes, str) else raw_scopes
        if (
            isinstance(values, list)
            and values
            and all(isinstance(value, str) and value.strip() for value in values)
        ):
            normalized = [value.strip() for value in values]
            if (
                all(
                    value == "*" or re.fullmatch(r"\d{12}", value)
                    for value in normalized
                )
                and (
                    "*" not in normalized or len(normalized) == 1
                )
            ):
                account_scopes = sorted(set(normalized))
                scope_mode = "claim"
    elif global_scope_enabled:
        # Local development global access is an explicit operator opt-in.
        account_scopes = ["*"]
        scope_mode = "global_admin"
    return {
        "subject": claims["sub"],
        "display_name": claims.get("name") or claims.get("preferred_username") or "",
        "email": claims.get("email") or "",
        "roles": roles,
        "permissions": permissions,
        "account_scopes": account_scopes,
        "scope_mode": scope_mode,
    }


def require_account_scope(claims: dict, account_id: str | None):
    """Enforce claim scope, or an explicit development-only global-scope opt-in."""
    identity = identity_summary(claims)
    scopes = identity["account_scopes"] or []
    if not account_id and "*" not in scopes:
        raise AuthorizationError("Resource has no account scope")
    if "*" not in scopes and account_id not in scopes:
        raise AuthorizationError("AWS account is outside the authenticated user's scope")
