"""Explicit local-only identity assumptions for isolated unit/integration tests."""

import pytest


@pytest.fixture(autouse=True)
def local_identity_test_configuration(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.delenv("OIDC_ACCOUNT_SCOPE_CLAIM", raising=False)
    monkeypatch.setenv("OIDC_ALLOW_GLOBAL_SCOPE", "true")
    monkeypatch.setenv("OIDC_ALLOW_UNVERIFIED_REVIEWER_ASSIGNMENTS", "true")
