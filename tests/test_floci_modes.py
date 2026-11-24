"""Source selection and endpoint isolation before any AWS-shaped call."""

import pytest

from common import aws_clients, config


@pytest.mark.parametrize("mock,seeded,expected", [
    ("false", "false", "FLOCI"),
    ("true", "false", "AWS"),
    ("false", "true", "MOCK"),
])
def test_source_mode(monkeypatch, mock, seeded, expected):
    monkeypatch.setenv("MOCK_IAM", mock)
    monkeypatch.setenv("SEEDED_IAM", seeded)
    assert config.iam_source_mode() == expected


def test_mutually_exclusive_modes(monkeypatch):
    monkeypatch.setenv("MOCK_IAM", "true")
    monkeypatch.setenv("SEEDED_IAM", "true")
    with pytest.raises(ValueError, match="cannot be combined"):
        config.iam_source_mode()


def test_floci_uses_fixed_credentials_and_local_endpoint(monkeypatch):
    monkeypatch.setenv("MOCK_IAM", "false")
    monkeypatch.setenv("SEEDED_IAM", "false")
    monkeypatch.setenv("FLOCI_ENDPOINT_URL", "http://127.0.0.1:4566")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "real-looking-credential")
    client = aws_clients.client("sts")
    assert client.meta.endpoint_url == "http://127.0.0.1:4566"
    assert client._request_signer._credentials.access_key == "test"


@pytest.mark.parametrize("endpoint", [
    "https://127.0.0.1:4566", "http://example.com:4566",
    "http://127.0.0.1:4566/other", "http://user:password@localhost:4566",
])
def test_floci_rejects_nonlocal_endpoint(monkeypatch, endpoint):
    monkeypatch.setenv("MOCK_IAM", "false")
    monkeypatch.setenv("SEEDED_IAM", "false")
    monkeypatch.setenv("FLOCI_ENDPOINT_URL", endpoint)
    with pytest.raises(ValueError, match="FLOCI_ENDPOINT_URL"):
        aws_clients.client("iam")


def test_floci_account_must_match_synthetic_account(monkeypatch):
    monkeypatch.setenv("MOCK_IAM", "false")
    monkeypatch.setenv("SEEDED_IAM", "false")
    monkeypatch.setenv("AWS_ACCOUNT_ID", "123456789012")
    monkeypatch.setenv("FLOCI_ACCOUNT_ID", "111111111111")
    with pytest.raises(ValueError, match="must match FLOCI_ACCOUNT_ID"):
        config.get_source_account_id()


def test_floci_sdk_blocked_in_staging(monkeypatch):
    monkeypatch.setenv("MOCK_IAM", "false")
    monkeypatch.setenv("SEEDED_IAM", "false")
    monkeypatch.setenv("APP_ENV", "staging")
    with pytest.raises(RuntimeError, match="disabled in staging"):
        aws_clients.client("iam")


def test_live_aws_rejects_endpoint_override(monkeypatch):
    monkeypatch.setenv("MOCK_IAM", "true")
    monkeypatch.setenv("SEEDED_IAM", "false")
    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:4566")
    with pytest.raises(ValueError, match="refuses configured endpoint"):
        aws_clients.client("sts")


def test_live_aws_uses_standard_endpoint_and_credentials(monkeypatch):
    monkeypatch.setenv("MOCK_IAM", "true")
    monkeypatch.setenv("SEEDED_IAM", "false")
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "local-test-key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "local-test-secret")
    client = aws_clients.client("sts")
    assert client.meta.endpoint_url.startswith("https://sts.")
    assert client._request_signer._credentials.access_key == "local-test-key"


def test_seeded_mode_never_constructs_client(monkeypatch):
    monkeypatch.setenv("MOCK_IAM", "false")
    monkeypatch.setenv("SEEDED_IAM", "true")
    with pytest.raises(RuntimeError, match="does not create"):
        aws_clients.client("iam")
