"""One explicit endpoint and credential boundary for AWS-shaped service calls."""

import json
import os
from urllib.parse import urlparse
from urllib.request import urlopen

import boto3
from botocore.config import Config as BotoConfig

from common import config


def _floci_endpoint() -> str:
    endpoint = config.get_floci_endpoint_url().rstrip("/")
    parsed = urlparse(endpoint)
    if (parsed.scheme != "http" or parsed.hostname not in
            {"localhost", "127.0.0.1", "floci"}
            or not parsed.port or parsed.path or parsed.query or parsed.fragment
            or parsed.username or parsed.password):
        raise ValueError("FLOCI_ENDPOINT_URL must be an HTTP loopback or floci service endpoint")
    return endpoint


def assert_floci_ready() -> dict:
    """Confirm a healthy Floci AWS endpoint before collecting or mutating IAM."""
    endpoint = _floci_endpoint()
    with urlopen(f"{endpoint}/_floci/health", timeout=3) as response:
        health = json.load(response)
    with urlopen(f"{endpoint}/_floci/info", timeout=3) as response:
        info = json.load(response)
    if (info.get("cloud") != "aws"
            or health.get("version") != info.get("version")
            or health.get("services", {}).get("iam") != "running"
            or health.get("status", "UP") != "UP"):
        raise RuntimeError("The local endpoint is not a ready Floci AWS emulator")
    return health


def client(service: str, *, client_config: BotoConfig | None = None):
    """Construct a service client without inheriting real credentials in Floci mode."""
    mode = config.iam_source_mode()
    if mode == "MOCK":
        raise RuntimeError("Seeded IAM mode does not create AWS service clients")
    base = client_config or BotoConfig()
    if mode == "FLOCI":
        if os.getenv("APP_ENV", "").strip().lower() in {"staging", "production"}:
            raise RuntimeError("Floci clients are disabled in staging and production")
        session = boto3.Session(
            aws_access_key_id="test", aws_secret_access_key="test",
            region_name=config.get_aws_region(),
        )
        return session.client(service, endpoint_url=_floci_endpoint(), config=base)
    overrides = [key for key in os.environ if key.startswith("AWS_ENDPOINT_URL")]
    if overrides:
        raise ValueError("Live AWS mode refuses configured endpoint overrides")
    session = boto3.Session(
        profile_name=config.get_aws_profile() or None,
        region_name=config.get_aws_region(),
    )
    return session.client(
        service,
        config=base.merge(BotoConfig(ignore_configured_endpoint_urls=True)),
    )
