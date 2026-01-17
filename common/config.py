import os
from urllib.parse import urlparse


def _get_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).lower() in ("1", "true", "yes", "y", "on")


# Core configuration
DB_URL = os.getenv("DB_URL", "sqlite:///iam_governance.db")
AWS_REGION = os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "us-east-1"))
MOCK_IAM = _get_bool("MOCK_IAM", False)
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Remediation safety
DRY_RUN = _get_bool("DRY_RUN", True)
ENABLE_REMEDIATION = _get_bool("ENABLE_REMEDIATION", False)
ALLOWLIST = {
    item.strip().lower()
    for item in os.getenv("REMEDIATION_ALLOWLIST", "").split(",")
    if item.strip()
}
DENYLIST = {
    item.strip().lower()
    for item in os.getenv("REMEDIATION_DENYLIST", "").split(",")
    if item.strip()
}
if not DENYLIST:
    DENYLIST.update({"administratoraccess", "breakglass", "break-glass"})

# Audit export
AUDIT_S3_BUCKET = os.getenv("AUDIT_S3_BUCKET")
AUDIT_S3_PREFIX = os.getenv("AUDIT_S3_PREFIX", "")
LOCAL_ONLY = _get_bool("LOCAL_ONLY", False)

# Schema/versioning
SCHEMA_VERSION = "2026-01-phase2"


def _parsed_db_url():
    # urlparse handles sqlite:///path
    return urlparse(DB_URL)


def db_is_sqlite() -> bool:
    parsed = _parsed_db_url()
    return parsed.scheme in ("sqlite", "") or DB_URL.endswith(".db")


def get_sqlite_path() -> str:
    """
    Resolve the SQLite file path from DB_URL. Defaults to iam_governance.db.
    """
    parsed = _parsed_db_url()
    if parsed.scheme not in ("sqlite", "") and not DB_URL.endswith(".db"):
        raise ValueError("DB_URL is not SQLite; cannot derive path.")
    path = parsed.path
    if not path or path == "/":
        path = "iam_governance.db"
    if path.startswith("/"):
        path = path[1:] if parsed.scheme == "sqlite" else path
    return os.path.abspath(path)


def require_sqlite_path() -> str:
    if not db_is_sqlite():
        raise ValueError("Only SQLite is supported in this execution path.")
    return get_sqlite_path()

