#common/config.py
import os
import re
from urllib.parse import urlparse


def _get_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).lower() in ("1", "true", "yes", "y", "on")


def _get_str(name: str, default: str = "") -> str:
    return os.getenv(name, default)


def _parse_list(name: str) -> set:
    return {
        item.strip().lower()
        for item in os.getenv(name, "").split(",")
        if item.strip()
    }


# Core configuration (import-time snapshots kept for backwards compat)
DB_URL = os.getenv("DB_URL", "sqlite:///iam_governance.db")
AWS_REGION = os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "us-east-1"))
AWS_PROFILE = os.getenv("AWS_PROFILE")
MOCK_IAM = _get_bool("MOCK_IAM", False)
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Remediation safety (snapshots; prefer runtime getters below)
DRY_RUN = _get_bool("DRY_RUN", True)
ENABLE_REMEDIATION = _get_bool("ENABLE_REMEDIATION", False)
ALLOWLIST = _parse_list("REMEDIATION_ALLOWLIST")
DENYLIST = _parse_list("REMEDIATION_DENYLIST")
if not DENYLIST:
    DENYLIST.update({"administratoraccess", "breakglass", "break-glass"})

# Audit export
AUDIT_S3_BUCKET = os.getenv("AUDIT_S3_BUCKET")
AUDIT_S3_PREFIX = os.getenv("AUDIT_S3_PREFIX", "")
LOCAL_ONLY = _get_bool("LOCAL_ONLY", False)

# GenAI
GENAI_MODEL = os.getenv("GENAI_MODEL", "gemini-3.8-flash")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

# Schema/versioning
SCHEMA_VERSION = "2026-10-p1-1"


# --- Runtime getters (avoid import-time freezing for Lambda) ---
def is_mock_iam() -> bool:
    return _get_bool("MOCK_IAM", False)


def is_dry_run() -> bool:
    return _get_bool("DRY_RUN", True)


def is_remediation_enabled() -> bool:
    return _get_bool("ENABLE_REMEDIATION", False)


def is_live_remediation_explicitly_allowed() -> bool:
    return _get_bool("ALLOW_LIVE_REMEDIATION", False)


def get_max_discovery_age_hours() -> int:
    try:
        return max(1, min(int(os.getenv("MAX_DISCOVERY_AGE_HOURS", "24")), 168))
    except (TypeError, ValueError):
        return 24


def get_allowlist() -> set:
    return _parse_list("REMEDIATION_ALLOWLIST")


def get_denylist() -> set:
    denies = _parse_list("REMEDIATION_DENYLIST")
    if not denies:
        denies.update({"administratoraccess", "breakglass", "break-glass"})
    return denies


def get_log_level() -> str:
    return os.getenv("LOG_LEVEL", "INFO").upper()


def get_aws_region() -> str:
    return os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "us-east-1"))


def get_aws_profile() -> str | None:
    return os.getenv("AWS_PROFILE")


def get_genai_model() -> str:
    return os.getenv("GENAI_MODEL", "gemini-3.8-flash")


def is_genai_enabled() -> bool:
    return _get_bool("ENABLE_GENAI", False)


def get_db_url() -> str:
    return os.getenv("DB_URL", "sqlite:///iam_governance.db")


def is_local_only() -> bool:
    return _get_bool("LOCAL_ONLY", False)


def redact_db_url(url: str | None = None) -> str:
    """Strip password from a DB URL for safe logging. Never log raw DB_URL."""
    raw = url if url is not None else get_db_url()
    try:
        parsed = urlparse(raw)
        if parsed.password:
            netloc = parsed.hostname or ""
            if parsed.username:
                netloc = f"{parsed.username}:***@{netloc}"
            if parsed.port:
                netloc = f"{netloc}:{parsed.port}"
            parsed = parsed._replace(netloc=netloc)
        if parsed.query:
            from urllib.parse import parse_qsl, urlencode
            query = urlencode([(k, "***" if any(s in k.lower() for s in ("password", "secret", "token", "key")) else v)
                               for k, v in parse_qsl(parsed.query, keep_blank_values=True)])
            return parsed._replace(query=query).geturl()
        return parsed.geturl()
    except Exception:
        return "***"


_SENSITIVE_KEYS = {"password", "passwd", "secret", "token", "api_key", "apikey", "db_url"}


def sanitize_details(details: dict | None) -> dict | None:
    """Redact sensitive keys before logging/persisting."""
    if not details:
        return details
    def clean(value, key=""):
        kl = str(key).lower()
        if kl == "db_url":
            return redact_db_url(str(value))
        if kl in _SENSITIVE_KEYS or any(s in kl for s in ("password", "secret", "token", "api_key", "apikey", "authorization", "prompt", "policy_document")):
            return "[REDACTED]"
        if isinstance(value, dict):
            return {k: clean(v, k) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [clean(v, key) for v in value]
        return value
    return clean(details)


def _parsed_db_url(url: str | None = None):
    # urlparse handles sqlite:///path
    return urlparse(url if url is not None else get_db_url())


def db_is_sqlite(url: str | None = None) -> bool:
    raw = url if url is not None else get_db_url()
    parsed = urlparse(raw)
    if parsed.scheme == "sqlite":
        return True
    if parsed.scheme in ("postgresql", "postgres"):
        return False
    if parsed.scheme == "":
        # Bare filesystem path like iam_governance.db or ./data.db
        return True
    # sqlite:///:memory: has scheme sqlite (handled above); anything else is not sqlite
    return raw.endswith(".db") and "://" not in raw


def get_sqlite_path(url: str | None = None) -> str:
    """
    Resolve the SQLite file path from DB_URL. Defaults to iam_governance.db.
    Correctly preserves absolute paths (sqlite:////tmp/x.db) and :memory:.
    """
    raw = url if url is not None else get_db_url()
    if not db_is_sqlite(raw):
        raise ValueError("DB_URL is not SQLite; cannot derive path.")
    parsed = urlparse(raw)
    if parsed.scheme == "":
        # Bare path, no URL wrapper
        path = raw
    else:
        path = parsed.path
    if path in (":memory:", "/:memory:"):
        return ":memory:"
    if not path or path == "/":
        path = "iam_governance.db"
    # sqlite:///relative.db -> /relative.db (strip 1 slash); sqlite:////abs.db -> //abs.db -> /abs.db
    if parsed.scheme == "sqlite" and path.startswith("/"):
        # urlparse gives /rel for sqlite:///rel and //abs for sqlite:////abs on some platforms;
        # normalize: exactly one leading slash stripped for relative, absolute kept.
        if path.startswith("//"):
            path = path[1:]
        else:
            stripped = path[1:]
            # If remainder looks like an absolute Windows (C:/...) or POSIX path requested
            # via 4-slash form, urlparse already collapsed; check netloc for absolute hint.
            if parsed.netloc and parsed.netloc not in ("", ".", "localhost"):
                # sqlite://hostname/... is not a local file; reject to avoid CWD confusion
                raise ValueError(f"Unsupported SQLite host in DB_URL: {parsed.netloc}")
            # Distinguish sqlite:///abs (unix absolute) from sqlite:///rel:
            # urlparse cannot tell; require 4-slash form for absolute paths.
            # Heuristic: if original had 4 slashes after scheme, it was absolute.
            if raw.startswith("sqlite:////"):
                path = "/" + stripped
            else:
                path = stripped
    # Windows drive-letter bare paths (C:\...) bypass abspath issues
    if re.match(r"^[A-Za-z]:[\\/]", path):
        return os.path.normpath(path)
    if path == ":memory:":
        return path
    return os.path.abspath(path)


def require_sqlite_path() -> str:
    if not db_is_sqlite():
        raise ValueError("Only SQLite is supported in this execution path.")
    return get_sqlite_path()

