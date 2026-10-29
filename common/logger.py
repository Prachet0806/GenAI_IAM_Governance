# common/logger.py
import json
import sys
from datetime import datetime, timezone

from common import config

_LEVELS = {"DEBUG": 10, "INFO": 20, "WARN": 30, "WARNING": 30, "ERROR": 40}


def _current_level() -> int:
    return _LEVELS.get(config.get_log_level(), 20)


# Kept for backwards compat; prefer _current_level() (dynamic).
_CURRENT_LEVEL = _LEVELS.get(config.LOG_LEVEL, 20)


def log(
    action: str,
    status: str,
    message: str,
    level: str = "INFO",
    entity_type: str | None = None,
    entity_id: str | None = None,
    details: dict | None = None,
):
    """
    Emit a structured JSON log line. Suitable for CloudWatch ingestion.
    """
    level = level.upper()
    if _LEVELS.get(level, 100) < _current_level():
        return

    payload = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "action": action,
        "status": status,
        "message": message,
    }
    if entity_type:
        payload["entity_type"] = entity_type
    if entity_id:
        payload["entity_id"] = entity_id
    if details:
        payload["details"] = config.sanitize_details(details)

    output = json.dumps(payload, default=str)
    stream = sys.stderr if level == "ERROR" else sys.stdout
    print(output, file=stream)
