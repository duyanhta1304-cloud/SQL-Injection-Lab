"""Canary traps and local security telemetry for Apex Gear Store."""

from __future__ import annotations

import json
import logging
from pathlib import Path
import re
from typing import Any


LOG_PATH = Path(__file__).with_name("security_alerts.log")
_logger = logging.getLogger("apex_store.security")
_logger.setLevel(logging.INFO)
_logger.propagate = False
if not _logger.handlers:
    handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    _logger.addHandler(handler)


def _safe_text(value: Any, limit: int = 800) -> str:
    """Keep log records single-line and bounded to resist log injection."""
    return str(value).replace("\r", "\\r").replace("\n", "\\n")[:limit]


def _client_ip(request_obj) -> str:
    forwarded = request_obj.headers.get("X-Forwarded-For", "")
    return _safe_text(forwarded.split(",", 1)[0].strip() or request_obj.remote_addr or "unknown", 80)


def _log_alert(level: int, client_ip: str, attack_vector: str, payload: str) -> None:
    record = {"client_ip": _safe_text(client_ip, 80), "attack_vector": _safe_text(attack_vector, 120), "payload": _safe_text(payload)}
    _logger.log(level, json.dumps(record, ensure_ascii=True, sort_keys=True))


def log_security_event(client_ip: str, attack_vector: str, payload: str) -> None:
    """Record a blocked or suspicious request in the security telemetry file."""
    _log_alert(logging.WARNING, client_ip, attack_vector, payload)


def inspect_honeypots(request_obj) -> bool:
    """Detect data placed in the deliberately empty hidden canary field."""
    values = request_obj.values.getlist("admin_debug_token")
    tampered_values = [value for value in values if value != ""]
    if tampered_values:
        _log_alert(logging.CRITICAL, _client_ip(request_obj), "hidden_form_canary_tamper", repr(tampered_values))
        return True
    return False


def check_canary_table_access(raw_query: str, client_ip: str) -> bool:
    """Log any reference to the decoy credential table and report whether it hit."""
    if re.search(r"(?i)\bsys_canary_credentials\b", raw_query or ""):
        _log_alert(logging.CRITICAL, client_ip, "decoy_database_table_access", raw_query)
        return True
    return False
