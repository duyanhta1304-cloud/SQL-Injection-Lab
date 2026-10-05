"""Defensive SQL inspection and parameterized execution helpers."""

from __future__ import annotations

import re
from typing import Any

import sqlparse
from sqlparse import tokens as T


ALLOWED_SORT_COLUMNS = {"price": "price", "name": "name", "category": "category"}


class SecurityViolation(ValueError):
    """Raised when user-controlled data fails the AST security inspection."""

    def __init__(self, inspection: dict[str, Any]):
        super().__init__("Potential SQL syntax mutation was blocked.")
        self.inspection = inspection


class ASTSecurityGuard:
    """Use sqlparse tokens plus focused heuristics to identify SQLi payloads."""

    KEYWORD_WEIGHTS = {
        "UNION": 65, "OR": 30, "AND": 20, "SELECT": 20, "FROM": 15,
        "DROP": 70, "INSERT": 60, "UPDATE": 60, "DELETE": 60, "PRAGMA": 55,
    }

    @classmethod
    def inspect_input(cls, raw_input: str) -> dict[str, Any]:
        """Return a deterministic risk verdict for one piece of user input."""
        value = "" if raw_input is None else str(raw_input)
        detected: list[str] = []
        score = 0

        for statement in sqlparse.parse(value):
            for token in statement.flatten():
                normalized = token.value.strip().upper()
                token_type = token.ttype
                if token_type is not None and token_type in T.Comment:
                    detected.append(f"COMMENT:{token.value.strip()[:24]}")
                    score += 50
                    continue
                if token_type is not None and token_type in T.Keyword:
                    keyword = normalized.split()[0] if normalized else ""
                    if keyword in cls.KEYWORD_WEIGHTS:
                        detected.append(f"KEYWORD:{keyword}")
                        score += cls.KEYWORD_WEIGHTS[keyword]

        if "--" in value and not any(item.startswith("COMMENT:") for item in detected):
            detected.append("INLINE_COMMENT:--")
            score += 50
        if "/*" in value or "*/" in value:
            detected.append("BLOCK_COMMENT")
            score += 50

        semicolon_count = value.count(";")
        if semicolon_count > 1:
            detected.append(f"MULTI_STATEMENT_SEMICOLONS:{semicolon_count}")
            score += 55
        elif semicolon_count == 1:
            detected.append("SEMICOLON")
            score += 10

        if re.search(r"(?i)(?:'|\")?\s*OR\s+(?:'[^']*'\s*=\s*'[^']*'|\d+\s*=\s*\d+)", value):
            detected.append("TAUTOLOGY_PATTERN")
            score += 55
        if re.search(r"(?i)\bSYS_CANARY_CREDENTIALS\b", value):
            detected.append("CANARY_TABLE_REFERENCE")
            score += 100

        detected_tokens = list(dict.fromkeys(detected))
        risk_score = min(score, 100)
        hard_signal = any(
            marker in finding
            for finding in detected_tokens
            for marker in ("COMMENT", "UNION", "TAUTOLOGY", "CANARY", "MULTI_STATEMENT")
        )
        return {"is_malicious": hard_signal or risk_score >= 40, "detected_tokens": detected_tokens, "risk_score": risk_score}


def execute_secure(cursor, base_query: str, params: tuple[Any, ...]) -> dict[str, Any]:
    """Inspect all string parameters, then execute a parameterized SQL statement."""
    combined = " ".join(str(param) for param in params if isinstance(param, str))
    inspection = ASTSecurityGuard.inspect_input(combined)
    if inspection["is_malicious"]:
        raise SecurityViolation(inspection)
    cursor.execute(base_query, params)
    return inspection
