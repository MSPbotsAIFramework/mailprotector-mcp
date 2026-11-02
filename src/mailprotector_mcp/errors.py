"""Structured error envelope for tool results.

Tools never raise exceptions to the MCP layer. Every error -- ours or the
vendor's -- comes back as a JSON string: {"error": {"code", "message",
"retryable"}}. "code" is drawn from a fixed, small vocabulary so an Agent can
branch on it programmatically; "retryable" tells it whether retrying the same
call could plausibly succeed.
"""

from __future__ import annotations

import json
from typing import Literal

ErrorCode = Literal[
    "not_configured",
    "unauthorized",
    "not_found",
    "invalid_argument",
    "rate_limited",
    "upstream_error",
]

# Mailprotector only documents 200/201/403 explicitly. 401/404/422/429 are an
# assumed mapping to standard REST semantics (see docs/tickets/PRD-21253.md,
# "Open questions"); unmapped/undocumented status codes fall back to
# upstream_error, which is the safe default (retryable, no false precision).
_STATUS_TO_CODE: dict[int, ErrorCode] = {
    401: "unauthorized",
    403: "unauthorized",
    404: "not_found",
    400: "invalid_argument",
    422: "invalid_argument",
    429: "rate_limited",
}

_RETRYABLE_CODES: frozenset[ErrorCode] = frozenset({"rate_limited", "upstream_error"})


def code_for_status(status_code: int) -> ErrorCode:
    """Map an upstream HTTP status to our fixed error-code vocabulary."""
    if status_code in _STATUS_TO_CODE:
        return _STATUS_TO_CODE[status_code]
    if 500 <= status_code < 600:
        return "upstream_error"
    return "upstream_error"


def error_envelope(code: ErrorCode, message: str) -> str:
    """Build the JSON string a tool returns on failure."""
    return json.dumps(
        {"error": {"code": code, "message": message, "retryable": code in _RETRYABLE_CODES}},
        separators=(",", ":"),
        ensure_ascii=False,
    )


def error_for_status(status_code: int, message: str) -> str:
    return error_envelope(code_for_status(status_code), message)
