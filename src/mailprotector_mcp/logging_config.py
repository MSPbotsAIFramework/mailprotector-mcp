"""Structured (JSON) logging for every Mailprotector tool call.

Every call to `log_tool_call` emits exactly one JSON object per line on
`logger` -- no custom log-aggregator parser needed. This is the single place
that decides what is safe to log: callers (today, only `runtime.call_api`)
pass in raw values and this module is the one that redacts them before they
ever reach a handler.

Never logged, by construction: the Mailprotector auth token / base-url
header (runtime.py never passes them here), and the raw response body
(callers only pass a status/error code, never the parsed payload).
"""

from __future__ import annotations

import json
import logging
import sys
import time

logger = logging.getLogger("mailprotector_mcp")

# Matched case-insensitively against each arg name. Covers the one sensitive
# tool argument today (mailprotector_create_user's `password`) and anything
# shaped like it added later, without needing a per-tool allowlist.
_SENSITIVE_KEY_MARKERS = ("password", "token", "secret", "credential", "auth")
_MAX_STRING_LEN = 60


def configure_logging(level: int = logging.INFO) -> None:
    """Attach the one JSON-lines handler this service uses.

    Idempotent (safe to call from both `__main__` and tests): a second call
    is a no-op rather than attaching a duplicate handler.
    """
    if logger.handlers:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False


def _redact_value(key: str, value: object) -> object:
    if any(marker in key.lower() for marker in _SENSITIVE_KEY_MARKERS):
        return "***redacted***"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if len(value) > _MAX_STRING_LEN:
            return f"{value[:_MAX_STRING_LEN]}...({len(value)} chars)"
        return value
    # Collections (rules/settings lists, dicts of ids, etc.) may carry
    # customer addresses or other business data -- summarize shape, not
    # content, which is enough to debug a call without logging that data.
    if isinstance(value, (list, tuple, set, frozenset)):
        return f"<{type(value).__name__}[{len(value)}]>"
    if isinstance(value, dict):
        return f"<dict[{len(value)}]>"
    return f"<{type(value).__name__}>"


def redact_args(args: dict[str, object]) -> dict[str, object]:
    return {key: _redact_value(key, value) for key, value in args.items()}


def log_tool_call(
    *,
    request_id: str | None,
    tool: str,
    args: dict[str, object],
    path: str | None,
    status_code: int | None,
    error_code: str | None,
    latency_ms: float,
) -> None:
    """One structured log line per tool invocation (SOP Sec 6).

    `path`/`status_code` describe the last Mailprotector HTTP call the tool
    made (None/None if the tool never got that far, e.g. not_configured).
    """
    payload = {
        "ts": time.time(),
        "request_id": request_id,
        "tool": tool,
        "args": redact_args(args),
        "mailprotector_path": path,
        "status_code": status_code,
        "error_code": error_code,
        "latency_ms": round(latency_ms, 1),
    }
    logger.info(json.dumps(payload, separators=(",", ":"), ensure_ascii=False))
