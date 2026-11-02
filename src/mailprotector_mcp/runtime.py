"""Per-request credential plumbing shared by every tool module.

The Gateway can route concurrent requests for different tenants to the same
running instance (SOP Sec 0.2/3.3). The two ContextVars below are the only
place a request's credentials live; CredentialMiddleware in server.py sets
them and resets them in a `finally`, and nothing here (or anywhere else in
this service) stores them in a module-level variable, cache, or on disk.
"""

from __future__ import annotations

import contextvars
import sys
import time
from collections.abc import Awaitable, Callable

from .api_client import MailprotectorAPIError, MailprotectorClient
from .errors import code_for_status, error_envelope, error_for_status
from .logging_config import log_tool_call

auth_token_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "mailprotector_auth_token", default=None
)
base_url_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "mailprotector_base_url", default=None
)
# Set once per inbound HTTP request by CredentialMiddleware (server.py) so
# every tool call made within that request logs the same correlation id.
request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "mailprotector_request_id", default=None
)


def _caller_tool_name_and_args() -> tuple[str, dict[str, object]]:
    """Identify the `@mcp.tool` function that is calling `call_api`.

    Every tool's body is `return await call_api(_call)` -- a direct call, so
    the frame one level up from `call_api` is always that tool function's
    own frame, never FastMCP's dispatch machinery. This lets every one of
    the 20 tools get logged from this single choke point without each of
    them having to pass its own name/args in by hand.
    """
    frame = sys._getframe(2)  # call_api's caller's caller (see call_api below)
    code = frame.f_code
    arg_names = code.co_varnames[: code.co_argcount + code.co_kwonlyargcount]
    args = {name: frame.f_locals[name] for name in arg_names if name in frame.f_locals}
    return code.co_name, args


def get_client() -> MailprotectorClient | None:
    """Build a client from this request's own credentials, or None if unset.

    Returning None (rather than raising) lets callers turn it into the
    `not_configured` error envelope. In normal operation this should not
    happen -- CredentialMiddleware already rejects requests with a 401
    before a tool ever runs -- this is the defensive fallback the SOP asks
    for, not the primary enforcement point.
    """
    token = auth_token_var.get()
    if not token:
        return None
    return MailprotectorClient(auth_token=token, base_url=base_url_var.get())


async def call_api(action: Callable[[MailprotectorClient], Awaitable[str]]) -> str:
    """Run one tool's body against a freshly built, request-scoped client.

    Every tool funnels its Mailprotector call(s) through here so the
    not_configured / upstream-error handling, and the structured logging
    required by the tech design's Observability section (SOP Sec 6), are
    each written exactly once instead of being re-copied into all 20 tools.
    """
    # Must run synchronously, before any `await`, while this frame is still
    # directly two levels below the calling tool function (see
    # _caller_tool_name_and_args's docstring).
    tool_name, args = _caller_tool_name_and_args()
    request_id = request_id_var.get()
    start = time.monotonic()

    client = get_client()
    if client is None:
        log_tool_call(
            request_id=request_id,
            tool=tool_name,
            args=args,
            path=None,
            status_code=None,
            error_code="not_configured",
            latency_ms=(time.monotonic() - start) * 1000,
        )
        return error_envelope(
            "not_configured",
            "Mailprotector credentials are not configured for this request.",
        )
    try:
        async with client:
            result = await action(client)
        last_call = client.last_call or {}
        log_tool_call(
            request_id=request_id,
            tool=tool_name,
            args=args,
            path=last_call.get("path"),
            status_code=last_call.get("status_code"),
            error_code=None,
            latency_ms=(time.monotonic() - start) * 1000,
        )
        return result
    except MailprotectorAPIError as exc:
        last_call = client.last_call or {}
        log_tool_call(
            request_id=request_id,
            tool=tool_name,
            args=args,
            path=last_call.get("path"),
            status_code=exc.status_code,
            error_code=code_for_status(exc.status_code),
            latency_ms=(time.monotonic() - start) * 1000,
        )
        return error_for_status(exc.status_code, exc.message)
