"""Per-request credential plumbing shared by every tool module.

The Gateway can route concurrent requests for different tenants to the same
running instance (SOP Sec 0.2/3.3). The two ContextVars below are the only
place a request's credentials live; CredentialMiddleware in server.py sets
them and resets them in a `finally`, and nothing here (or anywhere else in
this service) stores them in a module-level variable, cache, or on disk.
"""

from __future__ import annotations

import contextvars
from collections.abc import Awaitable, Callable

from .api_client import MailprotectorAPIError, MailprotectorClient
from .errors import error_envelope, error_for_status

auth_token_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "mailprotector_auth_token", default=None
)
base_url_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "mailprotector_base_url", default=None
)


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
    not_configured / upstream-error handling is written exactly once instead
    of being re-copied into all 20 tools.
    """
    client = get_client()
    if client is None:
        return error_envelope(
            "not_configured",
            "Mailprotector credentials are not configured for this request.",
        )
    try:
        async with client:
            return await action(client)
    except MailprotectorAPIError as exc:
        return error_for_status(exc.status_code, exc.message)
