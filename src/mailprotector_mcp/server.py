"""FastMCP factory, request-level credential middleware, and the ASGI app.

Builds the outer Starlette app that __main__.py serves: GET /health (a pure
local probe, never touches Mailprotector) plus the mounted MCP app at
POST /mcp, guarded by CredentialMiddleware.
"""

from __future__ import annotations

import uuid

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from . import runtime
from .config import settings
from .tools import accounts, config as config_tools, domains, groups_users, rules

AUTH_TOKEN_HEADER = "x-mailprotector-auth-token"
BASE_URL_HEADER = "x-mailprotector-base-url"
# The header name as declared in README.md -- used verbatim in the 401 body
# so a caller can see exactly what to send without reading source code.
AUTH_TOKEN_HEADER_NAME = "X-Mailprotector-Auth-Token"

INSTRUCTIONS = """\
Mailprotector is an email-security service (spam/virus filtering, allow/block \
lists) that MSPs manage on behalf of their end-customer domains. Every call \
is scoped to one manager's own account -- the credential you send determines \
what you can see, this connector does not add its own tenant model.

Core concepts: an account groups one or more domains; a domain has user \
groups; a user group has users. Spam tolerance, allow/block rules, and \
settings can each be read or set at the domain, user-group, or user level \
(narrower scopes inherit from their parent unless overridden).

Typical flows: list_accounts -> list_domains(account_id) -> \
get_domain_traffic_report(domain_id) for a security review; \
list_allow_block_rules -> set_allow_block_rules to adjust filtering; \
get_spam_tolerance -> set_spam_tolerance (or reset) to tune sensitivity.
"""


def build_mcp() -> FastMCP:
    mcp = FastMCP(
        name="mailprotector",
        instructions=INSTRUCTIONS,
        stateless_http=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    accounts.register(mcp)
    domains.register(mcp)
    groups_users.register(mcp)
    rules.register(mcp)
    config_tools.register(mcp)
    return mcp


async def _health(_request: Request) -> Response:
    return JSONResponse({"status": "ok"})


class CredentialMiddleware:
    """Reads the per-request Mailprotector credential headers.

    Only guards the mounted MCP path; /health must stay reachable without
    any credential so the container's health probe never depends on a
    caller having valid Mailprotector access.

    Also assigns this request's log correlation id (runtime.request_id_var)
    -- same lifetime and reset discipline as the credential ContextVars
    below, so every structured log line (logging_config.log_tool_call) for
    the tool calls made within one inbound HTTP request shares one id.
    """

    def __init__(self, app: object, mcp_path: str) -> None:
        self.app = app
        self._mcp_path = mcp_path

    async def __call__(self, scope: dict, receive: object, send: object) -> None:
        if scope["type"] != "http" or not scope["path"].startswith(self._mcp_path):
            await self.app(scope, receive, send)
            return

        header_map = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        token = header_map.get(AUTH_TOKEN_HEADER)
        if not token:
            response = JSONResponse(
                {
                    "error": {
                        "code": "unauthorized",
                        "message": f"Missing required header: {AUTH_TOKEN_HEADER_NAME}",
                        "retryable": False,
                    }
                },
                status_code=401,
            )
            await response(scope, receive, send)
            return

        auth_reset = runtime.auth_token_var.set(token)
        base_reset = runtime.base_url_var.set(header_map.get(BASE_URL_HEADER) or None)
        request_id_reset = runtime.request_id_var.set(uuid.uuid4().hex[:12])
        try:
            await self.app(scope, receive, send)
        finally:
            runtime.auth_token_var.reset(auth_reset)
            runtime.base_url_var.reset(base_reset)
            runtime.request_id_var.reset(request_id_reset)


def create_app() -> Starlette:
    mcp = build_mcp()
    mcp_app = mcp.streamable_http_app()
    mcp_path = mcp.settings.streamable_http_path

    app = Starlette(
        routes=[
            Route("/health", _health, methods=["GET"]),
            *mcp_app.routes,
        ],
        # Mount()/routes-copy alone would not run the MCP app's own lifespan
        # (session manager startup/shutdown); without this, /mcp fails with
        # "Task group is not initialized" while /health still returns 200.
        lifespan=mcp_app.router.lifespan_context,
    )
    app.add_middleware(CredentialMiddleware, mcp_path=mcp_path)
    return app


__all__ = ["build_mcp", "create_app", "settings"]
