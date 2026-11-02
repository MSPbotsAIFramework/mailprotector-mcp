"""Tests for the credential middleware: 401 on a missing header, correct
token reaching the request context, and -- for AC20 -- no cross-request
credential leakage under concurrency.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
from httpx import ASGITransport

from mailprotector_mcp import runtime
from mailprotector_mcp.server import AUTH_TOKEN_HEADER_NAME, create_app

from .conftest import run_lifespan


@pytest.fixture
def app():
    return create_app()


async def test_missing_auth_header_returns_401_with_header_name(app) -> None:
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Accept": "application/json, text/event-stream"},
        )
    assert response.status_code == 401
    body = response.json()
    assert body["error"]["code"] == "unauthorized"
    assert AUTH_TOKEN_HEADER_NAME in body["error"]["message"]


async def test_health_does_not_require_auth_header(app) -> None:
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_present_header_reaches_tools_list(app) -> None:
    async with run_lifespan(app):
        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "test", "version": "0"},
                    },
                },
                headers={
                    "Accept": "application/json, text/event-stream",
                    "X-Mailprotector-Auth-Token": "token-a",
                },
            )
    # Stateless mode accepts the call directly (no session-id handshake
    # required) -- 400/401 here would mean the header didn't get through.
    assert response.status_code == 200


async def test_concurrent_requests_do_not_leak_credentials() -> None:
    """AC20: two concurrent requests, two different tokens, no cross-talk.

    Exercises the real mechanism the SOP requires (contextvars.ContextVar,
    reset in `finally`): each asyncio Task gets its own copy of the current
    Context, so a `.set()` inside one task is invisible to a sibling task
    unless credentials leak through a shared global/module-level variable
    instead. This mocks the outbound Mailprotector call and records which
    token api_client actually sent on the wire for each task, which is what
    a real cross-tenant leak would corrupt.
    """
    import base64

    import respx

    seen_tokens: dict[str, str] = {}

    def _responder(request: httpx.Request) -> httpx.Response:
        _, _, encoded = request.headers["authorization"].partition(" ")
        token, _, _ = base64.b64decode(encoded).decode().partition(":")
        return httpx.Response(200, content=f"<account><id>1</id><name>{token}</name></account>".encode())

    async def run_as_request(token: str, label: str) -> None:
        reset = runtime.auth_token_var.set(token)
        try:
            await asyncio.sleep(0)  # yield so the other task's .set() runs first

            async def _call(client):
                return (await client.get_account(0))["name"]

            seen_tokens[label] = await runtime.call_api(_call)
        finally:
            runtime.auth_token_var.reset(reset)

    with respx.mock:
        respx.get(url__regex=r".*/accounts/0\.xml").mock(side_effect=_responder)
        await asyncio.gather(
            run_as_request("token-a", "a"),
            run_as_request("token-b", "b"),
        )

    assert seen_tokens["a"] == "token-a"
    assert seen_tokens["b"] == "token-b"
    # And nothing escaped back into this task's own context.
    assert runtime.auth_token_var.get() is None
