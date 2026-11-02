"""Tests for the review round 1 must-fix: structured per-request logging
(SOP Sec 6) from runtime.call_api, the single choke point every one of the
20 tools funnels through.

These attach their own handler to the "mailprotector_mcp" logger for the
duration of each test rather than using logging_config.configure_logging()'s
real stdout handler -- that handler is process-global, shared module state
that would leak between tests and whatever test happens to call it first.
"""

from __future__ import annotations

import json
import logging

import httpx
import pytest
import respx
from httpx import ASGITransport

from mailprotector_mcp import runtime
from mailprotector_mcp.logging_config import _redact_value, configure_logging, redact_args
from mailprotector_mcp.server import build_mcp, create_app

from .conftest import run_lifespan

BASE_URL = "https://console.mailprotector.com"


class _ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[dict] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(json.loads(record.getMessage()))


@pytest.fixture
def captured_logs():
    handler = _ListHandler()
    logger = logging.getLogger("mailprotector_mcp")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        yield handler.records
    finally:
        logger.removeHandler(handler)


@pytest.fixture
def mcp():
    return build_mcp()


async def _call_tool(mcp, tool_name: str, **kwargs):
    content_blocks, _structured = await mcp.call_tool(tool_name, kwargs)
    return json.loads(content_blocks[0].text)


# -- Unit tests: redaction (the "never log a password/token" half) -----------


def test_redact_value_masks_password_by_key_name() -> None:
    assert _redact_value("password", "hunter2") == "***redacted***"
    assert _redact_value("auth_token", "abc") == "***redacted***"
    assert _redact_value("PASSWORD", "hunter2") == "***redacted***"  # case-insensitive


def test_redact_value_truncates_long_strings() -> None:
    long_value = "x" * 100
    result = _redact_value("name", long_value)
    assert result != long_value
    assert result.startswith("x" * 60)
    assert "(100 chars)" in result


def test_redact_value_summarizes_collections_without_content() -> None:
    rules = [{"address": "a@b.com", "type": "block"}, {"address": "c@d.com", "type": "allow"}]
    result = _redact_value("rules", rules)
    assert result == "<list[2]>"
    assert "a@b.com" not in result


def test_redact_value_passes_through_scalars() -> None:
    assert _redact_value("domain_id", 123) == 123
    assert _redact_value("account_id", None) is None
    assert _redact_value("reset", True) is True


def test_redact_args_is_per_key() -> None:
    out = redact_args({"scope_id": 1, "password": "secret"})
    assert out == {"scope_id": 1, "password": "***redacted***"}


def test_configure_logging_attaches_exactly_one_handler_and_is_idempotent() -> None:
    logger = logging.getLogger("mailprotector_mcp")
    saved_handlers, saved_propagate = list(logger.handlers), logger.propagate
    logger.handlers = []
    try:
        configure_logging()
        configure_logging()  # second call must not attach a duplicate handler
        assert len(logger.handlers) == 1
    finally:
        logger.handlers = saved_handlers
        logger.propagate = saved_propagate


# -- Integration: every call_api invocation logs one structured line ---------


@respx.mock
async def test_successful_call_logs_tool_name_path_status_and_latency(mcp, captured_logs) -> None:
    respx.get(f"{BASE_URL}/accounts/123.xml").mock(
        return_value=httpx.Response(200, content=b"<account><id>123</id><name>Acme</name></account>")
    )
    reset = runtime.auth_token_var.set("super-secret-token")
    try:
        await _call_tool(mcp, "mailprotector_get_account", account_id=123)
    finally:
        runtime.auth_token_var.reset(reset)

    assert len(captured_logs) == 1
    entry = captured_logs[0]
    assert entry["tool"] == "mailprotector_get_account"
    assert entry["mailprotector_path"] == "/accounts/123.xml"
    assert entry["status_code"] == 200
    assert entry["error_code"] is None
    assert entry["args"] == {"account_id": 123}
    assert entry["latency_ms"] >= 0
    # The auth token must never reach a log line, under any key or value.
    assert "super-secret-token" not in json.dumps(entry)


@respx.mock
async def test_vendor_error_logs_status_and_error_code(mcp, captured_logs) -> None:
    respx.get(f"{BASE_URL}/accounts/999.xml").mock(return_value=httpx.Response(404, text="missing"))
    reset = runtime.auth_token_var.set("t")
    try:
        await _call_tool(mcp, "mailprotector_get_account", account_id=999)
    finally:
        runtime.auth_token_var.reset(reset)

    assert len(captured_logs) == 1
    entry = captured_logs[0]
    assert entry["status_code"] == 404
    assert entry["error_code"] == "not_found"
    assert entry["mailprotector_path"] == "/accounts/999.xml"


async def test_not_configured_logs_without_a_vendor_call(mcp, captured_logs) -> None:
    # No auth_token_var set -> call_api's get_client() returns None before
    # any HTTP call is attempted; there is no path/status to report.
    result = await _call_tool(mcp, "mailprotector_get_account", account_id=1)
    assert result["error"]["code"] == "not_configured"

    assert len(captured_logs) == 1
    entry = captured_logs[0]
    assert entry["error_code"] == "not_configured"
    assert entry["status_code"] is None
    assert entry["mailprotector_path"] is None


@respx.mock
async def test_create_user_password_is_redacted_in_the_log(mcp, captured_logs) -> None:
    respx.post(url__regex=r".*/domains/32/users\.xml").mock(
        return_value=httpx.Response(200, content=b"<user><id>1</id><name>jdoe</name></user>")
    )
    reset = runtime.auth_token_var.set("t")
    try:
        await _call_tool(
            mcp,
            "mailprotector_create_user",
            scope_type="domain",
            scope_id=32,
            name="jdoe",
            password="hunter2",
        )
    finally:
        runtime.auth_token_var.reset(reset)

    assert len(captured_logs) == 1
    entry = captured_logs[0]
    assert entry["tool"] == "mailprotector_create_user"
    assert entry["args"]["password"] == "***redacted***"
    assert "hunter2" not in json.dumps(entry)


@respx.mock
async def test_request_id_is_shared_across_tool_calls_in_one_http_request(captured_logs) -> None:
    """Exercises the real HTTP path so CredentialMiddleware actually assigns
    runtime.request_id_var -- the in-process mcp.call_tool() path the other
    tests in this file use never goes through that middleware."""
    respx.get(f"{BASE_URL}/accounts.xml").mock(
        return_value=httpx.Response(200, content=b'<accounts type="array"></accounts>')
    )

    app = create_app()
    async with run_lifespan(app):
        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            init = await client.post(
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
                    "X-Mailprotector-Auth-Token": "t",
                },
            )
            assert init.status_code == 200

            call = await client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "mailprotector_list_accounts", "arguments": {}},
                },
                headers={
                    "Accept": "application/json, text/event-stream",
                    "X-Mailprotector-Auth-Token": "t",
                },
            )
            assert call.status_code == 200

    assert len(captured_logs) == 1
    entry = captured_logs[0]
    assert entry["tool"] == "mailprotector_list_accounts"
    assert entry["request_id"] is not None
    assert len(entry["request_id"]) == 12
