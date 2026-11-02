"""tools/list snapshot (20 tools + required args), the status-code -> error
code mapping table, and representative per-tool behaviour (one test per AC
group, mirroring docs/tickets/PRD-21253.ac.json's TC ids in the docstrings).
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from mailprotector_mcp import runtime
from mailprotector_mcp.errors import code_for_status
from mailprotector_mcp.server import build_mcp

BASE_URL = "https://console.mailprotector.com"

EXPECTED_TOOLS: dict[str, list[str]] = {
    "mailprotector_list_accounts": [],
    "mailprotector_get_account": ["account_id"],
    "mailprotector_list_domains": [],
    "mailprotector_get_domain": ["domain_id"],
    "mailprotector_create_domain": ["name"],
    "mailprotector_get_domain_traffic_report": ["domain_id"],
    "mailprotector_list_user_groups": ["domain_id"],
    "mailprotector_list_users": ["scope_type", "scope_id"],
    "mailprotector_get_user": ["user_id"],
    "mailprotector_create_user": ["scope_type", "scope_id", "name"],
    "mailprotector_move_user": ["user_id", "user_group_id"],
    "mailprotector_delete_user": ["user_id"],
    "mailprotector_get_user_message_stats": ["domain_id"],
    "mailprotector_list_allow_block_rules": ["scope_type", "scope_id"],
    "mailprotector_set_allow_block_rules": ["scope_type", "scope_id", "rules"],
    "mailprotector_get_spam_tolerance": ["scope_type", "scope_id"],
    "mailprotector_set_spam_tolerance": ["scope_type", "scope_id"],
    "mailprotector_get_settings": ["scope_type", "scope_id"],
    "mailprotector_set_settings": ["scope_type", "scope_id", "settings"],
    "mailprotector_get_dashboard_stats": [],
}


@pytest.fixture
def mcp():
    return build_mcp()


async def test_tools_list_snapshot(mcp) -> None:
    """TC-shape test (SOP Sec 10): exactly the 20 designed tools, each with
    the required args the tech design's contract table specifies."""
    tools = await mcp.list_tools()
    names = {t.name for t in tools}
    assert names == set(EXPECTED_TOOLS), (
        f"missing: {set(EXPECTED_TOOLS) - names}, unexpected: {names - set(EXPECTED_TOOLS)}"
    )
    assert len(tools) == 20

    by_name = {t.name: t for t in tools}
    for name, required in EXPECTED_TOOLS.items():
        schema = by_name[name].inputSchema
        assert set(schema.get("required", [])) == set(required), name


async def test_tool_descriptions_fit_the_token_budget(mcp) -> None:
    """SOP Sec 2.2: description <= 500 chars, first line <= 100 chars."""
    tools = await mcp.list_tools()
    for tool in tools:
        description = tool.description or ""
        assert len(description) <= 500, f"{tool.name} description too long: {len(description)}"
        first_line = description.splitlines()[0] if description else ""
        assert len(first_line) <= 100, f"{tool.name} first line too long: {len(first_line)}"


@pytest.mark.parametrize(
    "status_code,expected_code,expected_retryable",
    [
        (401, "unauthorized", False),
        (403, "unauthorized", False),
        (404, "not_found", False),
        (400, "invalid_argument", False),
        (422, "invalid_argument", False),
        (429, "rate_limited", True),
        (500, "upstream_error", True),
        (502, "upstream_error", True),
        (503, "upstream_error", True),
        (418, "upstream_error", True),  # undocumented/unmapped code -> safe fallback
    ],
)
def test_status_to_error_code_mapping(status_code, expected_code, expected_retryable) -> None:
    from mailprotector_mcp.errors import _RETRYABLE_CODES

    code = code_for_status(status_code)
    assert code == expected_code
    assert (code in _RETRYABLE_CODES) == expected_retryable


# -- Representative tool-call behaviour (mirrors ac.json's TC ids) -----------


async def _call_tool(mcp, tool_name: str, **kwargs):
    # FastMCP.call_tool returns (content_blocks, structured_result); our
    # tools return exactly one text block containing the JSON string.
    content_blocks, _structured = await mcp.call_tool(tool_name, kwargs)
    return json.loads(content_blocks[0].text)


@respx.mock
async def test_tc1_tc2_list_accounts_defaults_and_caps_limit(mcp) -> None:
    """TC1: omitted limit defaults to 50. TC2: limit=9999 is capped to 200
    (SOP Sec 2.5 hard cap) -- both asserted against what api_client actually
    receives, not just the tools/list schema default."""
    captured: dict[str, int] = {}

    def _responder(request: httpx.Request) -> httpx.Response:
        captured["limit"] = int(request.url.params["limit"])
        return httpx.Response(200, content=b'<accounts type="array"></accounts>')

    respx.get(f"{BASE_URL}/accounts.xml").mock(side_effect=_responder)

    reset = runtime.auth_token_var.set("t")
    try:
        await _call_tool(mcp, "mailprotector_list_accounts")
        assert captured["limit"] == 50  # TC1

        await _call_tool(mcp, "mailprotector_list_accounts", limit=9999)
        assert captured["limit"] == 200  # TC2
    finally:
        runtime.auth_token_var.reset(reset)


@respx.mock
async def test_tc3_get_account_known_id(mcp) -> None:
    respx.get(f"{BASE_URL}/accounts/123.xml").mock(
        return_value=httpx.Response(
            200,
            content=b"<account><id>123</id><name>Acme</name>"
            b"<account_status>Configured</account_status>"
            b"<created_at>2010-07-06T15:37:15Z</created_at></account>",
        )
    )
    reset = runtime.auth_token_var.set("t")
    try:
        result = await _call_tool(mcp, "mailprotector_get_account", account_id=123)
    finally:
        runtime.auth_token_var.reset(reset)
    assert result == {
        "id": 123,
        "name": "Acme",
        "account_status": "Configured",
        "created_at": "2010-07-06T15:37:15Z",
    }


@respx.mock
async def test_tc4_get_account_unknown_id_returns_not_found(mcp) -> None:
    respx.get(f"{BASE_URL}/accounts/999.xml").mock(return_value=httpx.Response(404, text="missing"))
    reset = runtime.auth_token_var.set("t")
    try:
        result = await _call_tool(mcp, "mailprotector_get_account", account_id=999)
    finally:
        runtime.auth_token_var.reset(reset)
    assert result["error"]["code"] == "not_found"


async def test_tc18_create_alias_user_without_parent_id_is_invalid_argument(mcp) -> None:
    reset = runtime.auth_token_var.set("t")
    try:
        result = await _call_tool(
            mcp,
            "mailprotector_create_user",
            scope_type="domain",
            scope_id=32,
            name="aliasuser",
            user_type="alias",
        )
    finally:
        runtime.auth_token_var.reset(reset)
    assert result["error"]["code"] == "invalid_argument"


async def test_tc25_remove_empty_rules_list_is_rejected_before_any_vendor_call(mcp) -> None:
    with respx.mock:
        route = respx.post(url__regex=r".*/allow_block_rules/destroy_rules\.xml").mock(
            return_value=httpx.Response(200)
        )
        reset = runtime.auth_token_var.set("t")
        try:
            result = await _call_tool(
                mcp,
                "mailprotector_set_allow_block_rules",
                scope_type="domain",
                scope_id=545,
                rules=[],
                action="remove",
            )
        finally:
            runtime.auth_token_var.reset(reset)
    assert result["error"]["code"] == "invalid_argument"
    assert route.call_count == 0


async def test_tc29_set_spam_tolerance_rejects_max_below_min(mcp) -> None:
    reset = runtime.auth_token_var.set("t")
    try:
        result = await _call_tool(
            mcp,
            "mailprotector_set_spam_tolerance",
            scope_type="domain",
            scope_id=32,
            possible_spam_min_score=500,
            possible_spam_max_score=100,
        )
    finally:
        runtime.auth_token_var.reset(reset)
    assert result["error"]["code"] == "invalid_argument"
