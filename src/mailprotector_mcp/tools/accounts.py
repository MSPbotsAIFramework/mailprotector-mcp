"""Tools for Mailprotector accounts (the top-level customer/tenant grouping)."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..api_client import MailprotectorClient
from ..runtime import call_api

_MAX_LIMIT = 200
_DEFAULT_LIMIT = 50


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations={"readOnlyHint": True, "idempotentHint": True})
    async def mailprotector_list_accounts(limit: int = _DEFAULT_LIMIT, offset: int = 0) -> str:
        """List accounts visible to the authenticated manager.

        Args:
            limit: Max accounts to return (default 50, hard cap 200).
            offset: Index of the first record to return, for pagination.
        """
        limit = max(1, min(limit, _MAX_LIMIT))

        async def _call(client: MailprotectorClient) -> str:
            items = await client.list_accounts(limit=limit, offset=offset)
            return json.dumps(
                {"accounts": items, "has_more": len(items) >= limit},
                separators=(",", ":"),
                ensure_ascii=False,
            )

        return await call_api(_call)

    @mcp.tool(annotations={"readOnlyHint": True, "idempotentHint": True})
    async def mailprotector_get_account(account_id: int) -> str:
        """Get one account's detail by id.

        Args:
            account_id: The account's numeric id.
        """

        async def _call(client: MailprotectorClient) -> str:
            account = await client.get_account(account_id)
            return json.dumps(account, separators=(",", ":"), ensure_ascii=False)

        return await call_api(_call)
