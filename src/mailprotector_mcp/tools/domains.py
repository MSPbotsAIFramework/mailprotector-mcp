"""Tools for Mailprotector domains (the protected mail domains under an account)."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..api_client import MailprotectorClient
from ..errors import error_envelope
from ..runtime import call_api

_MAX_LIMIT = 200
_DEFAULT_LIMIT = 50
_MAX_USERS_IN_REPORT = 200


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations={"readOnlyHint": True, "idempotentHint": True})
    async def mailprotector_list_domains(
        account_id: int | None = None, limit: int = _DEFAULT_LIMIT, offset: int = 0
    ) -> str:
        """List protected domains, optionally scoped to one account.

        Args:
            account_id: Only return domains under this account. Omit for every
                domain visible to the manager.
            limit: Max domains to return (default 50, hard cap 200).
            offset: Index of the first record to return, for pagination.
        """
        limit = max(1, min(limit, _MAX_LIMIT))

        async def _call(client: MailprotectorClient) -> str:
            items = await client.list_domains(account_id=account_id, limit=limit, offset=offset)
            return json.dumps(
                {"domains": items, "has_more": len(items) >= limit},
                separators=(",", ":"),
                ensure_ascii=False,
            )

        return await call_api(_call)

    @mcp.tool(annotations={"readOnlyHint": True, "idempotentHint": True})
    async def mailprotector_get_domain(domain_id: int) -> str:
        """Get one domain's detail by id.

        Args:
            domain_id: The domain's numeric id.
        """

        async def _call(client: MailprotectorClient) -> str:
            domain = await client.get_domain(domain_id)
            return json.dumps(domain, separators=(",", ":"), ensure_ascii=False)

        return await call_api(_call)

    @mcp.tool(annotations={"readOnlyHint": False, "idempotentHint": False})
    async def mailprotector_create_domain(
        name: str, account_id: int | None = None, parent_id: int | None = None
    ) -> str:
        """Add a new protected domain, optionally as an alias of an existing one.

        Args:
            name: Fully qualified domain name to protect.
            account_id: Account to create the domain under. Omit to create
                under the manager's default account.
            parent_id: Id of an existing domain to make this one an alias of.
                Omit to create a standalone domain.
        """
        if not name or not name.strip():
            return error_envelope("invalid_argument", "name must be a non-empty domain name.")

        async def _call(client: MailprotectorClient) -> str:
            domain = await client.create_domain(
                name=name.strip(), account_id=account_id, parent_id=parent_id
            )
            return json.dumps(domain, separators=(",", ":"), ensure_ascii=False)

        return await call_api(_call)

    @mcp.tool(annotations={"readOnlyHint": True, "idempotentHint": True})
    async def mailprotector_get_domain_traffic_report(
        domain_id: int, date_start: str | None = None, date_end: str | None = None
    ) -> str:
        """Get a domain's mail traffic report: blocked/spam/virus/delivered counts
        and a per-user breakdown for a date range (defaults to the last 7 days).

        Args:
            domain_id: The domain's numeric id.
            date_start: Start of the date range, e.g. "2026-10-01". Defaults to
                7 days ago.
            date_end: End of the date range, e.g. "2026-10-08". Defaults to today.
        """

        async def _call(client: MailprotectorClient) -> str:
            report = await client.get_domain_traffic_report(
                domain_id=domain_id, date_start=date_start, date_end=date_end
            )
            # Defensive cap per SOP Sec 2.5 -- the vendor doesn't paginate this
            # endpoint, so a domain with an unusually large user count could
            # otherwise produce an oversized response.
            users = report.get("users", [])
            has_more = len(users) > _MAX_USERS_IN_REPORT
            result = {**report, "users": users[:_MAX_USERS_IN_REPORT], "has_more": has_more}
            return json.dumps(result, separators=(",", ":"), ensure_ascii=False)

        return await call_api(_call)
