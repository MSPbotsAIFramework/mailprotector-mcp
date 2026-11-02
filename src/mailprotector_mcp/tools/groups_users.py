"""Tools for Mailprotector user groups, users, and per-user message stats."""

from __future__ import annotations

import json
from typing import Literal

from mcp.server.fastmcp import FastMCP

from ..api_client import MailprotectorClient
from ..errors import error_envelope
from ..runtime import call_api

_MAX_LIMIT = 200
_DEFAULT_LIMIT = 50

ScopeType = Literal["domain", "user_group"]
_VALID_SCOPES: frozenset[str] = frozenset({"domain", "user_group"})


def _invalid_scope(scope_type: str) -> str:
    return error_envelope(
        "invalid_argument",
        f"scope_type must be one of {sorted(_VALID_SCOPES)}, got {scope_type!r}.",
    )


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations={"readOnlyHint": True, "idempotentHint": True})
    async def mailprotector_list_user_groups(domain_id: int) -> str:
        """List the user groups under a domain, with each group's services and
        user count.

        Args:
            domain_id: The domain's numeric id.
        """

        async def _call(client: MailprotectorClient) -> str:
            items = await client.list_user_groups(domain_id=domain_id)
            return json.dumps({"user_groups": items}, separators=(",", ":"), ensure_ascii=False)

        return await call_api(_call)

    @mcp.tool(annotations={"readOnlyHint": True, "idempotentHint": True})
    async def mailprotector_list_users(
        scope_type: ScopeType, scope_id: int, limit: int = _DEFAULT_LIMIT, offset: int = 0
    ) -> str:
        """List users under a domain or under one of its user groups.

        Args:
            scope_type: "domain" or "user_group" -- what scope_id refers to.
            scope_id: The numeric id of that domain or user group.
            limit: Max users to return (default 50, hard cap 200).
            offset: Index of the first record to return, for pagination.
        """
        if scope_type not in _VALID_SCOPES:
            return _invalid_scope(scope_type)
        limit = max(1, min(limit, _MAX_LIMIT))

        async def _call(client: MailprotectorClient) -> str:
            items = await client.list_users(
                scope_type=scope_type, scope_id=scope_id, limit=limit, offset=offset
            )
            return json.dumps(
                {"users": items, "has_more": len(items) >= limit},
                separators=(",", ":"),
                ensure_ascii=False,
            )

        return await call_api(_call)

    @mcp.tool(annotations={"readOnlyHint": True, "idempotentHint": True})
    async def mailprotector_get_user(user_id: int) -> str:
        """Get one user's detail by id.

        Args:
            user_id: The user's numeric id.
        """

        async def _call(client: MailprotectorClient) -> str:
            user = await client.get_user(user_id)
            return json.dumps(user, separators=(",", ":"), ensure_ascii=False)

        return await call_api(_call)

    @mcp.tool(annotations={"readOnlyHint": False, "idempotentHint": False})
    async def mailprotector_create_user(
        scope_type: ScopeType,
        scope_id: int,
        name: str,
        password: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
        user_type: Literal["user", "alias", "mailing_list"] = "user",
        parent_id: int | None = None,
    ) -> str:
        """Add a new user under a domain or user group.

        Args:
            scope_type/scope_id: Where to create the user.
            name: Username part of the mail address ("jdoe" for jdoe@x.com).
            password: Mailbox password, optional.
            first_name/last_name: Optional.
            user_type: "user" (default), "alias", or "mailing_list".
            parent_id: Required, and only meaningful, when user_type="alias":
                the user this one aliases.
        """
        if scope_type not in _VALID_SCOPES:
            return _invalid_scope(scope_type)
        if not name or not name.strip():
            return error_envelope("invalid_argument", "name must be a non-empty username.")
        if user_type == "alias" and parent_id is None:
            return error_envelope(
                "invalid_argument", "parent_id is required when user_type is 'alias'."
            )

        async def _call(client: MailprotectorClient) -> str:
            user = await client.create_user(
                scope_type=scope_type,
                scope_id=scope_id,
                name=name.strip(),
                password=password,
                first_name=first_name,
                last_name=last_name,
                user_type=user_type,
                parent_id=parent_id,
            )
            return json.dumps(user, separators=(",", ":"), ensure_ascii=False)

        return await call_api(_call)

    @mcp.tool(annotations={"readOnlyHint": False, "idempotentHint": True})
    async def mailprotector_move_user(user_id: int, user_group_id: int) -> str:
        """Move a user to a different user group.

        Args:
            user_id: The user's numeric id.
            user_group_id: Numeric id of the user group to move the user into.
        """

        async def _call(client: MailprotectorClient) -> str:
            await client.move_user(user_id=user_id, user_group_id=user_group_id)
            return json.dumps(
                {"status": "moved", "user_id": user_id, "user_group_id": user_group_id},
                separators=(",", ":"),
                ensure_ascii=False,
            )

        return await call_api(_call)

    @mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False})
    async def mailprotector_delete_user(user_id: int) -> str:
        """Permanently delete a user. This cannot be undone.

        Args:
            user_id: The user's numeric id. Must be a specific, known id --
                this tool never accepts a filter or deletes more than one user.
        """

        async def _call(client: MailprotectorClient) -> str:
            await client.delete_user(user_id=user_id)
            return json.dumps(
                {"status": "deleted", "user_id": user_id}, separators=(",", ":"), ensure_ascii=False
            )

        return await call_api(_call)

    @mcp.tool(annotations={"readOnlyHint": True, "idempotentHint": True})
    async def mailprotector_get_user_message_stats(
        domain_id: int,
        date_start: str | None = None,
        date_end: str | None = None,
        direction: Literal["inbound", "outbound"] | None = None,
        limit: int = _DEFAULT_LIMIT,
        offset: int = 0,
    ) -> str:
        """Get per-user inbound/outbound message summaries for a domain.

        Args:
            domain_id: The domain's numeric id.
            date_start/date_end: Date range, e.g. "2026-10-01".
            direction: "inbound" or "outbound" only; omit for both.
            limit/offset: Pagination (limit default 50, hard cap 200).
        """
        limit = max(1, min(limit, _MAX_LIMIT))

        async def _call(client: MailprotectorClient) -> str:
            summaries = await client.get_user_message_stats(
                domain_id=domain_id,
                date_start=date_start,
                date_end=date_end,
                direction=direction,
                limit=limit,
                offset=offset,
            )
            return json.dumps(summaries, separators=(",", ":"), ensure_ascii=False)

        return await call_api(_call)
