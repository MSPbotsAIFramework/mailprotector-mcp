"""Tools for Mailprotector spam tolerance, general settings, and dashboard stats."""

from __future__ import annotations

import json
from typing import Literal

from mcp.server.fastmcp import FastMCP

from ..api_client import MailprotectorClient
from ..errors import error_envelope
from ..runtime import call_api

ScopeType = Literal["domain", "user_group", "user"]
_VALID_SCOPES: frozenset[str] = frozenset({"domain", "user_group", "user"})
SettingsScopeType = Literal["account", "domain", "user_group", "user"]
_VALID_SETTINGS_SCOPES: frozenset[str] = frozenset({"account", "domain", "user_group", "user"})
_MIN_SCORE = 0
_MAX_SCORE = 1000


def _invalid_scope(scope_type: str, valid: frozenset[str]) -> str:
    return error_envelope(
        "invalid_argument", f"scope_type must be one of {sorted(valid)}, got {scope_type!r}."
    )


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations={"readOnlyHint": True, "idempotentHint": True})
    async def mailprotector_get_spam_tolerance(scope_type: ScopeType, scope_id: int) -> str:
        """Get the effective spam-tolerance thresholds for a domain, user group,
        or user, and which entity they are currently inherited from.

        Args:
            scope_type: "domain", "user_group", or "user" -- what scope_id
                refers to.
            scope_id: The numeric id of that domain, user group, or user.
        """
        if scope_type not in _VALID_SCOPES:
            return _invalid_scope(scope_type, _VALID_SCOPES)

        async def _call(client: MailprotectorClient) -> str:
            tolerance = await client.get_spam_tolerance(scope_type=scope_type, scope_id=scope_id)
            return json.dumps(tolerance, separators=(",", ":"), ensure_ascii=False)

        return await call_api(_call)

    @mcp.tool(annotations={"readOnlyHint": False, "idempotentHint": True})
    async def mailprotector_set_spam_tolerance(
        scope_type: ScopeType,
        scope_id: int,
        possible_spam_min_score: int | None = None,
        possible_spam_max_score: int | None = None,
        possible_spam_text_location: Literal["header", "subject"] | None = None,
        possible_spam_text: str | None = None,
        reset: bool = False,
    ) -> str:
        """Set spam-tolerance thresholds, or reset to inherit from the parent.

        Args:
            scope_type/scope_id: Entity to set tolerance for.
            possible_spam_min_score/max_score: 0-1000, max >= min.
            possible_spam_text_location: "header" or "subject" for the marker.
            possible_spam_text: Marker text for possibly-spam messages.
            reset: If True, ignore other args and inherit from the parent.
        """
        if scope_type not in _VALID_SCOPES:
            return _invalid_scope(scope_type, _VALID_SCOPES)

        if not reset:
            for label, score in (
                ("possible_spam_min_score", possible_spam_min_score),
                ("possible_spam_max_score", possible_spam_max_score),
            ):
                if score is not None and not (_MIN_SCORE <= score <= _MAX_SCORE):
                    return error_envelope(
                        "invalid_argument",
                        f"{label} must be between {_MIN_SCORE} and {_MAX_SCORE}, got {score}.",
                    )
            if (
                possible_spam_min_score is not None
                and possible_spam_max_score is not None
                and possible_spam_max_score < possible_spam_min_score
            ):
                return error_envelope(
                    "invalid_argument",
                    "possible_spam_max_score must be >= possible_spam_min_score.",
                )

        async def _call(client: MailprotectorClient) -> str:
            if reset:
                await client.reset_spam_tolerance(scope_type=scope_type, scope_id=scope_id)
                return json.dumps({"status": "reset"}, separators=(",", ":"), ensure_ascii=False)
            tolerance = await client.set_spam_tolerance(
                scope_type=scope_type,
                scope_id=scope_id,
                possible_spam_min_score=possible_spam_min_score,
                possible_spam_max_score=possible_spam_max_score,
                possible_spam_text_location=possible_spam_text_location,
                possible_spam_text=possible_spam_text,
            )
            return json.dumps(tolerance, separators=(",", ":"), ensure_ascii=False)

        return await call_api(_call)

    @mcp.tool(annotations={"readOnlyHint": True, "idempotentHint": True})
    async def mailprotector_get_settings(scope_type: SettingsScopeType, scope_id: int) -> str:
        """Get the effective settings for an account, domain, user group, or user.

        Args:
            scope_type: "account", "domain", "user_group", or "user".
            scope_id: The numeric id of that account, domain, user group, or user.
        """
        if scope_type not in _VALID_SETTINGS_SCOPES:
            return _invalid_scope(scope_type, _VALID_SETTINGS_SCOPES)

        async def _call(client: MailprotectorClient) -> str:
            items = await client.get_settings(scope_type=scope_type, scope_id=scope_id)
            return json.dumps({"settings": items}, separators=(",", ":"), ensure_ascii=False)

        return await call_api(_call)

    @mcp.tool(annotations={"readOnlyHint": False, "idempotentHint": True})
    async def mailprotector_set_settings(
        scope_type: SettingsScopeType, scope_id: int, settings: list[dict[str, str]]
    ) -> str:
        """Set one or more named settings for an account, domain, user group, or
        user.

        Args:
            scope_type: "account", "domain", "user_group", or "user".
            scope_id: The numeric id of that account, domain, user group, or user.
            settings: List of {"name": <setting name>, "value": <new value>}.
        """
        if scope_type not in _VALID_SETTINGS_SCOPES:
            return _invalid_scope(scope_type, _VALID_SETTINGS_SCOPES)
        if not settings:
            return error_envelope("invalid_argument", "settings must contain at least one entry.")
        for item in settings:
            if not item.get("name"):
                return error_envelope("invalid_argument", "Each setting needs a non-empty 'name'.")
            if "value" not in item:
                return error_envelope("invalid_argument", "Each setting needs a 'value'.")

        async def _call(client: MailprotectorClient) -> str:
            await client.set_settings(scope_type=scope_type, scope_id=scope_id, items=settings)
            return json.dumps(
                {"status": "ok", "updated": len(settings)}, separators=(",", ":"), ensure_ascii=False
            )

        return await call_api(_call)

    @mcp.tool(annotations={"readOnlyHint": True, "idempotentHint": True})
    async def mailprotector_get_dashboard_stats() -> str:
        """Get the manager-scoped dashboard summary: spam/virus/policy/delivered
        counts and rates across every account and domain this manager can see.
        """

        async def _call(client: MailprotectorClient) -> str:
            summary = await client.get_dashboard_stats()
            return json.dumps({"summary": summary}, separators=(",", ":"), ensure_ascii=False)

        return await call_api(_call)
