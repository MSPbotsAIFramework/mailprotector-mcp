"""Tools for Mailprotector allow/block (sender) rules."""

from __future__ import annotations

import json
from typing import Literal

from mcp.server.fastmcp import FastMCP

from ..api_client import MailprotectorClient
from ..errors import error_envelope
from ..runtime import call_api

ScopeType = Literal["domain", "user_group", "user"]
_VALID_SCOPES: frozenset[str] = frozenset({"domain", "user_group", "user"})
_VALID_RULE_TYPES: frozenset[str] = frozenset({"allow", "block"})


def _invalid_scope(scope_type: str) -> str:
    return error_envelope(
        "invalid_argument",
        f"scope_type must be one of {sorted(_VALID_SCOPES)}, got {scope_type!r}.",
    )


def _validate_rules(rules: list[dict[str, str]]) -> str | None:
    if not rules:
        return error_envelope("invalid_argument", "rules must contain at least one entry.")
    for rule in rules:
        address = rule.get("address")
        rule_type = rule.get("type")
        if not address or not str(address).strip():
            return error_envelope("invalid_argument", "Each rule needs a non-empty 'address'.")
        if rule_type not in _VALID_RULE_TYPES:
            return error_envelope(
                "invalid_argument",
                f"Each rule's 'type' must be one of {sorted(_VALID_RULE_TYPES)}, got {rule_type!r}.",
            )
    return None


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations={"readOnlyHint": True, "idempotentHint": True})
    async def mailprotector_list_allow_block_rules(
        scope_type: ScopeType, scope_id: int, rule_type: Literal["allow", "block"] | None = None
    ) -> str:
        """List the allow/block rules in effect for a domain, user group, or user.

        Args:
            scope_type/scope_id: What to list rules for.
            rule_type: "allow" or "block" to filter to one list; omit for both.
        """
        if scope_type not in _VALID_SCOPES:
            return _invalid_scope(scope_type)

        async def _call(client: MailprotectorClient) -> str:
            items = await client.list_allow_block_rules(
                scope_type=scope_type, scope_id=scope_id, rule_type=rule_type
            )
            return json.dumps({"rules": items}, separators=(",", ":"), ensure_ascii=False)

        return await call_api(_call)

    @mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True})
    async def mailprotector_set_allow_block_rules(
        scope_type: ScopeType,
        scope_id: int,
        rules: list[dict[str, str]],
        action: Literal["add", "remove"] = "add",
    ) -> str:
        """Add or remove allow/block rules for a domain, user group, or user.

        "remove" is destructive: only exact address+type pairs are accepted,
        never a wildcard or an empty list that would clear every rule.

        Args:
            scope_type/scope_id: What to apply the rules to.
            rules: [{"address": <email or domain>, "type": "allow"|"block"}].
            action: "add" (default) or "remove".
        """
        if scope_type not in _VALID_SCOPES:
            return _invalid_scope(scope_type)
        validation_error = _validate_rules(rules)
        if validation_error is not None:
            return validation_error

        async def _call(client: MailprotectorClient) -> str:
            if action == "remove":
                await client.remove_allow_block_rules(
                    scope_type=scope_type, scope_id=scope_id, rules=rules
                )
            else:
                await client.add_allow_block_rules(
                    scope_type=scope_type, scope_id=scope_id, rules=rules
                )
            return json.dumps(
                {"status": "ok", "applied": len(rules)}, separators=(",", ":"), ensure_ascii=False
            )

        return await call_api(_call)
