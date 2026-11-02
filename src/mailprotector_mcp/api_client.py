"""Thin async wrapper around the Mailprotector Console API.

Mailprotector's API (https://github.com/mailprotector/mailprotector-api) is
plain XML over HTTP, authenticated with a per-manager token sent as the HTTP
Basic username (dummy password). It has no JSON mode, so this module also
does the XML <-> dict translation at the boundary -- tools never see raw XML.

One client instance is built per request (see server.py's credential
middleware) and is never shared or cached across requests/tenants.
"""

from __future__ import annotations

import asyncio
import xml.etree.ElementTree as ET
from typing import Any, Iterable

import httpx

DEFAULT_BASE_URL = "https://console.mailprotector.com"

# Connect fast-fails, read tolerates the vendor being slow; well under the
# SOP's <120s total-call budget even with retries.
_CONNECT_TIMEOUT = 5.0
_READ_TIMEOUT = 30.0
_MAX_RETRIES = 3
_RETRY_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


class MailprotectorAPIError(Exception):
    """Raised for any non-2xx response or transport failure.

    Carries the upstream status_code (0 for connect/timeout failures with no
    response at all) so the tools layer can map it to the structured error
    vocabulary in errors.py -- this module itself never constructs that
    envelope, it only reports what happened.
    """

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


# ---------------------------------------------------------------------------
# XML parsing helpers
#
# The vendor's XML is flat and shallow (see docs/tickets/PRD-21253.md "Current
# state"): no namespaces, no deep nesting beyond one list-of-records level.
# Each resource gets its own small, explicit parser below rather than one
# generic auto-detecting XML->dict converter -- a generic converter cannot
# reliably tell "one item" from "a list with one item" (e.g. message_summaries
# below), and guessing wrong would silently return the wrong shape to tools.
# ---------------------------------------------------------------------------


def _is_nil(elem: ET.Element) -> bool:
    return elem.get("nil") == "true"


def _child(elem: ET.Element, tag: str) -> ET.Element | None:
    return elem.find(tag)


def _str(elem: ET.Element, tag: str) -> str | None:
    child = _child(elem, tag)
    if child is None or _is_nil(child):
        return None
    text = (child.text or "").strip()
    return text or None


def _int(elem: ET.Element, tag: str) -> int | None:
    text = _str(elem, tag)
    return int(text) if text is not None else None


def _float(elem: ET.Element, tag: str) -> float | None:
    text = _str(elem, tag)
    return float(text) if text is not None else None


def _parse_account(elem: ET.Element) -> dict[str, Any]:
    return {
        "id": _int(elem, "id"),
        "name": _str(elem, "name"),
        "account_status": _str(elem, "account_status"),
        "created_at": _str(elem, "created_at"),
    }


def _parse_accounts(root: ET.Element) -> list[dict[str, Any]]:
    return [_parse_account(e) for e in root.findall("account")]


def _parse_domain(elem: ET.Element) -> dict[str, Any]:
    return {
        "id": _int(elem, "id"),
        "name": _str(elem, "name"),
        "account_id": _int(elem, "account_id"),
        "parent_id": _int(elem, "parent_id"),
    }


def _parse_domains(root: ET.Element) -> list[dict[str, Any]]:
    return [_parse_domain(e) for e in root.findall("domain")]


def _parse_traffic_report(root: ET.Element) -> dict[str, Any]:
    summary_elem = root.find("traffic_summary")
    summary: dict[str, Any] = {}
    if summary_elem is not None:
        summary = {
            "blocked_percentage": _float(summary_elem, "blocked_percentage"),
            "blocked_per_day": _int(summary_elem, "blocked_per_day"),
            "spam_count": _int(summary_elem, "spam_count"),
            "viruses_count": _int(summary_elem, "viruses_count"),
            "attacks_count": _int(summary_elem, "attacks_count"),
            "policy_count": _int(summary_elem, "policy_count"),
            "delivered_count": _int(summary_elem, "delivered_count"),
            "total_count": _int(summary_elem, "total_count"),
        }
    users_elem = root.find("users")
    users = []
    if users_elem is not None:
        for u in users_elem.findall("user"):
            users.append(
                {
                    "id": _int(u, "id"),
                    "name": _str(u, "name"),
                    "spam": _int(u, "spam"),
                    "virus": _int(u, "virus"),
                    "policy": _int(u, "policy"),
                    "delivered": _int(u, "delivered"),
                    "total": _int(u, "total"),
                }
            )
    return {"traffic_summary": summary, "users": users}


def _parse_user_group(elem: ET.Element) -> dict[str, Any]:
    services_elem = elem.find("services")
    services = (
        [(s.text or "").strip() for s in services_elem.findall("service")]
        if services_elem is not None
        else []
    )
    return {
        "id": _int(elem, "id"),
        "name": _str(elem, "name"),
        "domain_id": _int(elem, "domain_id"),
        "services": services,
        "user_count": _int(elem, "user_count"),
        "created_at": _str(elem, "created_at"),
    }


def _parse_user_groups(root: ET.Element) -> list[dict[str, Any]]:
    return [_parse_user_group(e) for e in root.findall("user_group")]


def _parse_user(elem: ET.Element) -> dict[str, Any]:
    return {
        "id": _int(elem, "id"),
        "name": _str(elem, "name"),
        "user_type": _str(elem, "user_type"),
        "parent_id": _int(elem, "parent_id"),
        "domain_id": _int(elem, "domain_id"),
        "user_group_id": _int(elem, "user_group_id"),
        "first_name": _str(elem, "first_name"),
        "last_name": _str(elem, "last_name"),
        "created_at": _str(elem, "created_at"),
    }


def _parse_users(root: ET.Element) -> list[dict[str, Any]]:
    return [_parse_user(e) for e in root.findall("user")]


def _parse_message_summary(elem: ET.Element) -> dict[str, Any]:
    return {
        "user_id": _int(elem, "user_id"),
        "username": _str(elem, "username"),
        "spam": _int(elem, "spam"),
        "virus": _int(elem, "virus"),
        "policy": _int(elem, "policy"),
        "delivered": _int(elem, "delivered"),
        "total": _int(elem, "total"),
    }


def _parse_message_summaries(root: ET.Element) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    inbound_elem = root.find("inbound_summaries")
    if inbound_elem is not None:
        result["inbound_summaries"] = [
            _parse_message_summary(e) for e in inbound_elem.findall("user_summary")
        ]
    outbound_elem = root.find("outbound_summaries")
    if outbound_elem is not None:
        result["outbound_summaries"] = [
            _parse_message_summary(e) for e in outbound_elem.findall("user_summary")
        ]
    return result


def _parse_rule(elem: ET.Element) -> dict[str, Any]:
    return {"address": _str(elem, "address"), "type": _str(elem, "type")}


def _parse_rules(root: ET.Element) -> list[dict[str, Any]]:
    return [_parse_rule(e) for e in root.findall("rule")]


def _parse_spam_tolerance(root: ET.Element) -> dict[str, Any]:
    return {
        "entity_type": _str(root, "entity_type"),
        "entity_id": _int(root, "entity_id"),
        "possible_spam_min_score": _int(root, "possible_spam_min_score"),
        "possible_spam_max_score": _int(root, "possible_spam_max_score"),
        "possible_spam_text_location": _str(root, "possible_spam_text_location"),
        "possible_spam_text": _str(root, "possible_spam_text"),
    }


def _parse_setting(elem: ET.Element) -> dict[str, Any]:
    return {
        "entity_id": _int(elem, "entity_id"),
        "entity_type": _str(elem, "entity_type"),
        "name": _str(elem, "name"),
        "value": _str(elem, "value"),
    }


def _parse_settings(root: ET.Element) -> list[dict[str, Any]]:
    return [_parse_setting(e) for e in root.findall("setting")]


def _parse_dashboard_summary(root: ET.Element) -> dict[str, Any]:
    # The vendor's /dashboard.xml also includes a multi-week, per-direction
    # day-by-day series (<data>) meant to drive the console's charts. That
    # series alone is tens of thousands of characters -- returning it would
    # blow the SOP's 20,000-char per-call budget (SOP Sec 2.5) for a tool
    # whose AC only asks for "the dashboard summary". We trim to <summary>,
    # which already carries every headline figure the console shows.
    summary_elem = root.find("summary")
    if summary_elem is None:
        return {}
    # The vendor uses kebab-case tags here (unlike every other resource,
    # which uses snake_case) -- normalize to snake_case for a consistent
    # JSON shape across all 20 tools.
    return {
        child.tag.replace("-", "_"): _coerce_scalar(child)
        for child in summary_elem
    }


def _coerce_scalar(elem: ET.Element) -> Any:
    text = (elem.text or "").strip()
    type_attr = elem.get("type")
    if text == "":
        return None
    if type_attr == "integer":
        return int(text)
    if type_attr == "float":
        return float(text)
    return text


# ---------------------------------------------------------------------------
# XML request-body builders
# ---------------------------------------------------------------------------


def _build_flat_xml(root_tag: str, fields: dict[str, Any]) -> bytes:
    root = ET.Element(root_tag)
    for key, value in fields.items():
        if value is None:
            continue
        child = ET.SubElement(root, key)
        child.text = str(value)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _build_bare_value_xml(tag: str, value: Any) -> bytes:
    root = ET.Element(tag)
    root.text = str(value)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _build_rules_xml(rules: Iterable[dict[str, str]]) -> bytes:
    root = ET.Element("rules")
    for rule in rules:
        rule_elem = ET.SubElement(root, "rule")
        ET.SubElement(rule_elem, "address").text = str(rule["address"])
        ET.SubElement(rule_elem, "type").text = str(rule["type"])
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _build_settings_xml(items: Iterable[dict[str, str]]) -> bytes:
    root = ET.Element("settings")
    for item in items:
        setting_elem = ET.SubElement(root, "setting")
        ET.SubElement(setting_elem, "name").text = str(item["name"])
        ET.SubElement(setting_elem, "value").text = str(item["value"])
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


_SCOPE_PATH = {
    "account": "accounts",
    "domain": "domains",
    "user_group": "user_groups",
    "user": "users",
}


class MailprotectorClient:
    """One instance per request; built from that request's own credentials."""

    def __init__(self, auth_token: str, base_url: str | None = None) -> None:
        self._auth_token = auth_token
        self._client = httpx.AsyncClient(
            base_url=base_url or DEFAULT_BASE_URL,
            auth=(auth_token, "X"),
            headers={"Accept": "application/xml"},
            timeout=httpx.Timeout(connect=_CONNECT_TIMEOUT, read=_READ_TIMEOUT, write=_READ_TIMEOUT, pool=_READ_TIMEOUT),
        )
        # Set by _request on every attempt (success, retry, or final
        # failure) so runtime.call_api can log "what did this tool actually
        # call" without _request needing to know anything about logging.
        # status_code is 0 for a transport/timeout failure with no response.
        self.last_call: dict[str, Any] | None = None

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "MailprotectorClient":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: bytes | None = None,
    ) -> ET.Element | None:
        params = {k: v for k, v in (params or {}).items() if v is not None}
        headers = {"Content-Type": "application/xml"} if body is not None else None
        last_error: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                response = await self._client.request(
                    method, path, params=params, content=body, headers=headers
                )
            except httpx.TimeoutException as exc:
                last_error = exc
                self.last_call = {"method": method, "path": path, "status_code": 0}
                raise MailprotectorAPIError(0, f"Timed out calling Mailprotector: {exc}") from exc
            except httpx.TransportError as exc:
                last_error = exc
                self.last_call = {"method": method, "path": path, "status_code": 0}
                raise MailprotectorAPIError(0, f"Network error calling Mailprotector: {exc}") from exc

            self.last_call = {"method": method, "path": path, "status_code": response.status_code}

            if response.status_code < 400:
                if not response.content:
                    return None
                return ET.fromstring(response.content)

            if response.status_code in _RETRY_STATUS_CODES and attempt < _MAX_RETRIES - 1:
                retry_after = response.headers.get("Retry-After")
                delay = float(retry_after) if retry_after and retry_after.isdigit() else (2**attempt)
                await asyncio.sleep(min(delay, 10.0))
                continue

            raise MailprotectorAPIError(
                response.status_code,
                f"{method} {path} -> {response.status_code}: {response.text[:500]}",
            )
        # Unreachable in practice (loop always returns or raises), kept for mypy.
        self.last_call = {"method": method, "path": path, "status_code": 0}
        raise MailprotectorAPIError(0, f"Exhausted retries calling Mailprotector: {last_error}")

    # -- Accounts ----------------------------------------------------------

    async def list_accounts(self, *, limit: int, offset: int) -> list[dict[str, Any]]:
        root = await self._request("GET", "/accounts.xml", params={"limit": limit, "offset": offset})
        return _parse_accounts(root) if root is not None else []

    async def get_account(self, account_id: int) -> dict[str, Any]:
        root = await self._request("GET", f"/accounts/{account_id}.xml")
        return _parse_account(root)

    # -- Domains -------------------------------------------------------------

    async def list_domains(
        self, *, account_id: int | None, limit: int, offset: int
    ) -> list[dict[str, Any]]:
        path = f"/accounts/{account_id}/domains.xml" if account_id is not None else "/domains.xml"
        root = await self._request("GET", path, params={"limit": limit, "offset": offset})
        return _parse_domains(root) if root is not None else []

    async def get_domain(self, domain_id: int) -> dict[str, Any]:
        root = await self._request("GET", f"/domains/{domain_id}.xml")
        return _parse_domain(root)

    async def create_domain(
        self, *, name: str, account_id: int | None, parent_id: int | None
    ) -> dict[str, Any]:
        path = f"/accounts/{account_id}/domains.xml" if account_id is not None else "/domains.xml"
        body = _build_flat_xml("domain", {"name": name, "parent_id": parent_id})
        root = await self._request("POST", path, body=body)
        return _parse_domain(root)

    async def get_domain_traffic_report(
        self, *, domain_id: int, date_start: str | None, date_end: str | None
    ) -> dict[str, Any]:
        root = await self._request(
            "GET",
            f"/reports/domain_summary/{domain_id}.xml",
            params={"date_start": date_start, "date_end": date_end},
        )
        return _parse_traffic_report(root) if root is not None else {"traffic_summary": {}, "users": []}

    # -- User groups / users ---------------------------------------------------

    async def list_user_groups(self, *, domain_id: int) -> list[dict[str, Any]]:
        root = await self._request("GET", f"/domains/{domain_id}/user_groups.xml")
        return _parse_user_groups(root) if root is not None else []

    async def list_users(
        self, *, scope_type: str, scope_id: int, limit: int, offset: int
    ) -> list[dict[str, Any]]:
        path = f"/{_SCOPE_PATH[scope_type]}/{scope_id}/users.xml"
        root = await self._request("GET", path, params={"limit": limit, "offset": offset})
        return _parse_users(root) if root is not None else []

    async def get_user(self, user_id: int) -> dict[str, Any]:
        root = await self._request("GET", f"/users/{user_id}.xml")
        return _parse_user(root)

    async def create_user(
        self,
        *,
        scope_type: str,
        scope_id: int,
        name: str,
        password: str | None,
        first_name: str | None,
        last_name: str | None,
        user_type: str | None,
        parent_id: int | None,
    ) -> dict[str, Any]:
        path = f"/{_SCOPE_PATH[scope_type]}/{scope_id}/users.xml"
        body = _build_flat_xml(
            "user",
            {
                "name": name,
                "password": password,
                "first_name": first_name,
                "last_name": last_name,
                "user_type": user_type,
                "parent_id": parent_id,
            },
        )
        root = await self._request("POST", path, body=body)
        return _parse_user(root)

    async def move_user(self, *, user_id: int, user_group_id: int) -> None:
        body = _build_bare_value_xml("user_group_id", user_group_id)
        await self._request("POST", f"/users/{user_id}/move.xml", body=body)

    async def delete_user(self, *, user_id: int) -> None:
        await self._request("DELETE", f"/users/{user_id}.xml")

    async def get_user_message_stats(
        self,
        *,
        domain_id: int,
        date_start: str | None,
        date_end: str | None,
        direction: str | None,
        limit: int,
        offset: int,
    ) -> dict[str, list[dict[str, Any]]]:
        root = await self._request(
            "GET",
            f"/domains/{domain_id}/messages.xml",
            params={
                "date_start": date_start,
                "date_end": date_end,
                "direction": direction,
                "limit": limit,
                "offset": offset,
            },
        )
        return _parse_message_summaries(root) if root is not None else {}

    # -- Allow/block rules -----------------------------------------------------

    async def list_allow_block_rules(
        self, *, scope_type: str, scope_id: int, rule_type: str | None
    ) -> list[dict[str, Any]]:
        path = f"/{_SCOPE_PATH[scope_type]}/{scope_id}/allow_block_rules.xml"
        root = await self._request("GET", path, params={"rule_type": rule_type})
        return _parse_rules(root) if root is not None else []

    async def add_allow_block_rules(
        self, *, scope_type: str, scope_id: int, rules: list[dict[str, str]]
    ) -> None:
        path = f"/{_SCOPE_PATH[scope_type]}/{scope_id}/allow_block_rules.xml"
        await self._request("POST", path, body=_build_rules_xml(rules))

    async def remove_allow_block_rules(
        self, *, scope_type: str, scope_id: int, rules: list[dict[str, str]]
    ) -> None:
        path = f"/{_SCOPE_PATH[scope_type]}/{scope_id}/allow_block_rules/destroy_rules.xml"
        await self._request("POST", path, body=_build_rules_xml(rules))

    # -- Spam tolerance ----------------------------------------------------

    async def get_spam_tolerance(self, *, scope_type: str, scope_id: int) -> dict[str, Any]:
        path = f"/{_SCOPE_PATH[scope_type]}/{scope_id}/spam_tolerance.xml"
        root = await self._request("GET", path)
        return _parse_spam_tolerance(root)

    async def set_spam_tolerance(
        self,
        *,
        scope_type: str,
        scope_id: int,
        possible_spam_min_score: int | None,
        possible_spam_max_score: int | None,
        possible_spam_text_location: str | None,
        possible_spam_text: str | None,
    ) -> dict[str, Any]:
        path = f"/{_SCOPE_PATH[scope_type]}/{scope_id}/spam_tolerance.xml"
        body = _build_flat_xml(
            "spam_tolerance",
            {
                "possible_spam_min_score": possible_spam_min_score,
                "possible_spam_max_score": possible_spam_max_score,
                "possible_spam_text_location": possible_spam_text_location,
                "possible_spam_text": possible_spam_text,
            },
        )
        root = await self._request("POST", path, body=body)
        if root is not None:
            return _parse_spam_tolerance(root)
        return await self.get_spam_tolerance(scope_type=scope_type, scope_id=scope_id)

    async def reset_spam_tolerance(self, *, scope_type: str, scope_id: int) -> None:
        path = f"/{_SCOPE_PATH[scope_type]}/{scope_id}/reset_spam_tolerance.xml"
        await self._request("GET", path)

    # -- Settings --------------------------------------------------------------

    async def get_settings(self, *, scope_type: str, scope_id: int) -> list[dict[str, Any]]:
        path = f"/{_SCOPE_PATH[scope_type]}/{scope_id}/settings.xml"
        root = await self._request("GET", path)
        return _parse_settings(root) if root is not None else []

    async def set_settings(
        self, *, scope_type: str, scope_id: int, items: list[dict[str, str]]
    ) -> None:
        path = f"/{_SCOPE_PATH[scope_type]}/{scope_id}/set_settings.xml"
        await self._request("POST", path, body=_build_settings_xml(items))

    # -- Dashboard ---------------------------------------------------------

    async def get_dashboard_stats(self) -> dict[str, Any]:
        root = await self._request("GET", "/dashboard.xml")
        return _parse_dashboard_summary(root) if root is not None else {}
