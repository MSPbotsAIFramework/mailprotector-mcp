"""XML<->dict round-trip tests for api_client.py, using fixture XML copied
from https://github.com/mailprotector/mailprotector-api's own documented
examples (sections/*.md), not invented shapes.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from mailprotector_mcp.api_client import MailprotectorAPIError, MailprotectorClient

BASE_URL = "https://console.mailprotector.com"


@pytest.fixture
async def client():
    c = MailprotectorClient(auth_token="test-token", base_url=BASE_URL)
    yield c
    await c.aclose()


# -- Accounts ----------------------------------------------------------------

ACCOUNTS_XML = b"""<accounts type="array">
 <account>
   <id>128</id>
   <name>Test Account A</name>
   <account_status>Demo</account_status>
   <created_at>2010-02-15T13:49:45Z</created_at>
 </account>
 <account>
   <id>248</id>
   <name>Test Account B</name>
   <account_status>New</account_status>
   <created_at>2010-07-06T13:56:00Z</created_at>
 </account>
</accounts>"""

ACCOUNT_XML = b"""<account>
 <id>123</id>
 <name>Test Account</name>
 <account_status>Configured</account_status>
 <created_at>2010-07-06T15:37:15Z</created_at>
</account>"""


@respx.mock
async def test_list_accounts_parses_vendor_xml(client: MailprotectorClient) -> None:
    respx.get(f"{BASE_URL}/accounts.xml").mock(
        return_value=httpx.Response(200, content=ACCOUNTS_XML, headers={"Content-Type": "application/xml"})
    )
    items = await client.list_accounts(limit=50, offset=0)
    assert items == [
        {"id": 128, "name": "Test Account A", "account_status": "Demo", "created_at": "2010-02-15T13:49:45Z"},
        {"id": 248, "name": "Test Account B", "account_status": "New", "created_at": "2010-07-06T13:56:00Z"},
    ]


@respx.mock
async def test_get_account_parses_vendor_xml(client: MailprotectorClient) -> None:
    respx.get(f"{BASE_URL}/accounts/123.xml").mock(return_value=httpx.Response(200, content=ACCOUNT_XML))
    account = await client.get_account(123)
    assert account == {
        "id": 123,
        "name": "Test Account",
        "account_status": "Configured",
        "created_at": "2010-07-06T15:37:15Z",
    }


@respx.mock
async def test_get_account_404_raises_api_error_with_status(client: MailprotectorClient) -> None:
    respx.get(f"{BASE_URL}/accounts/999.xml").mock(return_value=httpx.Response(404, text="not found"))
    with pytest.raises(MailprotectorAPIError) as exc_info:
        await client.get_account(999)
    assert exc_info.value.status_code == 404


# -- Domains (nil parent_id, type attributes) --------------------------------

DOMAIN_XML = b"""<domain>
 <account_id type="integer">127</account_id>
 <created_at type="datetime">2010-07-07T20:39:56Z</created_at>
 <id type="integer">545</id>
 <name>addtest1.com</name>
 <parent_id type="integer" nil="true"></parent_id>
 <updated_at type="datetime">2010-07-07T20:39:57Z</updated_at>
</domain>"""


@respx.mock
async def test_get_domain_handles_nil_parent_id(client: MailprotectorClient) -> None:
    respx.get(f"{BASE_URL}/domains/545.xml").mock(return_value=httpx.Response(200, content=DOMAIN_XML))
    domain = await client.get_domain(545)
    assert domain == {"id": 545, "name": "addtest1.com", "account_id": 127, "parent_id": None}


@respx.mock
async def test_create_domain_posts_xml_body_and_parses_response(client: MailprotectorClient) -> None:
    route = respx.post(f"{BASE_URL}/domains.xml").mock(
        return_value=httpx.Response(201, content=DOMAIN_XML)
    )
    domain = await client.create_domain(name="addtest1.com", account_id=None, parent_id=None)
    assert domain["name"] == "addtest1.com"
    sent_body = route.calls.last.request.content
    assert b"<name>addtest1.com</name>" in sent_body


@respx.mock
async def test_create_domain_forbidden_raises_403(client: MailprotectorClient) -> None:
    respx.post(f"{BASE_URL}/domains.xml").mock(return_value=httpx.Response(403, text="Forbidden"))
    with pytest.raises(MailprotectorAPIError) as exc_info:
        await client.create_domain(name="x.com", account_id=None, parent_id=None)
    assert exc_info.value.status_code == 403


# -- Domain traffic report ----------------------------------------------------

TRAFFIC_REPORT_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<report>
  <traffic_summary>
    <blocked_percentage>76.92307692307693</blocked_percentage>
    <blocked_per_day>1</blocked_per_day>
    <spam_count>36</spam_count>
    <viruses_count/>
    <attacks_count/>
    <policy_count>0</policy_count>
    <delivered_count>12</delivered_count>
    <total_count>52</total_count>
  </traffic_summary>
  <users>
    <user>
      <id>620178</id>
      <name>alerts</name>
      <spam>0</spam>
      <virus>0</virus>
      <policy>0</policy>
      <delivered>0</delivered>
      <total>0</total>
    </user>
  </users>
</report>"""


@respx.mock
async def test_get_domain_traffic_report(client: MailprotectorClient) -> None:
    respx.get(f"{BASE_URL}/reports/domain_summary/545.xml").mock(
        return_value=httpx.Response(200, content=TRAFFIC_REPORT_XML)
    )
    report = await client.get_domain_traffic_report(domain_id=545, date_start=None, date_end=None)
    assert report["traffic_summary"]["spam_count"] == 36
    assert report["traffic_summary"]["viruses_count"] is None
    assert report["users"] == [
        {"id": 620178, "name": "alerts", "spam": 0, "virus": 0, "policy": 0, "delivered": 0, "total": 0}
    ]


# -- User groups ---------------------------------------------------------

USER_GROUPS_XML = b"""<user-groups type="array">
 <user_group>
   <domain_id type="integer">32</domain_id>
   <id type="integer">303</id>
   <name>observers</name>
   <created_at>2013-06-04 20:27:28 UTC</created_at>
   <services>
     <service>CloudFilter Email Security</service>
     <service>Exchange+ Premium</service>
   </services>
   <user_count>5</user_count>
 </user_group>
</user-groups>"""


@respx.mock
async def test_list_user_groups_parses_services_list(client: MailprotectorClient) -> None:
    respx.get(f"{BASE_URL}/domains/32/user_groups.xml").mock(
        return_value=httpx.Response(200, content=USER_GROUPS_XML)
    )
    groups = await client.list_user_groups(domain_id=32)
    assert groups == [
        {
            "id": 303,
            "name": "observers",
            "domain_id": 32,
            "services": ["CloudFilter Email Security", "Exchange+ Premium"],
            "user_count": 5,
            "created_at": "2013-06-04 20:27:28 UTC",
        }
    ]


# -- Users -----------------------------------------------------------------

USERS_XML = b"""<users type="array">
 <user>
   <id>3314</id>
   <name>johndoe</name>
   <user_type>user</user_type>
   <parent_id></parent_id>
   <domain_id>32</domain_id>
   <user_group_id>64</user_group_id>
   <first_name>John</first_name>
   <last_name>Doe</last_name>
   <created_at>2010-04-05 21:19:54 UTC</created_at>
 </user>
</users>"""


@respx.mock
async def test_list_users_handles_empty_parent_id(client: MailprotectorClient) -> None:
    respx.get(f"{BASE_URL}/user_groups/64/users.xml").mock(
        return_value=httpx.Response(200, content=USERS_XML)
    )
    users = await client.list_users(scope_type="user_group", scope_id=64, limit=50, offset=0)
    assert users[0]["parent_id"] is None
    assert users[0]["name"] == "johndoe"


@respx.mock
async def test_move_user_sends_bare_value_body(client: MailprotectorClient) -> None:
    route = respx.post(f"{BASE_URL}/users/3314/move.xml").mock(return_value=httpx.Response(200))
    await client.move_user(user_id=3314, user_group_id=27)
    assert route.calls.last.request.content == (
        b"<?xml version='1.0' encoding='utf-8'?>\n<user_group_id>27</user_group_id>"
    )


@respx.mock
async def test_delete_user_calls_delete_verb(client: MailprotectorClient) -> None:
    route = respx.delete(f"{BASE_URL}/users/3314.xml").mock(return_value=httpx.Response(200))
    await client.delete_user(user_id=3314)
    assert route.called


@respx.mock
async def test_delete_unknown_user_raises_404(client: MailprotectorClient) -> None:
    respx.delete(f"{BASE_URL}/users/9999.xml").mock(return_value=httpx.Response(404, text="not found"))
    with pytest.raises(MailprotectorAPIError) as exc_info:
        await client.delete_user(user_id=9999)
    assert exc_info.value.status_code == 404


# -- Message summaries --------------------------------------------------------

MESSAGE_SUMMARIES_XML = b"""<message_summaries>
    <inbound_summaries>
      <user_summary>
        <user_id>79783</user_id>
        <username>abuse</username>
        <spam>0</spam>
        <virus>0</virus>
        <policy>0</policy>
        <delivered>0</delivered>
        <total>0</total>
      </user_summary>
    </inbound_summaries>
    <outbound_summaries>
      <user_summary>
        <user_id>79783</user_id>
        <username>abuse</username>
        <spam>0</spam>
        <virus>0</virus>
        <policy>0</policy>
        <delivered>0</delivered>
        <total>0</total>
      </user_summary>
    </outbound_summaries>
</message_summaries>"""


@respx.mock
async def test_get_user_message_stats_keeps_summaries_as_lists(client: MailprotectorClient) -> None:
    respx.get(f"{BASE_URL}/domains/32/messages.xml").mock(
        return_value=httpx.Response(200, content=MESSAGE_SUMMARIES_XML)
    )
    stats = await client.get_user_message_stats(
        domain_id=32, date_start=None, date_end=None, direction=None, limit=50, offset=0
    )
    assert isinstance(stats["inbound_summaries"], list)
    assert isinstance(stats["outbound_summaries"], list)
    assert stats["inbound_summaries"][0]["username"] == "abuse"


# -- Allow/block rules ---------------------------------------------------

RULES_XML = b"""<rules>
 <rule>
   <address>allowtestdomain.com</address>
   <type>allow</type>
 </rule>
 <rule>
   <address>blocktestdomain.com</address>
   <type>block</type>
 </rule>
</rules>"""


@respx.mock
async def test_list_allow_block_rules(client: MailprotectorClient) -> None:
    respx.get(f"{BASE_URL}/domains/545/allow_block_rules.xml").mock(
        return_value=httpx.Response(200, content=RULES_XML)
    )
    rules = await client.list_allow_block_rules(scope_type="domain", scope_id=545, rule_type=None)
    assert rules == [
        {"address": "allowtestdomain.com", "type": "allow"},
        {"address": "blocktestdomain.com", "type": "block"},
    ]


@respx.mock
async def test_add_allow_block_rules_hits_create_endpoint(client: MailprotectorClient) -> None:
    route = respx.post(f"{BASE_URL}/domains/545/allow_block_rules.xml").mock(
        return_value=httpx.Response(200)
    )
    await client.add_allow_block_rules(
        scope_type="domain", scope_id=545, rules=[{"address": "spam.example.com", "type": "block"}]
    )
    assert route.called
    assert b"<address>spam.example.com</address>" in route.calls.last.request.content


@respx.mock
async def test_remove_allow_block_rules_hits_destroy_endpoint(client: MailprotectorClient) -> None:
    route = respx.post(f"{BASE_URL}/domains/545/allow_block_rules/destroy_rules.xml").mock(
        return_value=httpx.Response(200)
    )
    await client.remove_allow_block_rules(
        scope_type="domain", scope_id=545, rules=[{"address": "spam.example.com", "type": "block"}]
    )
    assert route.called


# -- Spam tolerance ------------------------------------------------------

SPAM_TOLERANCE_XML = b"""<spam_tolerance>
 <entity_type>Domain</entity_type>
 <entity_id>32</entity_id>
 <possible_spam_min_score>220</possible_spam_min_score>
 <possible_spam_max_score>280</possible_spam_max_score>
 <possible_spam_text_location>subject</possible_spam_text_location>
 <possible_spam_text>[Possible spam]</possible_spam_text>
</spam_tolerance>"""


@respx.mock
async def test_get_spam_tolerance_parses_inherited_entity(client: MailprotectorClient) -> None:
    respx.get(f"{BASE_URL}/domains/32/spam_tolerance.xml").mock(
        return_value=httpx.Response(200, content=SPAM_TOLERANCE_XML)
    )
    tolerance = await client.get_spam_tolerance(scope_type="domain", scope_id=32)
    assert tolerance["entity_type"] == "Domain"
    assert tolerance["possible_spam_min_score"] == 220


@respx.mock
async def test_reset_spam_tolerance_calls_reset_endpoint(client: MailprotectorClient) -> None:
    route = respx.get(f"{BASE_URL}/domains/32/reset_spam_tolerance.xml").mock(
        return_value=httpx.Response(200)
    )
    await client.reset_spam_tolerance(scope_type="domain", scope_id=32)
    assert route.called


# -- Settings --------------------------------------------------------------

SETTINGS_XML = b"""<settings type="array">
 <setting>
   <entity_id type="integer">32</entity_id>
   <entity_type>Domain</entity_type>
   <name>inbound_smtp_host</name>
   <value>10.1.16.8</value>
 </setting>
</settings>"""


@respx.mock
async def test_get_settings_parses_list(client: MailprotectorClient) -> None:
    respx.get(f"{BASE_URL}/accounts/127/settings.xml").mock(
        return_value=httpx.Response(200, content=SETTINGS_XML)
    )
    items = await client.get_settings(scope_type="account", scope_id=127)
    assert items == [{"entity_id": 32, "entity_type": "Domain", "name": "inbound_smtp_host", "value": "10.1.16.8"}]


@respx.mock
async def test_set_settings_hits_set_settings_endpoint(client: MailprotectorClient) -> None:
    route = respx.post(f"{BASE_URL}/accounts/127/set_settings.xml").mock(return_value=httpx.Response(200))
    await client.set_settings(
        scope_type="account", scope_id=127, items=[{"name": "digest_report_enabled", "value": "false"}]
    )
    assert route.called
    assert b"<name>digest_report_enabled</name>" in route.calls.last.request.content


# -- Dashboard stats (kebab-case tags, trimmed to summary) ---------------

DASHBOARD_XML = b"""<statistics>
  <summary>
    <spam-count type="integer">88087</spam-count>
    <virus-count type="integer">4739</virus-count>
    <blocked-percentage type="float">95.78874218207089</blocked-percentage>
    <time-between-spam-label>seconds</time-between-spam-label>
  </summary>
  <data>
    <inbound><has-data type="boolean">true</has-data></inbound>
  </data>
</statistics>"""


@respx.mock
async def test_get_dashboard_stats_trims_to_summary_and_normalizes_keys(
    client: MailprotectorClient,
) -> None:
    respx.get(f"{BASE_URL}/dashboard.xml").mock(return_value=httpx.Response(200, content=DASHBOARD_XML))
    summary = await client.get_dashboard_stats()
    assert summary == {
        "spam_count": 88087,
        "virus_count": 4739,
        "blocked_percentage": 95.78874218207089,
        "time_between_spam_label": "seconds",
    }
    assert "data" not in summary


# -- Network robustness ---------------------------------------------------


@respx.mock
async def test_retries_on_429_then_succeeds(client: MailprotectorClient) -> None:
    route = respx.get(f"{BASE_URL}/accounts/1.xml").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "0"}),
            httpx.Response(200, content=ACCOUNT_XML.replace(b"123", b"1")),
        ]
    )
    account = await client.get_account(1)
    assert route.call_count == 2
    assert account["id"] == 1


@respx.mock
async def test_does_not_retry_on_400(client: MailprotectorClient) -> None:
    route = respx.post(f"{BASE_URL}/domains.xml").mock(return_value=httpx.Response(400, text="bad"))
    with pytest.raises(MailprotectorAPIError) as exc_info:
        await client.create_domain(name="x.com", account_id=None, parent_id=None)
    assert exc_info.value.status_code == 400
    assert route.call_count == 1
