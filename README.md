# mailprotector-mcp

MCP server for [Mailprotector](https://www.mailprotector.com/) -- an email-security
service (spam/virus filtering, allow/block lists, per-domain traffic reporting) --
for the MSPbots Agent platform.

- Transport: MCP Streamable HTTP (`POST /mcp`), stateless, plus a local `GET /health` probe.
- Stack: Python 3.12, [FastMCP](https://github.com/modelcontextprotocol/python-sdk), `httpx`.
- License: Apache-2.0. Copyright MSPbots.ai.

This connector talks to Mailprotector's public, vendor-maintained API
(https://github.com/mailprotector/mailprotector-api), which is XML over HTTP.
This service translates XML to/from JSON at the boundary -- callers never see
raw XML.

<div align="center">

## MSPbots Connector

**The MCP Gateway built for MSPs: visible, controlled, and your data stays where it belongs.**

[**Get started at connect.mspbots.ai →**](https://connect.mspbots.ai)

</div>

---

MSPbots Connector gives your AI clients one MCP URL to reach your entire MSP stack (RMM, PSA, documentation, security, finance), and gives you control over who can call which tool and a record of everything that was called.

**Hosted service: [connect.mspbots.ai](https://connect.mspbots.ai)** · Free to use.

### Why Connector

![MSPbots Connector](https://stgoss.mspbots.ai/files/mcp/mspbots-mcp.png)

| | |
|---|---|
| **Visible** | Every tool call is logged: who, which vendor, when. Usage dashboard, CSV export, SIEM streaming. |
| **Controlled** | Role-based, per-tool allowlist. Deny by default. |
| **Protected** | Credentials encrypted per record. AI clients never see your vendor passwords or tokens. |
| **MSP-native** | Built for the MSP stack only: RMM, PSA, documentation, security, finance. |

### Quick start

1. **Sign up** at [connect.mspbots.ai](https://connect.mspbots.ai).
2. **Connect your vendors.** Pick from 150+ connectors and authorize each one on the vendor's own page, or bring your own API keys. No extra vendor accounts needed.
3. **Set access.** Create roles and decide which tools each role may call. Nothing is allowed until you allow it.
4. **Add your MCP URL to your AI client.** Copy the URL from your Connector dashboard into Claude, ChatGPT, Cursor, VS Code, Gemini, Codex, or any MCP-capable client.
5. **Ask your AI to do real work**, and watch every call appear in the audit log.

### Features

**Unified gateway**
- One MCP URL for all your AI clients
- 150+ connectors across the MSP stack
- Custom MCP servers supported, free
- Authorization happens on each vendor's own page; the AI never sees passwords or tokens
- Bring your own credentials: use the vendor API keys you already have
- Multiple accounts per app; connect once, reuse across AI clients
- Tool search: finds the right action for the task
- One sign-in; vendor credentials are injected behind the scenes and OAuth tokens refresh automatically

**Visibility**
- Audit log for every tool call (who, which vendor, when)
- Usage dashboard: call volume, top vendors, error rate, per-user activity
- Export audit logs to CSV, or stream to Loki, Graylog, or LogScale (SIEM)
- Optional recording of tool arguments and result summaries (off by default, enabled per organization)

**Control**
- Per-role, per-tool allowlist, deny by default
- owner / admin / member roles
- SCIM provisioning with Entra ID, Okta, JumpCloud, and Google Workspace

**Security**
- Credentials encrypted one record at a time (AES-256-GCM, per-record key)
- AI clients authenticate with OAuth 2.1 + PKCE
- Vendor responses are scanned for prompt-injection patterns and returned as structured data. This is one layer of defense, not a guarantee against every attack.
- Static egress IP for customer firewall and API allowlisting

### Pricing

**Free.**

Links: [connect.mspbots.ai](https://connect.mspbots.ai) · [mspbots.ai](https://mspbots.ai)

---

## Authentication headers

Every request to `/mcp` must carry the manager's own Mailprotector
authentication token. Credentials are read only from these headers -- never
from an environment variable, config file, or disk.

| Header | Required | Meaning | Where to get it |
|---|---|---|---|
| `X-Mailprotector-Auth-Token` | Yes | Per-manager API authentication token, sent to Mailprotector as the HTTP Basic username (a dummy password is used). | Mailprotector Console -> **Edit Profile** screen. |
| `X-Mailprotector-Base-Url` | No | Override for a branded/self-hosted Mailprotector console. Default: `https://console.mailprotector.com`. | -- |

A missing `X-Mailprotector-Auth-Token` returns `401` with a body listing the
required header name, before any call reaches Mailprotector.

The authentication token is tied to one manager's own role and permissions in
Mailprotector -- this connector passes it straight through on every call and
does not add its own tenant or authorization model.

## Tools

20 tools across 5 resource families. All names are prefixed `mailprotector_`.

| Family | Tools |
|---|---|
| Accounts | `list_accounts`, `get_account` |
| Domains | `list_domains`, `get_domain`, `create_domain`, `get_domain_traffic_report` |
| User groups / users | `list_user_groups`, `list_users`, `get_user`, `create_user`, `move_user`, `delete_user`, `get_user_message_stats` |
| Allow/block rules | `list_allow_block_rules`, `set_allow_block_rules` |
| Spam tolerance / settings / dashboard | `get_spam_tolerance`, `set_spam_tolerance`, `get_settings`, `set_settings`, `get_dashboard_stats` |

`mailprotector_delete_user` and the "remove" action of
`mailprotector_set_allow_block_rules` are destructive and only accept
explicit ids/addresses -- never a filter or a wildcard.

Not in scope for this version (see `docs/tickets/PRD-21253.md` "Non-goals"):
billing/invoices, account/user-group create-update-delete, and bulk user
import. These are one-time provisioning or billing actions, not a recurring
Agent task; add them as new tools in the existing modules if a concrete need
shows up later.

## Errors

Tools never raise exceptions. Failures come back as a JSON string:

```json
{"error": {"code": "not_found", "message": "...", "retryable": false}}
```

`code` is one of `not_configured`, `unauthorized`, `not_found`,
`invalid_argument`, `rate_limited`, `upstream_error`.

## Running locally

```bash
uv sync
uv run python -m mailprotector_mcp         # listens on 0.0.0.0:8080
```

```bash
curl -s http://localhost:8080/health
curl -s -X POST http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'X-Mailprotector-Auth-Token: placeholder' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

## Tests

```bash
uv sync
uv run pytest
```

`tests/test_api_client.py` mocks Mailprotector's XML API with fixtures copied
from the vendor's own documented examples. `tests/test_middleware.py` and
`tests/test_tools.py` cover the credential middleware (401, request
isolation) and the tool contract (snapshot, error mapping, validation).

## Docker

```bash
docker build --platform linux/amd64 -t mailprotector-mcp:dev .
```

See `docker-compose.yml` for local debug only; it is not used for deployment.
