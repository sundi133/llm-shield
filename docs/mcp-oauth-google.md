---
title: Google Workspace MCP through Shield
layout: default
permalink: /mcp-oauth-google/
description: "Put Google's own Drive, Gmail, Calendar and other Workspace MCP servers behind the Shield MCP gateway, with Shield holding the Google sign-in."
---

# Google Workspace MCP servers through Shield
{: .no_toc }

Google runs MCP servers for Drive, Gmail, Calendar, Docs, Sheets, Slides, Chat
and People. This guide puts one of them behind the Shield MCP gateway, so that:

- every tool call and every result goes through your Shield policies;
- Shield signs in to Google once and keeps that sign-in refreshed in its vault;
- agents connect to Shield with a Shield key and never hold a Google token.

The steps use Drive. The other servers are the same with a different URL and
scopes (see [Other Google servers](#other-google-servers)).

## Before you start

You need:

1. **Google's Workspace Developer Preview.** Google's MCP servers are currently
   available through that program. Join it for the Google Cloud project you use
   below.
2. **A Google Cloud project** where you can create OAuth clients.
3. **The Shield redirect address**, from your Shield administrator. It is the
   value of `SHIELD_OAUTH_REDIRECT_URI` on your Shield admin service, for
   example `https://shield.example.com/v1/tenant/me/mcp/oauth/callback`.

## 1. Set up Google Cloud

In the Google Cloud console, for your project:

1. **Enable the APIs.** Enable the Google Drive API and the Drive MCP service
   (`drivemcp.googleapis.com`).
2. **Configure the OAuth consent screen.**
   - For a Google Workspace organisation, choose **Internal**. Only your
     organisation's users can sign in, and Google does not require app
     verification.
   - **External** apps in the **Testing** state get refresh tokens that expire
     after 7 days, so Shield's connection stops after a week. Publish the app,
     or use Internal.
   - Full Drive access is a restricted scope. An External app needs Google's
     verification before anyone outside your test users can grant it.
3. **Create an OAuth client.** Credentials, Create credentials, OAuth client
   ID. Choose **Web application**, and add the Shield redirect address under
   **Authorised redirect URIs**, exactly as given. Keep the client ID and
   secret for step 3.

## 2. Register the server in Shield

In the Shield console, open **MCP Gateway**, then **Register a Server**:

| Field | Value |
|---|---|
| Route name | `gdrive` (any short name; agents use it in their URL) |
| Transport | `http` |
| Upstream URL | `https://drivemcp.googleapis.com/mcp/v1` |

Agents will use `https://<your Shield gateway>/gateway/gdrive/mcp`.

## 3. Connect with OAuth

On the `gdrive` server card, select **OAuth**. The panel shows:

- **Provider**: `https://accounts.google.com`, profile `google`, and that a
  client ID is required (Google does not let Shield register itself).
- **Scopes**: the Drive scopes Google offers. None is ticked; you choose.

Then:

1. Enter the **client ID** and **client secret** from step 1.
2. Tick the scopes the agents need. Prefer `drive.readonly` unless they must
   change files.
3. Select **Connect**, read the consent note, and select **Open sign-in page**.
4. Sign in to Google **with the account the agents should act as**, and
   approve.

The browser returns to a Shield page that says **Connected: gdrive**. Back in the
panel, the status reads **Connected**, with the time the current token is valid
until.

**Every agent and user of this route acts as the account that signed in, with
all of its access.** Sign in with a dedicated account that can see only what the
agents should see, never a personal or administrator account.

Shield also sets the route's `Authorization` header to use the credential it
now holds. If the route already had its own `Authorization` header, Shield
leaves it alone and the panel says the new credential is not in use; remove
that header to switch.

## 4. Check it works

List the tools through the gateway with your Shield tenant key:

```bash
curl -s -X POST https://<your Shield gateway>/gateway/gdrive/mcp -H "X-API-Key: <tenant key>" -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

The response lists Drive's tools. Register an agent for them (**Agent
Registry**) and apply your tool policies before giving agents access.

## 5. Point agents at Shield

Configure each MCP client with the gateway URL and Shield headers only:

```bash
claude mcp add --transport http gdrive https://<your Shield gateway>/gateway/gdrive/mcp --header "X-API-Key: <tenant key>" --header "X-Agent-Key: <agent id>" --header "X-User-Role: <role>"
```

Do not also give agents Google credentials or Google's MCP URL. An agent that
can reach Google directly can go around Shield.

## How the credential stays valid

- Shield asks Google for offline access, so Google issues a refresh token.
  Shield stores it in its vault, never in plain text and never shown in the
  console.
- When the access token nears expiry, the next tool call through the gateway
  refreshes it first. There is no separate background job; a route nobody uses
  is refreshed on its next use.
- If Google stops accepting the refresh token (the user removed Shield's
  access, a Testing app reached 7 days, or, for Gmail scopes, the user changed
  their password),
  the status changes to an error and calls fail until you connect again.

## Troubleshooting

| What you see | Cause | Fix |
|---|---|---|
| "this server grants access by scope; choose the scopes" | No scope ticked | Tick at least one scope |
| Google says `redirect_uri_mismatch` | The OAuth client's redirect URI differs from Shield's | Copy the Shield redirect address into the client exactly, including `https` and the path |
| Google says the app is not verified, or `access_denied` | External app, restricted scope, user not a test user | Use Internal, add the user as a test user, or complete Google's verification |
| Status: "returned no refresh token, so this connection stops working" | Google had an earlier grant for this client and did not issue a new refresh token | Remove Shield at myaccount.google.com/permissions, then connect again |
| Connected, but calls fail with 401 or 403 | The token lacks a needed scope, or the project is not in the Developer Preview | Connect again with the right scope; check the preview enrolment and that the Drive MCP service is enabled |
| Tool calls fail with HTTP 500 and no message | Google rejected the call, usually because the route is not connected or the token was revoked. A known gateway issue reports this as a server error instead of an authorization error | Check the route's OAuth status and connect again |
| Status: "sends its own Authorization header, so this credential is not in use" | The route already had an Authorization header | Remove it from the route |
| "OAuth brokering stores tokens in the vault" | The Shield vault is off | Ask your Shield administrator to enable it |

## Other Google servers

Repeat the steps with a separate route per server:

| Service | Upstream URL |
|---|---|
| Gmail | `https://gmailmcp.googleapis.com/mcp/v1` |
| Google Calendar | `https://calendarmcp.googleapis.com/mcp/v1` |
| Google Docs | `https://docsmcp.googleapis.com/mcp/v1` |
| Google Sheets | `https://sheetsmcp.googleapis.com/mcp/v1` |
| Google Slides | `https://slidesmcp.googleapis.com/mcp/v1` |
| Google Chat | `https://chatmcp.googleapis.com/mcp/v1` |
| People | `https://people.googleapis.com/mcp/v1` |

Enable the matching API and MCP service in Google Cloud for each. The OAuth
client can be the same one; the panel offers each server's own scopes.
