---
title: Connect your MCP client
layout: default
nav_order: 30
permalink: /connect-your-client/
description: For employees — point Claude, Cursor, or any MCP client at a vendor MCP server through your organization's Shield gateway, so org policy applies to every tool call.
---

# Connect your MCP client
{: .no_toc }

Your security team has put a vendor's MCP server behind Shield. You point your
client at Shield's URL instead of the vendor's, and every tool call is checked
against your organization's policy on the way through.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## What you don't need

**A vendor account or API token.** Many MCP servers require one —
`mcp.higgsfield.ai` answers an unauthenticated request with
`401 ... WWW-Authenticate: Bearer`. The gateway holds that credential and
attaches it on the way out, so it never reaches your laptop, your shell history,
or a config file you might commit.

If a vendor server was the reason you were about to request a shared team token,
you no longer need one.

## What to ask your security team for

Three values. They come from whoever administers your Shield tenant.

| Value | Looks like | What it is |
|---|---|---|
| Gateway URL | `https://shield.acme.com/gateway/higgsfield/mcp` | The endpoint you connect to. The last path segment is the **route** — the short name your team gave that vendor. |
| Tenant API key | `sk-...` | Which organization's policy applies. Treat it like a password. |
| Your role | `viewer`, `creator`, `admin` | Which grants apply to you on top of the org-wide rules. |

Ask for a **route name**, not the vendor's own URL. Connecting straight to the
vendor bypasses every control below, and on a properly configured server it will
simply be refused.

---

## Claude Code

Native header support, so this is one command:

```bash
claude mcp add --transport http higgsfield https://shield.acme.com/gateway/higgsfield/mcp --header "X-API-Key: $SHIELD_KEY" --header "X-Agent-Key: $USER-claude-code" --header "X-User-Role: creator"
```

Set `SHIELD_KEY` in your shell profile rather than pasting the key into the
command, so it stays out of your shell history.

Add `--scope user` to share the connection across all your projects; the default
is the current project only. Manage it with `claude mcp list`,
`claude mcp get higgsfield`, `claude mcp remove higgsfield`.

## Claude Desktop

Desktop accepts only **stdio** entries in `claude_desktop_config.json` and
silently skips `"type": "http"` ones, so use the `mcp-remote` bridge — a local
process that proxies to the gateway URL. Requires Node, for `npx`.

**Quit Desktop before editing.** It rewrites this file on exit, so edits made
while it is running are lost. The path contains a space, so quote it:

```bash
vi "$HOME/Library/Application Support/Claude/claude_desktop_config.json"
```

```json
{
  "mcpServers": {
    "higgsfield": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://shield.acme.com/gateway/higgsfield/mcp",
               "--header", "X-API-Key:${SHIELD_KEY}",
               "--header", "X-Agent-Key:my-desktop",
               "--header", "X-User-Role:creator"],
      "env": { "SHIELD_KEY": "sk-your-tenant-key" }
    }
  }
}
```

Keep the key in `env` and reference it as `${SHIELD_KEY}`. That also avoids a
Windows quoting bug with spaces in header values — note there is no space after
the colon in `X-API-Key:${SHIELD_KEY}`.

Start Desktop; the server appears under the connectors (🔌) menu. First launch is
slower while `npx` downloads the bridge. `mcp-remote` probes for OAuth first,
finds none, then falls back to these headers — that is expected, not an error.

## Cursor, Codex, and other MCP clients

Any client that speaks streamable-HTTP MCP works: give it the gateway URL and
the three headers. Clients that only support stdio use the same `mcp-remote`
bridge shown above.

## claude.ai on the web

**Not supported with a tenant key.** Web custom connectors require OAuth and will
not send static headers. Use Claude Code or Desktop.

---

## Check it is actually enforcing

Ask your client to list the available tools. You should see **fewer tools than
the vendor documents** — the gateway removes the ones your organization has not
allowed, so the model is never tempted to call them.

Then ask it to do something your team has restricted. A working setup returns a
clear refusal:

```
Blocked by Shield: Tool 'delete_account' is denied on this MCP server by policy
```

If a restricted action instead succeeds, tell your security team: the client is
probably still pointed at the vendor directly.

---

## What your organization can see and control

Per vendor server, independently of every other one:

- **Which tools exist at all.** Non-allowed tools are hidden from the listing and
  refused if called anyway.
- **What comes back.** Tool results and file contents are scanned for sensitive
  data and redacted before they reach the model.
- **Untrusted content.** Results can be scanned for hidden instructions aimed at
  your agent — a real attack against tools that fetch third-party content.
- **A kill switch.** One tool, or a whole server, can be cut off immediately.
  Your client will start refusing that tool within one call; nothing is cached.

Two things worth understanding rather than discovering later:

**Your role is a claim, not a credential.** Today `X-User-Role` is whatever your
client sends. Setting it to `admin` does **not** widen your access on a governed
server, because the controls above are applied per server and never read the
role. Verified identity is coming; until then, do not treat the role as a
security boundary, and do not assume nobody notices — every call is audited
against your `X-Agent-Key`.

**Your calls are logged.** Tool name, decision, and your agent key are recorded
for the security team. Blocked calls never reach the vendor at all, so they also
do not appear in the vendor's logs or on their bill.

---

## Troubleshooting

| You see | What it means |
|---|---|
| `-32001 unauthenticated: no tenant resolved` | `X-API-Key` is missing, wrong, or not valid on this Shield deployment. |
| `-32004 no upstream configured for route 'X'` | The route name is wrong, or it was removed. Check the spelling with your admin. |
| `route 'X' is disabled by an administrator` | The server was deliberately switched off. Ask your team; the config is intact, so re-enabling is instant. |
| `Blocked by Shield: ...` | Working as intended. Your org restricted that tool. |
| `Output blocked by Shield data policy` | The result contained data your role may not receive. |
| `upstream credential could not be materialized` | A Shield-side credential problem, not yours. Send your admin the header name from the message. |
| Empty tool list | Either everything is restricted for your role, or the vendor server is unreachable from the gateway. Your admin can tell which. |
| Desktop: "some MCP servers could not be loaded" | The entry format was rejected. Use the `mcp-remote` form above, not `"type": "http"`. Check `~/Library/Logs/Claude/main.log`. |
| Desktop config edits keep disappearing | Desktop rewrites the file on exit. Quit it first, then edit, then start it. |

Per-server logs live at `~/Library/Logs/Claude/mcp-server-<name>.log`; a healthy
one shows `Server started and connected successfully` followed by a `tools/list`
result.
