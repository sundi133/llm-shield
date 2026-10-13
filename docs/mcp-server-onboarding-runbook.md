---
title: Onboarding an MCP server to the Votal gateway — enterprise runbook
description: Step-by-step to register an upstream MCP server behind the Votal gateway, define RBAC, connect AI clients, and verify it with an enterprise acceptance test.
---

# Onboarding an MCP server — enterprise runbook

How an enterprise registers a third-party (or internal) MCP server behind the
**Votal gateway**, governs it, connects Codex / Claude Code, and **tests it step
by step**. The worked example is a generic **enterprise directory MCP server** at
`https://mcp.example.com/v1`; every step is the same for any upstream.

## 0. The model (what the gateway adds)

```
AI client (Claude Code / Codex / REST)
      │  MCP over HTTPS, authenticated to the GATEWAY (not the upstream)
      ▼
Votal gateway route  ──►  upstream MCP server (e.g. https://mcp.example.com/v1)
      │  the gateway:
      ├─ validates the upstream URL (SSRF-safe registration + dial)
      ├─ authorizes EVERY tools/list and tools/call (default-deny RBAC)
      ├─ injects the UPSTREAM credential from the vault (never forwards the
      │  client's gateway token upstream)
      └─ writes a tamper-evident audit record per decision
```

Two layers of access control stack:
- **The upstream's own RBAC** (the upstream enforces whatever the token allows).
- **The Votal gateway's RBAC** on top — which of *your* roles may see/call which
  tools, independent of the upstream.

## 1. Prerequisites

**Upstream side** — the server owner does this once:
- Enable the upstream's MCP endpoint and note its URL, e.g.
  `https://mcp.example.com/v1`.
- Have a credential: either one **service token** (shared model, §2a) or each
  user generates **their own token / API key** (per-user model, §2b).
- Keep the upstream's API-docs link handy so users know how to get their key.

**Votal side:**
- A tenant and **tenant-admin** (or platform-operator) access to the portal/API.
- The gateway base URL, e.g. `https://api.guardrails.votal.ai` (`$BASE`), and your
  tenant API key (`$KEY`) for the admin calls below.

## 2. Register the upstream server

Pick a short **route** id — it namespaces the server in the gateway URL and the
tool names. Use `dir-admin`.

### 2a. Shared service credential (simplest; Votal RBAC governs)
Store the upstream **service token** in the vault, then register the route so the
gateway injects it on every call. The client never sees or sends it.

```bash
curl -X PUT "$BASE/v1/tenant/me/mcp-gateway/upstreams/dir-admin" \
  -H "X-API-Key: $KEY" -H "content-type: application/json" -d '{
    "transport": "http",
    "url": "https://mcp.example.com/v1",
    "headers": { "Authorization": "Bearer shield://dir-admin-token" },
    "credential_scope": "shared",
    "isolation_ack": true
  }'
```
`shield://dir-admin-token` is a **vault reference** (store the real token with the
vault API; it is never kept in the route config in cleartext). With `shared`, all
calls use the one service token and **Votal's RBAC (§3) decides who may do what**.

### 2b. Per-user credentials (recommended — inherits each user's upstream RBAC)
Each user connects **their own** token, so the upstream sees the real person and
enforces *their* permissions. Register `per_user` and require verified identity:

```bash
curl -X PUT "$BASE/v1/tenant/me/mcp-gateway/upstreams/dir-admin" \
  -H "X-API-Key: $KEY" -H "content-type: application/json" -d '{
    "transport": "http", "url": "https://mcp.example.com/v1",
    "credential_scope": "per_user", "require_verified_identity": true,
    "isolation_ack": true
  }'
```
Each user then connects their credential once:
`$BASE/connect/<tenant>/dir-admin` → **Start** (the gateway brokers the per-user
credential; OAuth where the upstream supports it, otherwise the user's token).
Until a user connects, their calls get a friendly "connect your account" message
instead of running anonymously.

> **Internal MCP servers:** if the upstream is on your private network, the SSRF
> guard blocks it by default. Add `"allow_private": true` to the registration to
> permit an **explicitly-approved** RFC 1918 destination. Loopback, link-local and
> cloud-metadata endpoints stay blocked regardless.

## 3. Define the Votal RBAC (role → allowed tools)

Default-deny: a role may only call the tools you grant it. Register an agent with
a `role_permissions` map (tool names are the upstream's):

```bash
curl -X POST "$BASE/v1/agents/registry" -H "X-API-Key: $KEY" \
  -H "content-type: application/json" -d '{
    "agent_key": "dir-admin-agent",
    "role_permissions": {
      "directory-reader":   ["directory_user_get","directory_user_list","directory_device_list"],
      "directory-operator": ["directory_user_get","directory_user_list","directory_device_list",
                             "directory_user_suspend","directory_user_reset_mfa"]
    }
  }'
```
Unlisted tools are denied. A role's effective access is the **intersection** of
its Votal grant and what the upstream token already allows.

## 4. Review and approve the tool catalog

On registration the gateway **scans the server's tool descriptions** (they are
instructions a model will act on). A critical finding leaves the route
**registered but INACTIVE** pending review — intentional, not an error. Review the
tools and activate:

```bash
curl "$BASE/v1/tenant/me/mcp-gateway/upstreams/dir-admin" -H "X-API-Key: $KEY"   # inspect scan + tools
# after review, re-PUT with "active": true (or activate in the portal)
```

## 5. Connect an AI client

The gateway MCP endpoint for the route is `$BASE/gateway/dir-admin/mcp`
(credential-resolved) or the tenant-addressed `$BASE/gateway/t/<tenant>/dir-admin/mcp`
(for per-user OAuth sign-in).

```bash
# Claude Code
claude mcp add --transport http votal-dir $BASE/gateway/dir-admin/mcp \
  --header "X-API-Key: $KEY" \
  --header "X-Agent-Key: dir-admin-agent" \
  --header "X-User-Role: directory-operator"

# Codex CLI
codex mcp add votal-dir --url $BASE/gateway/dir-admin/mcp
codex mcp login votal-dir
```
For per-user (§2b), point the client at `$BASE/gateway/t/<tenant>/dir-admin/mcp`
so the user signs in and connects their own credential.

## 6. Test it — step by step (the enterprise acceptance run)

Run these in order; each is a pass/fail gate.

| # | Step | Expected |
|---|---|---|
| 1 | **Discovery** — `tools/list` through the client as `directory-reader` | Only the reader's granted tools appear; `directory_user_suspend` is **absent** |
| 2 | **Allowed call** — as `directory-operator`, call `directory_user_get` | Succeeds; returns the directory data |
| 3 | **RBAC deny** — as `directory-reader`, call `directory_user_suspend` | **Blocked by Shield: role 'directory-reader' is not allowed to use tool 'directory_user_suspend'** |
| 4 | **Default-deny** — call a tool not in any role grant | Denied (even though the upstream exposes it) |
| 5 | **Credential isolation** — inspect the request the gateway sends upstream | The client's `X-API-Key` is **not** forwarded; the gateway injected the upstream token. The upstream's audit shows the service/user token, never the gateway key |
| 6 | **SSRF** — try to register `http://169.254.169.254/` or an internal IP | Rejected at registration (400) |
| 7 | **Audit** — open the Telemetry tab after the calls | Each decision is recorded (tool, role, allow/deny, outcome) in the tamper-evident log |
| 8 | **Revocation** — disable the route (`"active": false`) or revoke the role | Calls denied within the freshness bound (~15–30s), including through an already-open MCP session |

Check the gateway-side decision log for any call:
```bash
curl "$BASE/v1/tenant/me/telemetry?tool_name=directory_user_suspend" -H "X-API-Key: $KEY"
```

## 7. Security verification checklist (what a reviewer signs off)

- [ ] **Default-deny** — a new role has no tool access until granted.
- [ ] **Independent authorization** — enforced on `tools/list` **and** `tools/call`
      (a hidden tool can't be invoked by guessing its name).
- [ ] **Credential non-forwarding** — the client's gateway token never reaches the
      upstream; the upstream credential comes from the vault.
- [ ] **SSRF** — internal / loopback / metadata upstream URLs are blocked
      (`allow_private` only for an explicitly-approved internal destination).
- [ ] **Per-user attribution** (if §2b) — the upstream enforces each user's own
      RBAC; the gateway binds the decision to the verified principal.
- [ ] **Audit** — every call has a decision + outcome record; no secrets in logs.
- [ ] **Revocation** — disabling the route or the role stops calls within the bound.

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Route registered but tools don't appear | Scan left it **inactive** (critical finding) — review §4 and set `active: true`. |
| "connect your account" instead of a result | Per-user route (§2b) and the user hasn't connected — send them `$BASE/connect/<tenant>/dir-admin`. |
| Registration 400 "rejected by SSRF policy" | The URL resolves to a private/loopback/metadata address — for a legitimate internal server add `allow_private: true`; metadata stays blocked. |
| Every tool denied | No `role_permissions` grant for the caller's role, or the `X-User-Role` header doesn't match a granted role; default-deny is working. |
| Upstream 401 | The injected token is missing/expired — re-store the vault secret (shared) or reconnect (per-user). |

---
*This runbook targets the current gateway. Namespaced `server__tool` catalog
names, a REST `/api/v1/tool-calls` surface, and human-approval over MCP are on the
enterprise-gateway roadmap (docs/specs/spec-mcp-gateway-enterprise.md).*
