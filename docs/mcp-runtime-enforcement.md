---
title: MCP Runtime Enforcement (Policy vs. Enforcement Location)
layout: default
nav_order: 25
permalink: /mcp-runtime-enforcement/
description: Why MCP tool allowlists must be enforced at the runtime (a PEP in the call path), not just declared in the client — and exactly where Shield enforces, with the one deployment requirement that makes it hold.
---

# MCP runtime enforcement
{: .no_toc }

An allowlist is only as strong as **where** it's checked. A correct policy that's
enforced in a bypassable place gives you the *feeling* of least privilege without
the guarantee. This page explains the principle and shows exactly where Shield
enforces MCP tool calls — and the one deployment requirement that makes it hold.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Policy vs. enforcement location

Two separate things, both required:

- **Policy** — the allowlist: *"this agent/role may call `search` and `wire_money`, nothing else."*
- **Enforcement location** — the point in the system that actually checks the policy
  **before the tool executes**.

A correct policy checked only in a bypassable place is not least privilege. The
enforcement must sit at a **Policy Enforcement Point (PEP) in the call path** — so
an off-list call is refused at execution **regardless of how it arrived**.

## Why client-side / discovery-only enforcement fails

If the allowlist is enforced only in the agent/client or only at tool discovery:

- **Prompt injection** can make the agent emit a raw `tools/call` for an off-list
  tool — the client's "allowed tools" list is never consulted.
- A **compromised or buggy client** skips its own check.
- The agent reaches the tool **server directly**, on a different path than the
  sanctioned client.
- A **discovery-time** check (filtering `tools/list`) is never re-applied at
  `tools/call`.

In every case the policy says "no" and nothing in the execution path enforces it.

## Where Shield enforces

Shield is a **runtime PEP**: it decides on every call, server-side, before any
upstream execution.

| Surface | Enforcement | Notes |
|---|---|---|
| **OpenAPI→MCP generated tools** (`POST /v1/openapi/call`) | `enforce_tool_call()` runs **before** the upstream request is built/sent | Strongest model — see "credential chokepoint" below |
| **Transparent MCP proxy** (`core/mcp/proxy_server.py`) | `call_tool` runs `enforce_tool_call()`; on block returns an MCP error and **never** calls upstream | Requires network isolation of the upstream (below) |
| `tools/list` discovery | `filter_tools_for_role()` hides tools a role can't use | Cosmetic only — the call-time gate is authoritative |
| Shield's own MCP server `shield_check_*` (`api/routes_mcp_server.py`) | **Advisory** — the agent calls these to check itself | A helper, **not** a chokepoint; do not rely on it alone |

Properties of the enforcement core (`core/mcp/enforcement.py`):

- **Call-time, not discovery-time** — `enforce_tool_call()` runs on every `tools/call`.
- **Deny-by-default** — `ToolAllowlistGuardrail` is strict deny-by-default; `RBACGuard`
  denies unknown agents and roles absent from `role_permissions`.
- **Server-side** — the decision is independent of what the agent/client believes.
- **Layered** — kill switch → RBAC → data-access → allowlist → tool-call validation,
  then output sanitization on the result.

## The deployment requirement that makes it hold

The PEP only enforces **what flows through it**. To close the "go around the PEP"
bypass:

- **Generated tools (`/v1/openapi/call`): structurally closed.** Shield holds the
  upstream `base_url` + credentials server-side; the agent only ever has the Shield
  endpoint. There is no off-PEP path because the agent never holds upstream creds.
- **Transparent proxy in front of a third-party MCP server: you must isolate the
  upstream.** Ensure the upstream MCP server accepts connections **only** from the
  Shield proxy — network policy / firewall / mTLS / binding it to localhost behind
  the proxy. The proxy logic is correct, but if the upstream is directly reachable,
  the agent can skip Shield.

> **Rule of thumb:** ship the allowlist **and** make the PEP the *only* path to the
> tool. Policy without an unbypassable enforcement location is not enforcement.

## See also
- [Enterprise Integration Architecture](/enterprise-integration-architecture/) — PDP/PEP placement.
- [AI Gateway & Proxy Interoperability](/ai-gateway-interoperability/) — server-side PEPs.
- Code: `core/mcp/enforcement.py`, `core/mcp/proxy_server.py`, `api/routes_openapi_mcp.py`.
