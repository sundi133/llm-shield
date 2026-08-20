---
title: Glossary
layout: default
nav_order: 9
permalink: /glossary/
description: One definition per term, shared by developers and security teams.
---

# Glossary
{: .no_toc }

So "agent", "tool", and "policy" mean exactly one thing to both the developers
who integrate Shield and the security team who operates it.
{: .fs-6 .fw-300 }

---

**Agent** — an AI system that takes actions by calling tools. Identified to
Shield by an `agent_key`.

**Agent key** — the string an agent presents on every request (`X-Agent-Key`).
How Shield knows *who is acting*.

**Tool** — a single capability an agent can invoke (e.g. `get_account`,
`wire_transfer`). May come from an MCP server or be generated from an API.

**Tool call** — one invocation of a tool with arguments. The unit Shield
authorizes.

**Role / RBAC** — the caller's role (e.g. `reader`, `admin`) gates which
tools it may call. RBAC = role-based access control. Shield accepts the role
either as a `user_role` field in the request body or as an `X-User-Role`
header; the body field takes precedence when both are present.

> **The role is supplied by the caller.** Shield enforces against whatever
> role it is handed — it does not authenticate the role itself. Resolve the
> role from your own verified session or token before calling Shield, and do
> not pass a role that originated from untrusted client input.

**Role permissions** — the map, per agent, of role → allowed tools. Set once
when the agent is registered.

**Capability minting** — defining what an agent *can* do (its tools and
role-permissions) before it runs. Done once at registration.

**Guardrail** — one check Shield runs. *Fast-tier* guardrails (keyword
blocklist, length limit, regex, PII detection) are CPU-only and run in under
5 ms; *slow-tier* (content inspection, output sanitization) use an LLM. See
the Guardrails Catalog for the full list and which tier each one sits in.
The kill switch is not a guardrail — it is an administrative block, defined
separately below.

**Risk tier** — a zero-config `low` / `medium` / `high` score Shield assigns
every tool call from its name, HTTP method, and arguments — so dangerous calls
surface before any policy is written.

**Policy mode** — `monitor` or `enforce` per tenant. **Monitor** evaluates
everything and records what *would* block, but blocks nothing (a dry run).
**Enforce** actually blocks. Default is enforce.

**Would-block** — in monitor mode, the list of guardrails that *would have*
blocked a call. The review queue before turning on enforcement.

**Kill switch** — an operator's one-click disable of a tool, fleet-wide and
instant. An *administrative* block: enforced even in monitor mode.

**Agent disable** — toggling an agent off in the registry; it cannot act at all,
regardless of role. Also administrative.

**Shadow agent / shadow tool** — an agent or tool that called Shield without
being registered. Surfaced for the operator to approve or block.

**Tenant** — an isolated customer/workspace. Its agents, policies, and audit log
are scoped to it. Resolved from the API key.

**Data policy / sanitization** — rules that redact or block sensitive data
(PII, secrets) in a tool's *output* before the agent sees it.

**Taint graph** — the per-session lineage of tool calls, used to trace a result
back through the chain to the originating prompt (forensics).

**Audit log / SIEM feed** — the record of every decision (agent, tool, role,
result, reason, timestamp), kept locally and streamed to the security team's
SIEM (Splunk, Elastic).

**Upstream MCP server** — an existing MCP server (third-party or internal) that
Shield's proxy sits in front of.

**MCP proxy** — Shield mediating between an MCP client and upstream MCP servers:
filtering `tools/list`, enforcing `tools/call`, sanitizing output.

**Generated server** — a standalone MCP server Shield emits from an OpenAPI spec
(Python or TypeScript), with the enforcement hook baked in.

**Sandbox key** — any `sk-test-*` API key; resolves to a shared sandbox tenant
Shield auto-provisions, for zero-setup trials.
