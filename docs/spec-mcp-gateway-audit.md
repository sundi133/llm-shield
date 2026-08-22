---
title: "Spec: audit MCP gateway decisions"
layout: default
nav_order: 54
permalink: /spec-mcp-gateway-audit/
description: "Every enforcement decision the MCP gateway makes is discarded. The proxy has a decision sink, the gateway never wires one, so blocks and allows on the MCP path appear in no audit trail a tenant can read."
---

# Spec: audit MCP gateway decisions

Status: DRAFT, awaiting approval.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. Problem & outcome

**Every enforcement decision the MCP gateway makes is thrown away.**

`MCPProxy` records decisions through an injected sink:

```python
async def _record(self, event: dict) -> None:
    if self._on_decision:
        ...
```

`_default_proxy_factory` (`core/mcp/gateway.py:174`) constructs the proxy with
`enforcer`, `scan_descriptions`, `policy` and `route`, and **never passes
`on_decision`**. So `self._on_decision` is `None` and `_record` is a no-op on
every production gateway request.

Confirmed empirically before it was confirmed in code. Two tool calls were made
through the live gateway on tenant `bankco` on 2026-08-21, one blocked and one
allowed. Afterwards:

- `GET /v1/tenant/me/audit` returned only admin actions
  (`mcp_gateway_upsert_upstream`, `tenant_create_api_key`) - no tool calls at all
- `GET /v1/tenant/me/telemetry` returned nothing for them

The comparable path is wired: `/v1/shield/tool/check` writes to `audit_logger`
(`api/routes_tool.py:216`), which is why `agent_key=jumpcloud-mcp-gateway`
entries exist from that endpoint and none exist from the gateway.

**Why this matters more than it looks.** Shield is sold as a governance control.
"Show me the audit trail" is the first question a security reviewer asks, and on
the MCP path the answer is currently that there isn't one. A blocked wire
transfer is exactly the event a tenant needs evidence of, and it is the event
most reliably lost. The gap is also silent: the console shows no error, just an
empty list, so nothing signals that recording never happened.

**Outcome.** A tool call through `POST /gateway/{route}/mcp` produces an audit
entry naming the tool, the agent, the decision, and the reason - readable at
`GET /v1/tenant/me/audit` alongside decisions from every other guard endpoint.

Observable success condition: after one allowed and one blocked gateway call,
`/v1/tenant/me/audit` contains two entries whose `input_text` names the tools,
whose `action_taken` is the recorded action, and whose `guardrails_triggered`
names the guardrail that objected on the blocked one.

### Non-goals

- **Not** changing any enforcement decision. This records what already happens.
- **Not** auditing `tools/list`. Discovery is worth recording (who was shown
  what) but it is a different event with a different volume profile. Follow-up.
- **Not** changing the audit schema, retention, or `/v1/tenant/me/audit`.
- **Not** fixing telemetry retention (observed emptying between two calls
  minutes apart). Separate, unexplained.

## 2. Plane & latency contract

- **Plane:** data plane. `core/mcp/gateway.py` only.
- **Touches the GUARD PATH?** Yes, `/gateway/{route}/mcp`.
- **Latency budget: zero measurable.** `audit_logger.log`
  (`storage/audit_log.py`) is already fire-and-forget: it calls
  `loop.run_in_executor(None, self._write_sync, entry)` and does **not** await
  the future, so the Redis write happens on a worker thread and the caller
  returns immediately. Nothing new is awaited on the request path.

This is deliberate and load-bearing given today's other finding: guardrail
metrics were being written synchronously on the request path and cost ~1.6s p50
(`docs/spec-metrics-off-hot-path.md`). Reusing an already-async writer avoids
reintroducing that class of bug.

## 3. Data model

Unchanged. Entries go to the existing `audit:{tenant_id}` ZSET through
`audit_logger`, with the same fields the tool endpoints already write. No new
keys, no schema change, no TTL change.

Tenant scoping: `tenant_id` is already present on the event the proxy passes to
`_record` (`core/mcp/proxy_server.py:165,176`), resolved during enforcement. The
sink passes it through; it never re-derives identity.

## 4. API / interface

No HTTP surface change. One new module-level function in `core/mcp/gateway.py`,
wired into the existing factory:

```python
async def _audit_decision(event: dict) -> None:
    """Map a gateway decision onto an audit entry. Never raises."""

# in _default_proxy_factory:
return await proxy_for(cfg, enforcer=enforcer, on_decision=_audit_decision, ...)
```

Field mapping, chosen to match `/v1/shield/tool/check` so both paths render
identically in the console:

| audit field | source |
|---|---|
| `agent_key` | `event["agent_key"]` |
| `endpoint` | `/gateway/{route}/mcp` |
| `input_text` | `mcp_call:{tool}` |
| `action_taken` | `event["action"]` |
| `guardrails_triggered` | names from `event["results"]` that did not pass |
| `metadata.tenant_id` | `event["tenant_id"]` |
| `metadata.blocked` | `not event["allowed"]` |
| `metadata.reason` | `event["reason"]` |
| `metadata.route` | the route |
| `metadata.mode` | `event["mode"]` (enforce vs monitor) |

`mode` is included deliberately: in monitor mode a call is forwarded while
`would_block` records what enforcement *would* have done, and an audit trail
that cannot distinguish "allowed" from "allowed because we were only watching"
is misleading in exactly the situation someone reviews it.

## 5. Security & backward compatibility

- **Authz:** unchanged. No new caller-reachable surface, no new decision.
- **Malicious caller:** one audit entry per tool call, already bounded by the
  existing rate limiter. No amplification.
- **Behaviour change:** entries begin appearing where there were none. Nothing
  reads this path today (it is empty), so nothing can break on their presence.
  Ships with `SHIELD_MCP_AUDIT=off` as the escape hatch per repo invariant.
- **A recording failure must never fail a guarded call.** The sink swallows and
  logs at debug. `_record` already wraps the callback in try/except; the sink is
  defensive independently so it is safe wherever else it is wired.

**Sensitive content.** `input_text` records `mcp_call:{tool}` - the tool name
only, never arguments. Arguments to MCP tools routinely carry the material the
vault and sanitisation layers exist to keep out of durable stores, and an audit
trail is a durable store. Recording the decision does not require recording the
payload.

## 6. Packaging & deploy

- **New pip deps:** none.
- **`Dockerfile.admin`:** no change; `core/mcp/gateway.py` and
  `storage/audit_log.py` are both already present. `tests/test_admin_dockerfile_imports.py`
  must stay green.
- **Images to rebuild:** data plane only.
- **Env flags:** `SHIELD_MCP_AUDIT` (unset = on).
- **Rollout:** deploy, make one allowed and one blocked gateway call, confirm
  both appear in `/v1/tenant/me/audit`. Revertible by env flag without a rebuild.

## 7. Failure modes & edge cases

| condition | behaviour |
|---|---|
| Redis down | `audit_logger` swallows internally; the call is unaffected. |
| Sink raises | Caught in the sink and again in `_record`. Never propagates. |
| `SHIELD_MCP_AUDIT=off` | Sink returns immediately; today's behaviour. |
| `tenant_id` missing | Skip the write. An entry with no tenant is unreadable and would pollute a shared key. |
| Blocked at the tool floor | Recorded. That path calls `_record` before contacting the upstream (`proxy_server.py:165`), and an administratively barred tool is exactly what a reviewer looks for. |
| Monitor mode | Recorded with `mode` and `would_block`, so a forwarded call is not mistaken for an approved one. |
| `pending_confirmation` | Recorded like any other action; the HITL decision is itself auditable. |
| Very large `results` | Only guardrail *names* are extracted, never payloads. |

**Fail-open vs fail-closed:** audit recording fails **open** - a logging outage
must never block a guarded call. This is deliberate and is the standard
trade-off for this repo's audit path; it is stated here so it is a decision
rather than an accident.

## 8. Test plan (Definition of Done)

New file `tests/test_mcp_gateway_audit.py`:

1. **An allowed call writes an audit entry** naming the tool and the action.
2. **A blocked call writes one**, with `blocked: true` and the guardrail that
   objected in `guardrails_triggered` - not merely the first one that ran.
3. **A tool-floor block is recorded**, proving the pre-upstream path is wired.
4. **The sink is actually attached by the factory.** The regression guard: this
   defect was a missing keyword argument, and every other test would pass
   without it.
5. **`tenant_id` is carried onto the entry.**
6. **No `tenant_id` writes nothing.**
7. **A raising audit writer does not fail the call.**
8. **`SHIELD_MCP_AUDIT=off` writes nothing.**
9. **Arguments never reach the entry** - assert the payload is absent from the
   serialised entry, so a future change that starts logging arguments fails here.
10. **Monitor mode records `mode` and `would_block`.**

Regression suites: `tests/test_mcp_proxy.py`, `tests/test_mcp_gateway.py`,
`tests/test_mcp_gateway_server.py`, `tests/test_mcp_enforcement.py`,
`tests/test_mcp_proxy_metrics_recording.py`, `tests/test_admin_dockerfile_imports.py`.

**Definition of done:** full suite green in a clean venv; CI `pytest` gate
passes; a live check after deploy showing one allowed and one blocked gateway
call in `/v1/tenant/me/audit`.
