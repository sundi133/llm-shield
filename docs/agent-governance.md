---
title: Agent Governance & Access Reviews
layout: default
nav_order: 16
permalink: /agent-governance/
description: Agent access intelligence grounded in real runtime activity — inventory (incl. shadow agents), used-vs-granted least-privilege, and access-review campaigns that apply revokes.
---

# Agent governance & access reviews
{: .no_toc }

Shield governs agents from **what they actually did**, not just what they were
configured to do. Because Shield sits in the runtime path, the inventory and
least-privilege views are backed by real call-path activity — and review
decisions apply through the same RBAC/registry that enforces tool access.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

All endpoints are **read/query operations on the control plane** (plus registry
writes when a review closes). Nothing here runs on the guard path
(`cap/mint`, `tools/call`), so guarded/LLM traffic has **no added latency**.
Authenticate with your tenant `X-API-Key`. In the tenant portal this is the
**Governance** tab.

## Where this runs (deployment)

Shield runs as two independent planes that share Redis:

| Plane | Hardware | Responsibilities |
|---|---|---|
| **Data plane** (guardrail server) | GPU (vLLM, ~9B guardrail model) | Pre/post-call inspection, agent & tool access control, the LLM-based checks (~250 ms) |
| **Admin & tenant plane** (portal) | CPU only, no GPU | Policy management, the tenant portal, and **governance** (inventory, used-vs-granted, reviews) |

Governance is **pure control-plane logic — no model, no GPU**, so it lives on the
admin/tenant plane and the portal's Governance tab calls it there. Both planes
read the **same Redis** (registry, auth-event activity), so governance sees a
consistent view of entitlements and runtime usage regardless of which plane
served a request. Because nothing here touches the GPU data plane's inference
path, governance adds **zero load to the guardrail server** — you can scale the
portal independently of the GPU fleet.

## 1. Agent inventory

`GET /v1/governance/agents` merges:
- **Registered agents** — entitlements from the registry (granted tools, roles, `allowed_resources`, status).
- **Shadow agents** — agent ids observed in traffic but never registered.
- **Recent activity** — `last_seen` and recently-used tools from the runtime auth-event stream.

```bash
curl -s "$SHIELD_URL/v1/governance/agents" -H "X-API-Key: $KEY" | python3 -m json.tool
```

Returns `registered_count`, `shadow_count`, and a per-agent list. Shadow agents
are the blind spot worth closing first — they're acting without a policy.

## 2. Used-vs-granted (least privilege)

`GET /v1/governance/agents/{agent_id}/usage` diffs what an agent was **granted**
against what it has **actually exercised**:

| Field | Meaning |
|---|---|
| `unused_grants` | granted but never used — candidates to remove |
| `used_not_granted` | used but not granted — **drift / investigate** |
| `used_tools` / `used_resources` | what the agent actually touched |
| `activity` | event breakdown (mint / verify / denied …) |

```bash
curl -s "$SHIELD_URL/v1/governance/agents/<agent_id>/usage" -H "X-API-Key: $KEY"
```

{: .note }
> Usage is derived from the runtime auth-event buffer (recent activity, not full
> history) — directional for least-privilege, not a substitute for full audit.
> Longer-retention usage analytics is on the roadmap. Treat `unused_grants` as a
> review prompt, not an automatic delete.

## 3. Access-review campaigns

Certify each agent's entitlements on a schedule, then apply the decisions.

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/v1/governance/reviews` | Create a campaign — snapshots entitlements + recommendations |
| `GET` | `/v1/governance/reviews` | List campaigns + progress |
| `GET` | `/v1/governance/reviews/{id}` | Campaign detail + decisions |
| `POST` | `/v1/governance/reviews/{id}/decisions` | Record `keep`/`revoke` per (agent, tool) |
| `POST` | `/v1/governance/reviews/{id}/close` | Close and **apply** revokes (idempotent) |

**Recommendations are pre-filled** from used-vs-granted: no recent activity →
`review` (a stale-grant candidate — not a hard revoke, since the usage window is
bounded), drift (used-but-not-granted) → `investigate`, used → `keep`. The
reviewer then chooses keep or revoke per grant. A future longer-retention usage
signal will let `review` graduate to a confident `revoke` for grants unused over
a real time window.

**On close**, each `revoke` removes that tool grant from the agent in the
registry. RBAC and capability minting read the registry, so the change takes
effect on the next mint/check; any live capability tokens expire on their own
(≤60s). Close is **idempotent** and snapshots entitlements at creation, so a
mid-review config change can't silently alter what's being certified.

```bash
# create
CID=$(curl -s -X POST "$SHIELD_URL/v1/governance/reviews" -H "X-API-Key: $KEY" \
  -d '{"name":"Q3 agent certification"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["campaign"]["campaign_id"])')
# decide
curl -s -X POST "$SHIELD_URL/v1/governance/reviews/$CID/decisions" -H "X-API-Key: $KEY" \
  -d '{"decisions":[{"agent_id":"billing-agent","tool":"send_email","decision":"revoke"}]}'
# close + apply
curl -s -X POST "$SHIELD_URL/v1/governance/reviews/$CID/close" -H "X-API-Key: $KEY"
```

Every decision and the close action is retained on the campaign (reviewer,
timestamp, applied actions) as the certification trail.

## 4. Delegation chains

When an agent spawns a sub-agent, the child's token records which agent
delegated to it. Two controls govern that link, both **off by default**.

### Prove the parent

By default `parent_agent_id` is whatever the caller put in the request body.
Shield signs it, but nothing verifies that the named parent exists or delegated
anything — so the lineage in your audit is a caller-supplied string.

```
SHIELD_DELEGATION_PARENT_PROOF=required
```

The parent is then derived from a **verified parent token** the caller presents
as `parent_agent_token`, and the body field is ignored. Holding a valid parent
token already implies more authority than the child will have, so there is no
escalation in deriving from it. A parent token belonging to a different tenant
is refused with `403`.

```bash
curl -X POST "$SHIELD/v1/tenant/me/agent-auth/agent-token" -H "X-API-Key: $TENANT_KEY" -H 'Content-Type: application/json' -d "{\"user_sub\":\"alice\",\"agent_id\":\"research-bot\",\"agent_instance_id\":\"inst-2\",\"build_hash\":\"b\",\"model_version\":\"m\",\"session_id\":\"s\",\"parent_agent_token\":\"$PARENT_TOKEN\"}"
```

### Bound the depth

```
SHIELD_MAX_DELEGATION_DEPTH=1
```

A root token is depth 0, its child depth 1. With the limit at 1, that child
cannot mint a grandchild — `403 delegation depth 2 exceeds limit 1`. The depth
is enforced at mint **and** at verification, so lowering the ceiling takes
effect immediately rather than waiting out every issued token's lifetime.

{: .warning }
> **Set the proof flag first.** A depth limit without
> `SHIELD_DELEGATION_PARENT_PROOF=required` bounds nothing: the depth is
> computed from the parent the caller named, so the caller also chooses its own
> depth. Shield logs a warning at boot if you configure it that way, but the
> limit will silently not apply.

### Rollout order

1. Set `SHIELD_DELEGATION_PARENT_PROOF=required`, no depth limit. Chains become
   proven but unbounded. Nothing breaks that was not already asserting an
   unproven parent.
2. Watch `delegation_depth` in the audit to learn your real maximum. This is
   why the claim reaches the audit before the limit is enforced.
3. Set `SHIELD_MAX_DELEGATION_DEPTH` at or above that observed maximum.
4. Lower it deliberately.

Turning both on at once without step 2 is how you break a legitimate
three-hop workflow.

### Known limit

**Revoking a parent does not revoke its children.** A child token stays valid
until its own expiry, capped at 15 minutes. Cascading revocation would need a
chain registry, and a registry means a Redis read per guarded request — the
15-minute ceiling is the mitigation instead. Revoke the child's
`agent_instance_id` directly if you need it gone sooner.

## See also

- [Agentic Integration Guide](/agentic-integration-guide/) — registering agents and entitlements.
- [Continuous Identity & Auto-Revoke](/continuous-identity/) — runtime revocation and signal exchange.
- [Developer Guide — MCP & APIs](/developer-guide-mcp/) — how tool access is governed at runtime.
