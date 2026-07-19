---
title: AI Bill of Materials (AIBOM)
layout: default
nav_order: 17
permalink: /aibom/
description: Shield generates a machine-readable AI Bill of Materials for every integrated app - agents, tools, MCP servers, guardrails, and policies observed live, plus declared models, prompts, and data sources - with approved snapshots and drift detection.
---

# AI Bill of Materials (AIBOM)
{: .no_toc }

When your app integrates with Shield, Shield already sees most of what your
AI system is made of: registered and shadow agents, tool definitions and
policies, MCP gateway routes, enabled guardrails, and RBAC roles. The AIBOM
API assembles all of it into a machine-readable inventory that follows the
AIBOM Specification v1.0, so your app gets its bill of materials generated
for it instead of maintaining one by hand.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## What you get

- **A generated inventory.** One call returns your application's models,
  prompts, agents (including shadow agents observed in traffic), MCP
  servers, tools, guardrails, runtime policies, identity surface, and
  observability summary as a single JSON document.
- **Declared components.** Whatever Shield cannot observe (your LLM models,
  prompt templates, vector stores, memory backends, package supply chain)
  your app declares once through a small API, and it merges into the same
  document.
- **Approved snapshots.** Freeze the current inventory as your design-time
  baseline once it has been reviewed.
- **Drift detection.** Compare the live inventory against the approved
  snapshot at any time. New agents, new tool grants, changed guardrails,
  and changed MCP servers are reported field by field; ordinary traffic
  churn is not drift.
- **Threat, compliance, and risk context.** Each inventory category is
  mapped to the AIBOM v1.0 threat taxonomy and to control references
  (OWASP LLM Top 10, NIST AI RMF, NIST 800-53, ISO/IEC 42001 and 27001,
  SOC 2, EU AI Act), and every asset gets a transparent, recomputable risk
  rating.

All endpoints live on the admin plane and read data Shield has already
recorded. Nothing runs on the guard path, so generating a BOM never adds
latency to guarded traffic.

## Generate your AIBOM

```bash
curl -s https://<shield-admin>/v1/tenant/me/aibom \
  -H "X-API-Key: $SHIELD_TENANT_KEY" | jq .
```

Use `?view=observed` for only what Shield sees at runtime, `?view=declared`
for only your declared components, or the default `view=full` for both.
Every section that could not be loaded or was truncated is listed in
`generation_notes`, so the document never has silent gaps.

## Declare what Shield cannot see

```bash
curl -s -X PUT https://<shield-admin>/v1/tenant/me/aibom/components/models \
  -H "X-API-Key: $SHIELD_TENANT_KEY" -H "Content-Type: application/json" \
  -d '{"components": {"gpt-5": {"provider": "openai", "version": "latest",
       "context_window": 200000, "supports_tools": true, "risk_rating": "high"}}}'
```

Sections: `models`, `prompts`, `knowledge_sources`, `memory`,
`supply_chain`, and flat `metadata` fields such as `environment` and
`owner`. Updates merge by component id; sending `null` for an id deletes
it. Declare secret **names** only (for example `"secrets_used":
["OPENAI_API_KEY"]`): values that look like credentials are rejected, so
secret material can never enter a BOM.

## Approve a baseline and watch for drift

```bash
# after review, freeze the current inventory
curl -s -X POST https://<shield-admin>/v1/tenant/me/aibom/snapshots \
  -H "X-API-Key: $SHIELD_TENANT_KEY" -d '{"approved_by": "alice", "note": "Q3 baseline"}'

# any time later
curl -s https://<shield-admin>/v1/tenant/me/aibom/drift \
  -H "X-API-Key: $SHIELD_TENANT_KEY" | jq '.drift_count, .drift.agents'
```

The drift report lists `added`, `removed`, and field-level `changed`
entries per section. Fields that change with normal traffic (`last_seen`,
recent tool use, metrics, timestamps) are excluded, so a non-zero
`drift_count` always means a configuration change: a new shadow agent, a
widened tool grant, a disabled guardrail, a new MCP upstream.

To be notified instead of polling, subscribe a webhook to the
`aibom_drift_detected` event. The payload carries only a summary (drift
count and affected section names), never the full document.

## Reading the risk section

Every asset's rating echoes its inputs, so you can recompute it by hand:

```json
{
  "asset_type": "agent", "asset_id": "rogue-bot",
  "likelihood": 3, "impact": 1, "score": 3, "level": "medium",
  "factors": ["shadow agent: observed in traffic, never registered"]
}
```

Shadow agents, tools without policies, and agents using tools outside
their grants raise likelihood; broader tool grants and credentialed MCP
upstreams raise impact. Declared components carry the `risk_rating` you
declared, or `informational` when there is no runtime signal. The
`overall` level is the highest actionable per-asset level.

## Notes and limits

- Runtime activity fields derive from a bounded buffer of recent auth
  events; absence of recent activity never marks a component as removed.
- Per-section emission caps (500 agents, 500 tools, 200 MCP servers) and
  declare limits (200 components and 64 KB per section) are reported in
  `generation_notes` when hit.
- Snapshots keep the 20 most recent baselines per tenant.
- Compliance references are pointers for your auditors, not a
  certification claim.
