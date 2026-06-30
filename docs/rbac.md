---
title: Role-Based Access (RBAC)
layout: default
permalink: /rbac/
description: How to control which roles and agents may call which tools — register agents with role_permissions and enforce at the tool boundary.
---

# Role-Based Access (RBAC)
{: .no_toc }

RBAC controls **which roles (and which agents) may call which tools**. It is the
authorization layer, separate from [Tool Data Policies](/tool-data-policies/),
which control *what data a role may see* once a tool is allowed.

- **RBAC** → *can this role call this tool?* (deterministic, no LLM)
- **Tool Data Policy** → *what fields may this role see in the result?* (LLM/DLP)

1. TOC
{:toc}

## The model

Each **agent** is registered with:

- `tools` — the agent's full tool capability.
- `role_permissions` — a map of `role → [tools that role may call]`.
- (optional) `allowed_resources`, `clearance_max`, `require_resource_scope` —
  object-level scope for [capability tokens](/agent-governance/).

At runtime, a caller presents an **agent identity** and a **user role**; the
guard allows the call only if the tool is permitted for that role.

## Register an agent (the API)

```bash
SHIELD=https://your-shield-data-plane
KEY="X-API-Key: <tenant-api-key>"

curl -X POST "$SHIELD/v1/agents/registry" \
  -H "$KEY" -H "Content-Type: application/json" \
  -d '{
    "agent_id": "people-ops-agent",
    "tools": ["search", "send_hr_email", "update_salary"],
    "role_permissions": {
      "employee":      [],
      "manager":       ["send_hr_email"],
      "hr_specialist": ["send_hr_email"],
      "hr_admin":      ["update_salary", "send_hr_email"]
    },
    "status": "active"
  }'
```

- `status` must be `active` for the agent to act (`inactive`/`disabled` are
  fail-closed, even in monitor mode).
- A registered agent with **no** permitted tools for a role is denied — fail
  closed by default.

## Enforce a tool call (the API)

Check before executing a tool:

```bash
curl -X POST "$SHIELD/v1/shield/tool/check" \
  -H "$KEY" -H "X-Agent-Key: people-ops-agent" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_key": "people-ops-agent",
    "tool_name": "update_salary",
    "user_role": "hr_admin",
    "tool_params": {"employee_id": "EMP-1001", "new_salary_usd": 180000}
  }'
# -> {"allowed": true|false, "action": "...", "guardrail_results": [...]}
```

The same check runs over MCP as the `shield_check_tool` tool, and on the MCP
proxy's `tools/call` path automatically.

**Agent identity is authenticated, not asserted.** The `X-Agent-Key` header is
the agent's identity; if it is present and disagrees with `agent_key` in the
body, the call is blocked as an impersonation attempt. Keep them consistent.

## Object-level scope (capabilities)

For high-risk tools, bind access to a specific resource and clearance with a
signed capability instead of trusting a plaintext role:

- `allowed_resources` — glob patterns the agent may mint caps for, e.g.
  `employee/{user_sub}/*`. With none configured, set
  `SHIELD_REQUIRE_RESOURCE_SCOPE=true` to deny unbounded mints.
- `clearance_max` — the agent's clearance ceiling; enforced at mint when
  `SHIELD_ENFORCE_CAP_CLEARANCE=true`.

See [Agent Governance](/agent-governance/) for the mint → verify flow.

## Two ways to configure

- **Tenant Portal** → Agents / Registry — register agents and edit
  `role_permissions` in the UI.
- **API** → `POST /v1/agents/registry` (above). `GET /v1/agents/registry` lists
  the tenant's agents.

## Field reference

| Field | Type | Notes |
|---|---|---|
| `agent_id` | string | 1–128 chars, alphanumeric/`-`/`_` |
| `tools` | list | the agent's full tool set |
| `role_permissions` | map | `role → [tools]` the role may call |
| `status` | `active`·`inactive`·`disabled` | only `active` may act |
| `allowed_resources` | list | glob patterns for capability minting |
| `require_resource_scope` | bool | force deny-by-default resource scope |
| `clearance_max` | string | `public`·`internal`·`confidential`·`restricted` |

## Tips

- Keep `role_permissions` **restrictive** — list only the tools each role needs.
- Pair RBAC with a [Tool Data Policy](/tool-data-policies/): RBAC gates the call,
  the data policy redacts the result.
- Run in **monitor** mode first ([Policy Lifecycle](/policy-lifecycle/)) to see
  what would be denied before enforcing.
