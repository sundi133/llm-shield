---
title: "Spec: global data policy for tool calls"
layout: default
nav_order: 56
permalink: /spec-global-tool-data-policy/
description: "Data policies are per tool and exact match only, so a tool nobody has written a policy for is judged by nothing. One declared, tenant-wide default, configurable from the portal and the API."
---

# Spec: global data policy for tool calls

Status: DRAFT, awaiting approval. No code written.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. Problem & outcome

Data policies are stored per tool and matched exactly
(`guardrails/agentic/tool/payload_risk.py::_load_data_policies`). There is no
wildcard and no default. A tool with no policy of its own is judged by nothing.

That gap was created deliberately, this week, and it needs filling.
`docs/spec-tool-output-action-authority.md` removed the old fallback, which
handed the model the string *"No specific data policies configured. Apply
reasonable security defaults."* Removing it was right: it was an instruction to
invent a rule, and it produced blocks that could not be explained to the
customer whose call was refused. But it was also, in effect, a global policy.
Taking it away leaves nothing behind it.

Three consequences of per-tool-only:

- **Enforcement lags discovery, permanently.** An upstream MCP server adds a
  tool. It is immediately callable and completely unjudged until somebody
  notices and writes a policy. Nothing surfaces the gap.
- **Most policy is not tool specific.** "Never return a national ID" is a
  property of the tenant, not of `customer_profile_get`. Expressing it per tool
  means writing it once per tool and watching the copies drift. One live tenant
  already carries three near-duplicate `customer_profile*` policies created in a
  single week.
- **Absence of configuration means absence of protection**, which is the wrong
  default for a security product.

**Outcome.** A tenant can declare one data policy that applies to every tool
call, from the portal and from the API, and see which policy decided a given
call. A tool with no policy of its own inherits it.

Observable success condition: with a global policy declaring "never return a
national ID" and **no** policy on `some_new_tool`, a call to `some_new_tool`
returning a national ID is judged, and the telemetry entry names the global
policy as the source.

### Non-goals

- **Not** reintroducing implicit scope. The defect fixed this week was
  `customer_profile.get` silently judging `patient_lookup`. This is the opposite:
  scope that is declared, visible, and attributable.
- **Not** changing per-tool policies, their storage shape, or their API.
- **Not** a policy inheritance tree. One global layer, one tool layer. Deeper
  hierarchies can come later if asked for; they are not needed to close this gap.
- **Not** cross-tenant or platform-wide policy. Global means tenant-wide.

## 2. Plane & latency contract

- **Planes: both.** `api/routes_data_policies.py` already mounts on the data
  plane (`core/app.py:48`) and the admin plane (`admin_app.py:62`), so the API
  is available on both without new wiring. The portal UI is admin plane only.
- **Touches the GUARD PATH?** Yes. `_load_data_policies` runs inside
  `payload_risk` (tool input) and `tool_output_sanitization` (tool output).
- **Latency budget: one additional dict lookup, no additional I/O.** See §3: the
  global policy lives in the **same Redis hash** already read on that path, so
  the request makes the same number of round trips it makes today.

This constraint drove the storage decision. A separate Redis key would have been
cleaner in isolation and would have added a second store round trip to every
guarded tool call. Given that a metrics write on this same path cost roughly
1.6s p50 until it was moved off (`docs/spec-metrics-off-hot-path.md`), adding
round trips here is not acceptable for a config read.

## 3. Data model

Global policy is stored in the existing `data_policies:{tenant_id}` hash under a
reserved key:

```
data_policies:{tenant_id}
  "customer_profile_get" : { sanitization_rules, role_policies, ... }
  "statement_generate"   : { ... }
  "__global__"           : { ... }        <- new, same shape
```

Same value shape as a tool policy, so the editor, the formatter, and the judge
prompt need no new vocabulary.

**Reserved-name collision.** `tool_name` is currently unvalidated on
`POST /v1/data-policies/tools/{tool_name}/policy`, so a caller could create a
tool policy literally named `__global__` and silently become the global policy.
Writes to the per-tool endpoint therefore **reject** the reserved name with 422,
and the dedicated endpoint in §4 is the only way to set it. A regression test
pins the refusal.

**Listing.** `GET /v1/data-policies/tools` filters `__global__` out of the tool
list, because it is not a tool. It is returned by the dedicated endpoint and
shown separately in the portal.

Tenant scoping is unchanged: one hash per tenant, resolved from the API key by
the existing path. There is no cross-tenant surface.

## 4. API / interface

Three endpoints, mirroring the per-tool shape so nothing new has to be learned:

| method | path | purpose |
|---|---|---|
| `GET` | `/v1/data-policies/global/policy` | read the global policy |
| `POST` | `/v1/data-policies/global/policy` | create or replace it |
| `DELETE` | `/v1/data-policies/global/policy` | remove it |

Body is the existing `ToolDataPolicy` model (`sanitization_rules`,
`role_policies`, `compliance_framework`) plus one field:

```json
{
  "sanitization_rules": [...],
  "role_policies": [...],
  "enabled": true
}
```

`enabled` allows a tenant to author a global policy and turn it off without
deleting it, which is what an operator wants when narrowing a false positive
under time pressure.

A dedicated path rather than a reserved `tool_name` on the existing route: it
cannot be created by accident, it reads correctly in an audit trail, and it
gives the portal something unambiguous to bind a separate editor to.

**Per-tool opt out.** A tool policy may set `inherit_global: false` to be judged
by its own rules alone. Default is `true`. Without this, a tool that genuinely
must return an email address forces the operator to delete or weaken the global
rule for everyone, which is how global policies get abandoned.

### Resolution order

```
effective = global (unless inherit_global is false) + tool policy
```

Both are passed to the judge, each labelled with its source. The tool policy is
**additive**: it may restrict further. It does not silently override the global
rule, because a policy that can be cancelled from below is not a floor.

Where they genuinely conflict for the same role, the more restrictive action
wins, using the ladder already canonical in this repo
(`pass < log < warn < redact/mask < block`, `api/routes_classify.py:629`).

### Admin panel

**Tool Registry -> Data Policies** already renders one card per tool
(`static/tenant.html`, `tp-sub-data-policies`). Add a **Default policy (all
tools)** card pinned above the search box and visually distinguished, with the
same rules editor the per-tool cards use plus the `enabled` toggle.

Each per-tool card gains an "Inherits default policy" indicator and the
`inherit_global` toggle, so an operator can see whether a tool is judged by one
policy or two without opening another screen.

## 5. Security & backward compatibility

- **Default off.** No global policy exists until a tenant creates one, so
  behaviour on upgrade is byte-identical. This is a capability, not a new
  default posture.
- **Recommend `warn` first.** The documented path is to declare the global
  policy at `warn`, watch Telemetry, then escalate per tool. Same
  declare-then-enforce ladder as `SHIELD_GUARD_REQUIRE_KEY` and the tool output
  action.
- **Authz:** unchanged. Same tenant API key, same router, same tenant scoping.
  No new caller-reachable surface beyond three CRUD endpoints on the caller's
  own tenant.
- **Escape hatch:** `SHIELD_GLOBAL_DATA_POLICY=off` ignores the global policy at
  enforcement time without deleting it.

**The failure mode worth naming.** A global policy is one object whose blast
radius is every tool call on the tenant. A careless `action: block` rule stops
the whole fleet. Three mitigations: default `warn` in the UI, a confirmation on
saving a global rule whose action is `block`, and the source attribution in §6
so the cause is one click away rather than an investigation.

That investigation is not hypothetical. Tracing a single unexplained block
through this system this week took multiple hours precisely because no surface
named which policy fired.

## 6. Observability

The telemetry entry for a tool decision records which policy produced it:
`"policy_source": "global" | "tool" | "both"`.

Without this, a global policy makes debugging worse rather than better, because
a block could originate from either layer and nothing distinguishes them. This
field is the difference between a capability and a liability.

## 7. Packaging & deploy

- **New pip deps:** none.
- **`Dockerfile.admin`:** no change. `api/routes_data_policies.py` is already
  imported by `admin_app.py`. `tests/test_admin_dockerfile_imports.py` must stay
  green.
- **Images:** both planes (API is mounted on both; UI is admin only).
- **Env flags:** `SHIELD_GLOBAL_DATA_POLICY` (unset = enabled).
- **Rollout:** ship, create a global policy at `warn` on one tenant, confirm it
  is judged on a tool with no policy of its own, confirm `policy_source` is
  populated, then escalate.

## 8. Failure modes & edge cases

| condition | behaviour |
|---|---|
| No global policy | Unchanged from today: tool policy alone, or no judgment. |
| Global exists, tool has none | Global alone. **The gap this closes.** |
| Global exists, tool has one | Both, tool additive. Global cannot be cancelled from below. |
| `inherit_global: false` on a tool | Tool policy alone, deliberately. |
| Global `enabled: false` | Ignored, not deleted. |
| Conflicting actions for a role | More restrictive wins, per the canonical ladder. |
| Write to `/tools/__global__/policy` | 422. The reserved name is not settable as a tool. |
| Redis unavailable | Existing behaviour: `_load_data_policies` logs and returns `[]`. Unchanged; this spec adds no new failure path. |
| Global policy very large | Bounded like a tool policy. Both are concatenated into the judge's system prompt, so unbounded growth costs tokens on every guarded call. |
| `SHIELD_GLOBAL_DATA_POLICY=off` | Global ignored at enforcement; config still readable and editable. |

**Fail open vs fail closed:** unchanged. A policy load failure yields no
policies and the existing handling applies. This spec does not alter the
enforcement decision for any tool that has its own policy today.

## 9. Test plan (Definition of Done)

New file `tests/test_global_data_policy.py`:

1. **A tool with no policy is judged by the global policy.** The headline gap.
2. **A tool with its own policy is judged by both**, and the tool's rules can
   restrict further.
3. **The global policy cannot be cancelled by a tool policy** absent
   `inherit_global: false`.
4. **`inherit_global: false` isolates a tool.**
5. **`enabled: false` disables without deleting.**
6. **The reserved name is refused on the per-tool endpoint** (422). The
   collision guard.
7. **`GET /v1/data-policies/tools` does not list `__global__` as a tool.**
8. **Conflicting actions resolve to the more restrictive** across the ladder.
9. **`policy_source` is recorded** as `global`, `tool`, or `both`.
10. **`SHIELD_GLOBAL_DATA_POLICY=off` ignores it** while leaving it readable.
11. **No global policy leaves today's behaviour byte-identical** (the
    backward-compatibility guard).
12. **One store round trip.** Assert the global policy costs no additional
    Redis read, pinning the §2 latency contract against a future refactor that
    splits the key.

Regression suites: `tests/test_mask_redact.py`,
`tests/test_tool_output_action_authority.py`, `tests/test_mcp_enforcement.py`,
`tests/test_data_policy_prefill_order.py`,
`tests/test_admin_dockerfile_imports.py`.

**Definition of done:** full suite green in a clean venv; CI `pytest` gate
passes; portal card renders and round-trips a policy through the API; a live
check showing a policy-less tool judged by the global rule with
`policy_source: "global"` in telemetry.
