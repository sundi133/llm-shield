---
title: "Spec: agent ownership, environment scoping, delegation visibility"
layout: default
nav_order: 46
permalink: /spec-agent-ownership-environment/
description: "Three gaps between Shield's agent registry and what the agent-identity category is being described as publicly. Two are a day's work. The third is a design decision that should not become a new write on the guard path."
---

# Spec: agent ownership, environment scoping, delegation visibility
{: .no_toc }

Shield can say what an agent may do and prove what it did. It cannot say **who
owns it**, cannot stop a staging agent acting against production, and cannot
answer **"what has alice delegated?"** without reading raw audit records.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. Problem & outcome

Three gaps, found by checking Shield against how the agent-identity category is
being described publicly. Each is real; none is large; one has a trap in it.

**G1 — no owner.** A registry entry carries `agent_id`, `name`, `description`,
`tools`, `role_permissions`, `agent_permissions`, `allowed_resources`,
`require_resource_scope`, `status`, `created_at`, `updated_at`
([routes_agents_registry.py:687](../api/routes_agents_registry.py)). It records
*when* an agent was created and never *by whom* or *who to ask about it*.

This is the first question in every access review. `/v1/governance/*` surfaces
used-vs-granted and drives revocation campaigns, and a reviewer looking at
`payments-bot` with 14 tools has nobody to ask whether it still needs them. The
review then either rubber-stamps or stalls, and both outcomes make the campaign
worthless.

**G2 — no environment.** `grep` for an environment or stage concept across
`core/` and `api/` returns nothing outside `os.environ` reads. An agent
registered for staging is, to Shield, indistinguishable from one registered for
production. Point a staging deployment at the production Shield — a mistake
people make constantly, usually via a copied env file — and every grant applies.

**G3 — delegation is invisible.** `resolve_identity()` produces `acting_for` and
`delegation_verified` in `audit_fields()`
([identity_resolution.py:427](../core/identity_resolution.py)), and those fields
are persisted on the tool path only
([routes_tool.py:299](../api/routes_tool.py) and `:602`). They are **not**
recorded from `/guardrails/*` or `cap/mint`, and there is no way to query them.
So "what has alice delegated, and to which agents?" is answerable by grepping
audit JSON, which means in practice it is not answerable.

### Outcome

- A reviewer opening any agent sees an owner and can contact them.
- A staging agent presented to a production Shield is refused, and the refusal
  cannot be bypassed by anything the caller sends.
- "What has this user delegated?" is one API call.

### Non-goals

- **Ownership is not an authorization input.** It is a human-facing label. The
  moment a grant depends on it, it needs to be verified, and verifying
  free-text team names is a project. §5 states this as an invariant rather than
  a preference.
- **Not a `delegations` table.** §3 explains why persisting a row per delegated
  request is the wrong shape — it is a write on the guard path, it grows
  without bound, and it duplicates an audit trail that already exists.
- **Not OPA or Cedar.** A policy-engine adapter is a real request from
  enterprises standardised on one, and it is a different spec. Do not
  pre-build it.
- **Not `public_key` on the agent entry.** That is proof-of-possession, already
  covered by [spec-agent-token-pop](/spec-agent-token-pop/).
- **Not per-environment separate registries.** One registry, agents declare
  where they may run. Multiple registries is a deployment topology question.

## 2. Plane & latency contract

| Gap | Plane | Guard path? |
|---|---|---|
| G1 ownership | admin (CPU) | **no** |
| G2 environment | admin write, **data-plane enforcement** | **yes** |
| G3 delegation visibility | admin read + data-plane emit | **marginally** |

**G1 touches nothing on the hot path.** It is a field on a record read by
`/v1/agents/registry` and `/v1/governance/*`, both admin.

**G2 does touch the guard path, and this is the item to scrutinise.**
Enforcement belongs beside the existing `role_permissions` read in
[rbac_guard.py:92](../guardrails/agentic/rbac_guard.py), which already has the
agent entry in hand. The added work is:

- one cached read of `SHIELD_ENVIRONMENT` (module-level, not per request)
- one list membership test against `entry.get("environments")`

No Redis, no network, no crypto. **Budget: under 5 µs, and zero when an agent
declares no environments** — the check short-circuits on absence, which is also
what makes it backward compatible.

**G3's emit half is on the guard path but adds no work.** `audit_fields()` is
already computed on every request that calls `resolve_identity()`; the change is
that two more call sites include the dict they already have in a record they
already write. The query half is admin-only.

**Contract: no new I/O on `/guardrails/*`, `cap/mint` or `tools/call`.** Nothing
in this spec adds a store read or a network call to a guarded request.

## 3. Data model

### G1 + G2 — two fields on the existing entry

Key `agents:{tenant_id}` is unchanged in shape. The entry gains:

```json
{
  "agent_id": "payments-bot",
  "owner": "team-payments",
  "owner_contact": "payments-oncall@example.com",
  "environments": ["prod", "staging"]
}
```

- **`owner`** — free text, ≤128 chars. A team name, a group, a person. Shield
  does not resolve it against anything, by design (§5).
- **`owner_contact`** — free text, ≤256 chars. Deliberately not validated as an
  email: it is as likely to be a Slack channel or a PagerDuty rotation, and a
  format check would only teach people to lie to it.
- **`environments`** — list of ≤16 short identifiers. **Absent or empty means
  "any environment"**, which is what makes every existing entry keep working.

All three are optional. An entry written before this change is valid after it.

### G3 — no new key, and that is the point

The instinct is a `delegations` table: `user_id, agent_id, scopes, expires_at`.
It is wrong here for three reasons:

1. **It is a write on the guard path.** Delegation is established per request
   from a token. Recording it means a store write on `/guardrails/*` — the one
   thing this repo's invariants exist to prevent.
2. **It grows without bound.** One row per delegated request, at agent traffic
   volumes, with no natural expiry that is not just the audit's retention.
3. **It already exists.** The decision audit records `acting_for` and
   `delegation_verified` on the tool path today. A second store would be a
   partial, less trustworthy copy of a tamper-evident one.

So G3 is: **emit the fields on the paths that currently omit them, and add a
read endpoint over the audit that already holds them.**

Stateless delegation is a genuine design choice, not an oversight. Its cost is
that there is no "standing grant" to revoke — you revoke the user's token at
the IdP, or the agent instance at Shield. §10 keeps that visible as a decision
rather than burying it.

### Tenant scoping

Inherited entirely. `agents:{tenant_id}` is already per-tenant and every
endpoint resolves the tenant from `X-API-Key` with no tenant parameter. The
delegation query reads the tenant's own audit scope. No new isolation surface,
and §8 asserts it.

## 4. API / interface

### G1 — ownership

`POST /v1/agents/registry` and `PUT /v1/agents/registry/{agent_id}` accept
`owner` and `owner_contact`. Both go through `_sanitize_string` and the length
limits above, alongside the existing `_validate_agent_body` checks
([routes_agents_registry.py:125](../api/routes_agents_registry.py)).

`GET /v1/governance/agents` adds both to its projection
([routes_governance.py:95](../api/routes_governance.py)), so a review campaign
shows who to ask without a second lookup.

**New: `GET /v1/governance/agents/unowned`** — every registered agent with no
`owner`. One call to answer "what in our estate has nobody accountable for it",
which is the question that actually drives adoption of the field.

### G2 — environment

Deployment declares its own environment; agents declare where they may run:

```
SHIELD_ENVIRONMENT=prod        # unset means "unscoped", enforcement off
```

```json
{"environments": ["staging"]}   # on the agent entry
```

Enforcement in `rbac_guard`: if `SHIELD_ENVIRONMENT` is set **and** the agent
declares a non-empty `environments` list **and** the deployment's environment is
not in it, the tool is denied with:

```
agent 'x' is registered for [staging], not 'prod'
```

**The environment is a property of the deployment, never of the request.** This
is the crux. If it came from a header or the request body, a caller would set
it, and it would be `X-User-Role` all over again — a control that reads as
enforcement and is a suggestion. Reading it from the Shield process makes it
unforgeable by construction, and costs a cached env read.

### G3 — delegation visibility

Two changes:

1. **Emit.** `api/routes_classify.py` and the `cap/mint` path include
   `_resolved.audit_fields()` in the record they already write, matching what
   `routes_tool.py` does today. No new computation; the dict is already built.

2. **Read.** `GET /v1/tenant/me/delegations?user_sub=…&since=…&limit=…` on the
   admin plane, reading the existing decision audit and returning:

```json
{"user_sub": "alice@example.com",
 "agents": [{"agent_id": "payments-bot",
             "delegation_verified": true,
             "first_seen": "…", "last_seen": "…", "decisions": 42}]}
```

Aggregated per agent rather than one row per request: the reviewer's question is
"which agents act for alice", not "list every call".

## 5. Security & backward compatibility

**Default behaviour: unchanged.** All three fields are optional, and G2's
enforcement requires `SHIELD_ENVIRONMENT` to be set — unset is today's
behaviour exactly. An existing deployment upgrading sees no difference.

**Ownership is metadata, and must stay metadata.** No grant, denial, capability
or policy may read `owner`. The reason is concrete: `owner` is free text, so if
it ever gates access, an authorization decision depends on an unverified string
a tenant admin types. §8 test 9 asserts no authorization path reads it, because
this is the kind of invariant that erodes one convenient exception at a time.

**Environment fails open on absence, closed on mismatch.**

| deployment | agent declares | result |
|---|---|---|
| unset | anything | allowed — enforcement off |
| `prod` | absent/empty | allowed — unscoped agent |
| `prod` | `["prod"]` | allowed |
| `prod` | `["staging"]` | **denied** |

Open-on-absence is what keeps it non-breaking. It also means an operator who
sets `SHIELD_ENVIRONMENT` and expects instant protection gets none until agents
declare — so `GET /v1/governance/agents/unowned` gains a sibling count of
agents with no `environments`, and the runbook says to check it.

**Environment is not a security boundary on its own.** It stops a
misconfiguration, not an attacker: anyone who can write the registry can add
`prod` to the list. It is a guardrail against the copied-env-file mistake, and
the docs must say so rather than implying tenant isolation.

**Delegation visibility exposes no new data.** Everything the endpoint returns
is already in the tenant's audit. It is a read path over existing records with
the existing tenant scoping.

## 6. Packaging & deploy

- **New module:** none. All three land in files that already exist:
  `api/routes_agents_registry.py`, `api/routes_governance.py`,
  `api/routes_tenant_self.py`, `guardrails/agentic/rbac_guard.py`,
  `api/routes_classify.py`.
- **`Dockerfile.admin`:** no change. Every file above is already in the
  allowlist. `tests/test_admin_dockerfile_imports.py` and
  `tests/test_admin_image_transitive_imports.py` must stay green as the
  evidence, not the assumption.
- **New pip dependency:** none.
- **Env flags:** one new, `SHIELD_ENVIRONMENT`, unset by default.
- **Images to rebuild:** both. The admin plane writes the fields, the data
  plane enforces `environments`. Order does not matter: an admin plane writing
  `environments` against an older data plane is inert (the field is ignored),
  and a newer data plane with `SHIELD_ENVIRONMENT` unset enforces nothing.
- **Rollback:** unset `SHIELD_ENVIRONMENT`. Stored fields become inert
  metadata; nothing to migrate or clean up.

## 7. Failure modes & edge cases

| condition | behaviour | posture |
|---|---|---|
| `owner` absent | allowed; listed by `/agents/unowned` | open, visible |
| `owner` over 128 chars | 400 at write | closed |
| `owner` containing markup | sanitised by the existing `_sanitize_string` | closed |
| `environments` absent or `[]` | agent runs anywhere | **open by design** |
| `environments` set, `SHIELD_ENVIRONMENT` unset | no enforcement; counted in the unscoped report | open, visible |
| `environments` mismatch | tool denied with the environment named | closed |
| `environments` not a list | 400 at write | closed |
| `environments` over 16 entries | 400 at write | closed |
| `SHIELD_ENVIRONMENT` set to whitespace | treated as unset | open |
| environment names differing in case | **exact match only**, `Prod` ≠ `prod` | closed, and documented |
| agent entry unreadable / Redis down | existing `rbac_guard` behaviour, unchanged | unchanged |
| delegation query with no `user_sub` | 400 | closed |
| delegation query, no audit records | `{"agents": []}`, not a 404 | open |
| delegation query over a huge window | `limit` capped at 1000, oldest dropped, count reported | bounded |

**Exact-match on environment names is deliberate.** Case-insensitive matching
invites `Prod`/`prod`/`PROD` to coexist and mean the same thing until one day
they do not. Refusing the mismatch loudly is better than papering over it,
provided the error names both values — which it does.

## 8. Test plan (Definition of Done)

**G1 ownership**
1. `owner` and `owner_contact` round-trip through POST and PUT.
2. Absent owner is valid; the entry writes and reads back.
3. Over-length owner → 400; over-length contact → 400.
4. Markup in `owner` is sanitised, matching existing field behaviour.
5. `GET /v1/governance/agents` includes both fields.
6. `GET /v1/governance/agents/unowned` lists exactly the agents with no owner.
7. PUT with no `owner` key does **not** clear an existing owner — partial
   updates must not silently delete metadata.

**G2 environment**
8. Matrix from §5, all four rows.
9. **No authorization path reads `owner`** — asserted by spying on the entry
    access in `rbac_guard` and the cap-mint decision. The invariant test.
10. `environments` not a list → 400; over 16 → 400.
11. Case mismatch denies, and the message names both values.
12. `SHIELD_ENVIRONMENT` whitespace-only behaves as unset.
13. An entry written before this change (no `environments` key) is allowed
    under any `SHIELD_ENVIRONMENT`. The backward-compatibility guard.
14. Zero store reads added: spy on the Redis client across a guarded request
    with and without `SHIELD_ENVIRONMENT` set, and assert the counts match.

**G3 delegation**
15. `audit_fields()` appears in the record written by `routes_classify`.
16. Same for the `cap/mint` path.
17. Query aggregates per agent with correct counts and first/last seen.
18. Query without `user_sub` → 400.
19. Query with no matching records → empty list, 200.
20. `limit` is capped and the cap is reported in the response.
21. One tenant's query never returns another tenant's delegations.

**Regression**
22. Existing registry tests pass unmodified. If any needs editing, the change
    was not additive.
23. `tests/test_admin_dockerfile_imports.py` and
    `tests/test_admin_image_transitive_imports.py` pass.

**Gate**
24. `python -m pytest tests -q` green in a clean venv.
25. CI `pytest` gate green.

## 9. Task breakdown (one PR each)

**PR 1 — ownership.** Fields, validation, governance projection, the unowned
report, tests 1 to 7. Independently useful: it makes access-review campaigns
actionable, and nothing else depends on it.

**PR 2 — environment.** `SHIELD_ENVIRONMENT`, the `environments` field,
enforcement in `rbac_guard`, tests 8 to 14. Test 14 (zero added store reads) is
the one to write first — it is the guard-path claim, and it is easier to keep
true than to restore.

**PR 3 — delegation emit.** `audit_fields()` from `routes_classify` and the
cap-mint path, tests 15 and 16. Small, and useful alone: the data starts
accumulating before the endpoint that reads it exists, so the endpoint has
something to return on day one.

**PR 4 — delegation query.** The endpoint, aggregation, limits, tests 17 to 21.

**PR 5 — docs.** Registry fields in the agent-governance guide; the environment
rollout in the runbook, including that it is a misconfiguration guardrail and
not tenant isolation.

PR 3 should land a week or two before PR 4 in calendar terms if possible, for
the reason above.

## 10. Open decisions

1. **Should `owner` be free text or a structured reference?** Free text ships in
   a day and is honest about being metadata. A reference to a group in the
   tenant's IdP is more useful and drags in directory integration. Proposed:
   free text now, and if it is ever wanted as a real reference, that is a
   different field rather than a reinterpretation of this one.
2. **Should stateless delegation stay stateless?** §3 argues yes. The cost is no
   standing grant to revoke. If a customer needs "revoke alice's delegation to
   payments-bot" as a discrete action, that is a genuine feature and a separate
   spec — not a widening of this one.
3. **Should `environments` default to `["prod"]` for new agents?** Safer, and it
   breaks every registration script that does not know the field yet. Proposed:
   no default. Revisit once the unscoped-agent count is something operators
   actually look at.
