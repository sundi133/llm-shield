---
title: "Spec: a role policy that applies to every role"
layout: default
nav_order: 58
permalink: /spec-wildcard-role-policy/
description: "Data policies must name a role, and role matching is done by the LLM reading prose. A rule meant for everyone has to enumerate every role, or rely on the model guessing what an asterisk means."
---

# Spec: a role policy that applies to every role

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

**There is no way to write a data policy that applies to everyone.**
`RoleDataPolicy.role` is required, no wildcard is handled anywhere, and role
matching is not performed in code at all. `_format_data_policies`
(`guardrails/agentic/tool/payload_risk.py:294`) renders the rule as prose and
the model decides whether it applies:

```
role='support'  ->  - Role 'support': block (scope: all)
role='*'        ->  - Role '*': block (scope: all)
role='any'      ->  - Role 'any': block (scope: all)
```

An operator can therefore write `*` today and it will **probably** work, because
a model will probably read an asterisk as "everyone". Probably, on undocumented
syntax, re-evaluated on every request by a component whose phrasing already
varies between identical calls. That is not a control, it is a coincidence that
usually holds.

The supported alternative is to enumerate. One live tenant carries **29 distinct
role names** across its policies (`admin`, `banker`, `branch_manager`, `ci_bot`,
`contractor`, `doctor`, `nurse`, `intern`, `oncall`, `teller`, and so on). A rule
like "never return a national ID" has to be written 29 times, and every new role
silently escapes it until someone remembers.

This is not hypothetical. A tenant wrote exactly that rule for `role: support`,
called the tool as `user`, and received an unredacted passport and national ID.
The policy was correct; it simply named a role the caller did not have.

**Outcome.** A `role_policies` entry with `role: "*"` applies to every role,
resolved in code before the prompt is built, so the model is told about the
caller's actual role and has nothing to infer.

Observable success condition: a policy whose only entry is `{"role": "*",
"action": "block", "output_rules": [...]}` produces, for a caller whose role is
`user`, a prompt containing `Role 'user': block` and no asterisk. The same
policy governs a caller with no role at all.

### Non-goals

- **Not** changing what the model judges once it knows the rule applies.
- **Not** a role hierarchy or group expansion. One wildcard, one exact match.
- **Not** changing the global-vs-tool policy layering
  (`docs/spec-global-tool-data-policy.md`). This is within a single policy.
- **Not** touching RBAC. `role_permissions` on the agent registry is a separate,
  code-enforced mechanism and is unaffected.

## 2. Plane & latency contract

- **Plane:** data plane. `guardrails/agentic/tool/payload_risk.py` (the
  formatter and its two callers), plus schema documentation in
  `api/routes_data_policies.py`.
- **Touches the GUARD PATH?** Yes. Tool input judging (`payload_risk`) and tool
  output judging (`tool_output_sanitization`).
- **Latency budget: zero, and probably negative.** Resolution is a dict lookup
  over a list already in memory. It **removes** prompt tokens, because an
  enumerated policy that listed 29 roles now renders one line.

## 3. Data model

Unchanged in storage. `role_policies[].role` gains one reserved value:

```
"*"   applies to every role
""    applies to callers with NO role   (existing behaviour, unchanged)
```

These are deliberately distinct. `""` is already a real, matched value: it is
what a connection carrying only a tenant key resolves to, and today's policies
rely on it. Conflating the two would silently widen every existing `""` rule to
the entire tenant, which is the kind of change that is discovered during an
incident.

## 4. Interface

No HTTP surface change. `role: "*"` is accepted where any role string is
accepted.

**Resolution, in code, before the prompt is built.** `_format_data_policies`
gains a `user_role` parameter, and both callers pass the caller's resolved role.
For each policy:

1. If an entry exists whose `role` matches the caller exactly, use it and
   **discard the wildcard entry**.
2. Otherwise, if a `"*"` entry exists, render it as the caller's role.
3. Otherwise, render nothing for that policy, as today.

The model therefore never sees an asterisk. It is told `Role 'user': block` and
judges content, which is the only thing it should be judging.

### Exact beats wildcard, including when it is more permissive

```json
[{"role": "*", "action": "block"}, {"role": "admin", "action": "allow"}]
```

An `admin` caller gets `allow`. This is the standard ACL reading and it is what
an operator writing those two lines means: "everyone blocked, except admin."

The alternative, most-restrictive-wins, was rejected: it would make the second
line unwritable, and an operator who cannot express an exception writes no
wildcard at all and goes back to enumerating.

The cost is stated plainly because it is a real footgun: **a permissive exact
entry silently exempts that role from the wildcard.** §6 covers surfacing it.

### Unknown caller role

When the caller's role is empty and a `"*"` entry exists, the wildcard applies
and renders as `Role 'any role': ...` rather than `Role '': ...`, which would be
indistinguishable from the existing no-role rule.

## 5. Security & backward compatibility

- **No behaviour change for any existing policy.** `"*"` is not currently
  handled, so no stored policy can be relying on it as a wildcard today. A
  policy that happens to contain the literal `"*"` is being matched by the model
  on prose, and after this change is matched deterministically, which is
  strictly better defined.
- **Direction of change: strengthening.** A wildcard rule now reliably applies
  where it previously depended on the model reading an asterisk correctly.
- **Escape hatch:** `SHIELD_WILDCARD_ROLE_POLICY=off` treats `"*"` as a literal
  role name again.

**The failure mode to name.** A single `"*"` entry governs every caller on the
tenant. A careless `action: block` there stops every guarded tool call for
everyone. That is the same blast radius as the global policy, and the same
mitigations apply: default the portal to `redact`, confirm before saving a
blocking wildcard, and record which entry decided a call.

## 6. Observability

The rendered rule records which entry produced it:
`policy_role_match: "exact" | "wildcard"`, alongside the existing
`policy_source` from the global policy work.

Without it, "why did this call behave differently for admin" requires reading
the policy JSON and reasoning about precedence. With it, the answer is in the
telemetry row. The precedence rule in §4 is exactly the kind of thing that is
obvious when written and invisible at 2am.

## 7. Packaging & deploy

- **New pip deps:** none.
- **`Dockerfile.admin`:** no change.
- **Images:** data plane. Portal copy only for the admin plane.
- **Env flags:** `SHIELD_WILDCARD_ROLE_POLICY` (unset = enabled).
- **Rollout:** ship, replace an enumerated policy with a single `"*"` entry on
  one tenant, confirm the prompt names the caller's real role and the behaviour
  matches, then confirm an exact entry still overrides it.

## 8. Failure modes & edge cases

| condition | behaviour |
|---|---|
| Only `"*"` present | Applies to every caller. **The feature.** |
| `"*"` plus an exact match for the caller | Exact wins, wildcard discarded. |
| `"*"` plus an exact match for a different role | Wildcard applies to this caller. |
| Two `"*"` entries in one policy | First wins, deterministically. Rendering order is already stable. |
| `"*"` and `""` both present, caller has no role | `""` is an exact match for a roleless caller, so it wins. |
| Caller role empty, only `"*"` present | Wildcard applies, rendered as `any role`. |
| Global and tool policy both have `"*"` | Both render, in the global-then-tool order the layering already defines. |
| `SHIELD_WILDCARD_ROLE_POLICY=off` | `"*"` is a literal role name. Today's behaviour. |
| A role literally named `*` in an agent registry | Cannot be created: `AGENT_ID_RE` and the role charset exclude `*`. No collision. |

**Fail open vs fail closed:** unchanged. This spec decides *which rule is shown
to the judge*, never whether the call proceeds. A policy that resolves to
nothing behaves exactly as an absent policy does today.

## 9. Test plan (Definition of Done)

New file `tests/test_wildcard_role_policy.py`:

1. **A `"*"` entry applies to a caller with any role**, and the rendered prompt
   names the caller's role, not an asterisk. The headline.
2. **It applies to a caller with no role**, rendered as `any role`.
3. **An exact match wins over the wildcard**, including when the exact entry is
   more permissive. The precedence rule.
4. **An exact match for a *different* role does not suppress the wildcard.**
5. **`""` still means "no role" and is not widened.** The backward-compatibility
   guard, and the one that would be a silent security change if it broke.
6. **No wildcard leaves rendering byte-identical to today.**
7. **The model never sees an asterisk** when the flag is on. Asserted on the
   captured prompt, because that is the actual contract.
8. **`policy_role_match` records exact vs wildcard.**
9. **A wildcard collapses an enumerated policy**: a rule written for 29 roles
   and a single `"*"` produce the same decision, and the wildcard prompt is
   shorter.
10. **`SHIELD_WILDCARD_ROLE_POLICY=off` restores literal matching.**
11. **Both callers pass the role through**, `payload_risk` and
    `tool_output_sanitization`, asserted separately. A formatter that supports
    wildcards while one caller forgets to pass the role is the same
    half-applied-fix pattern that left the output side unscoped for months.

Regression suites: `tests/test_data_policy_prefill_order.py`,
`tests/test_llm_redaction.py`, `tests/test_global_data_policy.py`,
`tests/test_tool_output_action_authority.py`, `tests/test_mask_redact.py`.

**Definition of done:** full suite green in a clean venv; CI `pytest` gate
passes; a live check on the reproduction from §1, where a single `"*"` rule
governs a caller whose role is `user`.
