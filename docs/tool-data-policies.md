---
title: Tool Data Policies
layout: default
permalink: /tool-data-policies/
description: How to add a per-tool data policy: control what each role can see in a tool's inputs and outputs, via the Tenant Portal or the API.
---

# Tool Data Policies
{: .no_toc }

A **tool data policy** controls, per tool and per role, what a caller may do with
a tool and what data they may see in its **inputs** and **outputs**. It is the
DLP layer that runs around agentic tool calls.

1. TOC
{:toc}

## What a policy contains

Each policy is attached to one tool (e.g. `lookup_employee`, `check_vitals`) and
holds:

- **Role policies**: for each role, an action and the rules that govern it.
- **Sanitization rules**: optional regex redactions (fast, no LLM).
- **`sanitization_intent`**: an optional natural-language description of what
  must never leave the tool (evaluated by the LLM).
- **Scope mappings, compliance framework, audit/retention**: optional metadata.

Per-role action:

| Action | Meaning |
|---|---|
| `allow` | full access |
| `redact` | mask sensitive fields |
| `mask` | partial mask |
| `block` | deny if rules are violated |

## Where it runs

- **Input rules** are checked against the tool's **parameters** before it runs
  (`tool_call_validation` / `payload_risk`).
- **Output rules** are checked against the tool's **result** before the agent
  uses it (`tool_output_sanitization`).

Both are evaluated by the guardrail model (vLLM) against your rule text. Write
the rules in plain English, one per line. Regex `sanitization_rules` run first
as a fast path; the LLM handles everything else.

## Option 1: Tenant Portal (UI)

1. Open the **Tenant Portal → Tool Policies**.
2. Click the tool (e.g. `check_vitals`).
3. Under **Role access**, for each role set the action (allow/redact/mask/block),
   the **Data scope** (comma-separated categories visible to that role), and the
   **Input rules** / **Output rules** (one per line).
4. **Save data policy.** Nothing is saved until you click save.

## Option 2: API

Create or update a tool's policy:

```bash
SHIELD=https://your-shield-data-plane
KEY="X-API-Key: <tenant-api-key>"

curl -X POST "$SHIELD/v1/data-policies/tools/lookup_employee/policy" \
  -H "$KEY" -H "Content-Type: application/json" \
  -d '{
    "tool_name": "lookup_employee",
    "role_policies": [
      {
        "role": "employee",
        "action": "redact",
        "redaction_level": "partial",
        "data_scope": ["directory"],
        "input_rules": [
          "Allow lookup of exactly one employee_id",
          "Block bulk or name-only lookups"
        ],
        "output_rules": [
          "Allow name, title, department, office",
          "Redact work_email and any phone number",
          "Block date of birth, SSN, and home address"
        ]
      },
      {
        "role": "hr_admin",
        "action": "allow",
        "data_scope": ["directory", "compensation"]
      }
    ],
    "compliance_framework": "hipaa",
    "audit_required": true
  }'
```

View or delete it:

```bash
curl "$SHIELD/v1/data-policies/tools/lookup_employee/policy" -H "$KEY"
curl -X DELETE "$SHIELD/v1/data-policies/tools/lookup_employee/policy" -H "$KEY"
```

Dry-run the AI sanitizer against a sample before saving:

```bash
curl -X POST "$SHIELD/v1/data-policies/preview-sanitization" \
  -H "$KEY" -H "Content-Type: application/json" \
  -d '{"payload":"name=Sarah Chen, ssn=123-45-6789","intent":"never reveal SSN","stage":"output","tool_name":"lookup_employee"}'
```

## Field reference

**`role_policies[]`**

| Field | Values | Notes |
|---|---|---|
| `role` | any role string | matched against the caller's `user_role` |
| `action` | `allow` · `redact` · `mask` · `block` | what happens on a match |
| `data_scope` | list of category names | categories this role may see |
| `redaction_level` | `none` · `partial` · `full` | how aggressively to mask |
| `input_rules` | list of strings | checked against tool **params** |
| `output_rules` | list of strings | checked against tool **output** |

**Top level:** `sanitization_rules[]` (regex: `regex`, `replacement`, `severity`,
`action`), `sanitization_intent` (NL), `sanitization_mode` (`regex` · `ai` ·
`both`), `scope_mappings[]`, `compliance_framework` (`hipaa` · `pci_dss` ·
`gdpr`), `audit_required`, `retention_days`.

## Redact reliably: write a transform, not a prohibition

`tool_output_sanitization` lets the model choose the action (allow / redact /
block) against your rules. For sensitive data it **defaults to block**, and a
rule phrased as a pure prohibition makes that non-deterministic: the same call
blocks most of the time and redacts occasionally. If you want a masked result on
every call, the rule wording is the control, not luck, and not a code change.

**A prohibition tends to block:**

```
"Never return a card number."
"Never return a national ID, passport, or SSN."
```

**A transform with an explicit action redacts deterministically:**

```
"When a card number is present you MUST use action=redact (do NOT block).
 Return the record unchanged EXCEPT mask the card to its last 4 digits as
 **** **** **** NNNN, and remove the CVV."

"Mask any national ID, passport number, or SSN as [REDACTED] using
 action=redact."
```

Two things make the difference, and both are needed: say **how** to mask, and
say **`use action=redact, do NOT block`** explicitly. With that, a
`card_details` tool returns `**** **** **** 1111  cvv=[REDACTED]` on every call:
the agent can confirm the card without ever seeing the number.

Reserve a bare prohibition for data that should be withheld **entirely** (a
full KYC dossier, a raw secret) where blocking is the intended outcome.

> The MCP gateway reads this guardrail's ceiling from the route's bound **policy
> profile**, not from `/v1/tenant/me/policies`. If a `redact` rule still blocks,
> confirm the route is bound to a profile whose `output_guardrails`
> `tool_output_sanitization.action` is `redact`. The ceiling caps the verdict,
> and a `warn` ceiling can never redact. See the MCP gateway profile docs.

## Tips

- Start in **monitor** mode (see [Policy Lifecycle](/policy-lifecycle/)) to watch
  what *would* block before enforcing.
- Keep `output_rules` specific: list the fields a role **may** see, then block
  the rest. Vague rules let the model over- or under-redact.
- To mask rather than block, phrase the rule as a transform with an explicit
  `action=redact` (see above).
- `severity: "critical"` on a sanitization rule always escalates to **block**.
