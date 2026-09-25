---
title: Sigma Policies and ASIM Telemetry
layout: default
nav_order: 27
permalink: /sigma-policies/
description: Write custom input and output policies as Sigma rules, import and export Sigma rules, and read Shield telemetry in Microsoft ASIM format.
---

# Sigma policies and ASIM telemetry
{: .no_toc }

Custom input and output policies can be written as **Sigma rules** as well as in
natural language. Both formats are enforced the same way at runtime. You can
import existing Sigma rules as policies and export any policy as a Sigma rule.
Shield telemetry includes **Microsoft ASIM** fields alongside its existing fields.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## Two policy formats

| Format | How it is judged | Best for |
|---|---|---|
| `natural_language` (default) | The guardrail model reads the policy and the text | Intent and meaning, for example "no investment advice" |
| `sigma` | Deterministic rule matching, no model call | Exact patterns: identifiers, keys, phrases, roles, tools |

Both run inside the `custom_policy_input` and `custom_policy_output` guardrails.
Actions (`pass`, `warn`, `redact`, `block`), priorities, monitor and enforce mode,
and `SHIELD_CUSTOM_POLICY_FAIL_OPEN` apply to both formats. Existing policies
are unchanged and stay natural language.

A Sigma policy makes no model call, so it adds no model latency. A match is
certain, so the confidence threshold does not apply to it.

## Writing a Sigma policy

Create it like any custom policy, with `format: "sigma"` and the rule in
`sigma_rule` (YAML text or a JSON object):

```bash
curl -X POST "$SHIELD/v1/tenant/me/custom-policies/" \
  -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{
    "name": "No SSNs in prompts",
    "description": "Blocks prompts that contain a US social security number",
    "action": "block",
    "stage": "input",
    "format": "sigma",
    "sigma_rule": "title: SSN in prompt\nlogsource:\n  product: votal\n  service: shield\n  category: llm_input\ndetection:\n  ssn:\n    message|re: \"\\\\b\\\\d{3}-\\\\d{2}-\\\\d{4}\\\\b\"\n  condition: ssn\nlevel: high\n"
  }'
```

The portal API (`/v1/tenant/me/policies/custom`) accepts the same fields.

### In the tenant portal

Under **Custom Input Policies** or **Custom Output Policies**, choose
**+ Custom Policy** and set **Format** to **Sigma rule**. Paste one rule, or use
**Insert example**, then **Test Policy** to validate it before saving. The
confidence threshold is hidden for Sigma policies because a match is certain.
Policy cards show a **Sigma** badge and the rule text.

**Import Sigma** and **Export Sigma** sit next to each section heading. Import
takes a `.yml` file with one or more rules and adds them to that section.
Export downloads that section's policies as a Sigma file.

### Fields a rule can match

| Field | Value |
|---|---|
| `message` | The text being screened: the prompt on input, the model output on output |
| `stage` | `input` or `output` |
| `user_role` | Caller role |
| `session_id` | Session identifier |
| `agent_id` | Calling agent |
| `tool_name` | Tool being called (output stage) |
| `tool_input` | Tool arguments as JSON text (output stage) |

A keyword list (a detection identifier holding plain strings) searches `message`.

### Supported Sigma

* Field maps (all fields must match), lists of maps (any may match), keyword lists.
* Values compare case-insensitively with `*` and `?` wildcards. A list of values
  matches any of them. `null` means the field is absent.
* Modifiers: `contains`, `startswith`, `endswith`, `all`, `cased`, `exists`, and
  `re` with the `i`, `m` and `s` flags.
* Conditions: `and`, `or`, `not`, parentheses, `1 of x*`, `all of x*`,
  `1 of them`, `all of them`.

Correlation rules (`timeframe`, `| count()`) and other modifiers such as `base64`,
`windash` and `cidr` are rejected when the policy is saved, so a rule never
silently matches nothing. Each evaluation is bounded by
`SHIELD_SIGMA_EVAL_TIMEOUT_MS` (default 250). A rule that runs past it counts as
an evaluation error and follows `SHIELD_CUSTOM_POLICY_FAIL_OPEN`.

## Import Sigma rules

```bash
curl -X POST "$SHIELD/v1/tenant/me/custom-policies/import/sigma" \
  -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"sigma": "<one or more YAML documents separated by --->", "dry_run": true}'
```

* Each rule becomes one policy. One invalid rule does not stop the others; the
  response lists `created` and `errors`.
* **Stage** comes from the `stage` field in the request, otherwise from
  `logsource.category` (`llm_input` or `llm_output`).
* **Action** comes from the `action` field in the request, otherwise from the
  rule `level`: `informational` is `pass`, `low` and `medium` are `warn`, `high`
  and `critical` are `block`.
* Use `"dry_run": true` to see what would be created without saving.
* The 10 policies per stage limit applies.

## Export policies as Sigma

```bash
# All policies, as multi-document YAML in the "yaml" field
curl "$SHIELD/v1/tenant/me/custom-policies/export/sigma" -H "X-API-Key: $KEY"

# One policy
curl "$SHIELD/v1/tenant/me/custom-policies/<policy_id>/export/sigma" -H "X-API-Key: $KEY"
```

* A Sigma policy exports as its rule.
* A natural-language policy is translated: the guardrail model extracts keywords
  and patterns, and Shield builds and validates the rule. The result is an
  approximation of a policy that a model judges, so it is marked
  `status: experimental`. Review it before relying on it in another tool. Pass
  `translate=false` to skip natural-language policies instead.
* Translation needs the guardrail model to be reachable from the server you
  call. If it is not, those policies are listed in `errors` and every Sigma
  policy still exports.
* Every exported rule carries a `votal:` block with the stage, action and
  priority, and for natural-language policies the original prompt. Importing an
  exported rule back into Shield restores the policy exactly.

## Telemetry in ASIM format

Shield telemetry (Elasticsearch, Splunk HEC, OTLP logs and the local JSON log
file) includes **Microsoft ASIM** fields, for example `EventResult`,
`DvcAction`, `SrcIpAddr`, `ActorUsername` and `EventSeverity`. Microsoft
Sentinel ASIM content and Sigma rules can read Shield events without a custom
parser. Agent context that ASIM has no field for (agent id, tool, guardrail
results, risk score) is in `AdditionalFields`. The ASIM fields never carry
prompt or response text.

### Nothing to migrate

By default every record keeps all of its existing `event.*` and `votal.*`
fields, unchanged, and the ASIM fields are added next to them. Dashboards,
saved searches and alerts built on the existing fields keep working.

Choose the format with `VOTAL_TELEMETRY_FORMAT` or `telemetry.format` in the
configuration file:

| Value | Records contain |
|---|---|
| `both` (default) | Existing fields plus ASIM fields |
| `asim` | ASIM fields only. Smaller records, once nothing reads the old fields |
| `native` | Existing fields only, exactly as before ASIM |

Records in `both` are larger than before. If your Elasticsearch index uses a
strict mapping (`dynamic: strict`), add the ASIM fields to it or use `native`.
