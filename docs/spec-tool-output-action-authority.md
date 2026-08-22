---
title: "Spec: make the configured action authoritative for tool output"
layout: default
nav_order: 55
permalink: /spec-tool-output-action-authority/
description: "tool_output_sanitization takes its action from the LLM's verdict, not from configuration. A tenant configured for warn gets blocks. The YAML also ships redaction patterns nothing reads."
---

# Spec: make the configured action authoritative for tool output

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

**Configuration does not restrain this guardrail.** `ToolOutputSanitizationGuardrail.check`
takes its action from the model's own verdict:

```python
action = result.get("action", "allow")     # the model decides
if action == "block":  return ... action="block"            # config ignored
elif action == "mask": return ... action="mask"             # config ignored
elif action == "redact": return ... action=self.configured_action   # only here
```

`self.configured_action` is consulted in **exactly one branch**, when the model
happens to answer `"redact"`. If it answers `"block"`, the call is blocked
regardless of what the tenant configured.

`config/default.yaml:309` declares `action: warn`. Production blocks. Both are
"correct" — the config is simply not consulted on that path. An operator reading
that file to understand behaviour is misled, which is exactly how this was
found: a tool call was blocked and the configured action said `warn`.

**Second defect: `redaction_patterns` is dead configuration.** The YAML ships
patterns for SSNs and API keys under `settings.redaction_patterns`. The only
reference anywhere in the codebase is a schema description string in
`core/policy_tools.py:221`. **Nothing reads them.** They look like a platform
redaction floor and redact nothing, which is worse than declaring no floor at
all: a reader concludes SSNs are masked by default when they are not.

**Outcome.** The configured action becomes a ceiling the model cannot exceed, so
a tenant configured for `warn` can never be blocked by this guardrail, and the
YAML stops describing behaviour that does not happen.

Observable success condition: with `action: warn`, an output the model judges
`block` yields `action == "warn"` and the original output, not
`[CONTENT BLOCKED DUE TO DATA POLICY]`. With `action: block`, behaviour is
byte-identical to today.

### Non-goals

- **Not** changing what the model judges, its prompt, or the 0.75 confidence
  floor. Only what is done with the verdict.
- **Not** moving expressive rules into Data Policies. They already live there
  (`role_policies[].output_rules`, `sanitization_rules`); this spec stops the
  YAML from contradicting them.
- **Not** removing the floor. `enabled` and `max_output_length` are real and stay.
- **Not** touching `payload_risk` (the input-side judge).

## 2. Plane & latency contract

- **Plane:** data plane. `guardrails/agentic/tool/tool_output_sanitization.py`
  and `config/default.yaml`.
- **Touches the GUARD PATH?** Yes — every MCP `tools/call` result and
  `/v1/shield/tool/output`.
- **Latency budget: zero.** One dict lookup and an integer comparison on a
  verdict already computed. No new I/O, no new model call.

## 3. Data model

Unchanged. No keys, no storage, no TTLs. This is pure decision logic.

## 4. API / interface

No HTTP surface change. Response shapes are unchanged; only the `action` value
can differ, and only downward.

**The cap.** Reuse the ladder already canonical in this repo
(`api/routes_classify.py:629`):

```python
_SEVERITY = {"pass": 0, "log": 1, "warn": 2, "redact": 3, "mask": 3, "block": 4}
```

`mask` sits level with `redact`: both return modified content without refusing
the call, so neither may be capped into the other.

After the model's verdict is resolved, clamp it:

```python
if _SEVERITY.get(action, 0) > _SEVERITY.get(self.configured_action, 4):
    action = self.configured_action
```

A verdict at or below the configured action passes through untouched. Only a
verdict **more severe** than configuration is reduced, and it is reduced to
exactly what the operator asked for.

**The default stays `warn`, and blocking becomes opt-in.**

```yaml
tool_output_sanitization:
  enabled: true
  action: warn           # unchanged text, now actually honoured
  settings:
    max_output_length: 50000
```

This is the load-bearing decision, and it is a deliberate **reduction in default
enforcement**, chosen by the owner. Today a default deployment blocks tool
output because the model's verdict wins. After this change it warns, and a
tenant that wants blocking sets it per tool in Tool Registry -> Data Policies.

The alternative was to set the default to `block`, preserving today's behaviour
and making the file merely honest. That was rejected: a control plane whose
strictest setting is the unconfigurable default gives a tenant no way to adopt
it gradually, and this repo's own pattern elsewhere is a declare-then-enforce
ladder (`off | warn | enforce`). This puts tool output sanitization on the same
ladder.

`redaction_patterns` is deleted. Nothing reads it.

**No policy for a tool means no judgment.** `_load_policies_text` now takes the
tool name, and `check` returns `pass` when nothing applies. Two defects fed each
other here:

- it called `_load_data_policies(tenant_id)` with **no tool name**, so every
  policy on the tenant judged every tool. `payload_risk` was already fixed for
  precisely this — its docstring records a rule about `customer_profile.get`
  judging `patient_lookup` and the model reporting restrictions that did not
  exist. The output side kept loading all of them; one tenant had 15, including
  `prescribe_medication` and `rotate_credential`, in scope when judging a bank
  statement.
- when nothing was configured it handed the model *"No specific data policies
  configured. Apply reasonable security defaults"* — an instruction to invent a
  rule. A tool whose policy was **empty** was blocked by a policy that did not
  exist.

Enforcement is now driven by configured policy, not improvisation. A load
*failure* is distinguished from an empty policy: the former returns a
non-empty sentinel so the judge still runs, because a storage blip must not
silently disable the guardrail.

## 5. Security & backward compatibility

**Yes, this weakens the default, deliberately.** Two reductions, both chosen:

1. A default deployment warns where it used to block, because `warn` is now
   honoured.
2. A tool with no data policy is not judged at all, where it used to be judged
   against every other tool's policy plus an instruction to improvise.

Neither is a bug being introduced; both are enforcement that was never
configured and never auditable. A block produced by a policy that does not
exist is not security, it is noise that trains operators to route around the
control -- and it is unexplainable to the customer whose call was refused.

What remains unconditional: `enabled`, `max_output_length`, and every guard
ahead of this one (RBAC, allowlist, payload judging). What becomes opt-in is
model-discretionary blocking of tool results.

**Migration note, stated plainly:** deployments relying on the previous
behaviour must set `action: block` for the tools they care about, in
Tool Registry -> Data Policies. Anyone upgrading should be told that tool output
blocking is now opt-in, because a silent drop from block to warn is exactly the
kind of change that gets discovered during an incident.

**Direction of the cap matters.** The clamp only ever reduces severity toward
the configured value; it can never raise it. A misconfigured `_SEVERITY` lookup
falls back to `0` for an unknown verdict and `4` for an unknown configured
action, so an unrecognised value fails **closed** (no capping) rather than
silently permitting.

**Escape hatch:** `SHIELD_TOOL_OUTPUT_ACTION_CAP=off` restores
model-authoritative behaviour.

**Migration note.** `config/default.yaml` now declares `block`, matching what
the guardrail already did. Deployments that intentionally want warn-only tool
output sanitization should set `action: warn` and will, for the first time,
actually get it.

## 6. Packaging & deploy

- **New pip deps:** none.
- **`Dockerfile.admin`:** no change; neither file is newly imported by
  `admin_app.py`.
- **Images to rebuild:** data plane.
- **Env flags:** `SHIELD_TOOL_OUTPUT_ACTION_CAP` (unset = cap enabled).
- **Rollout:** ship, confirm a known-blocking payload still blocks under the
  default, then confirm it only warns when the action is set to `warn`.

## 7. Failure modes & edge cases

| condition | behaviour |
|---|---|
| configured `block` (the default) | nothing capped; identical to today |
| configured `warn`, model says `block` | capped to `warn`, original output returned |
| configured `warn`, model says `allow` | passes; caps never raise severity |
| configured `redact`, model says `block` | capped to `redact` |
| configured `redact`, model says `mask` | unchanged (same severity level) |
| unknown configured action | treated as severity 4, so nothing is capped — fails closed |
| unknown model verdict | severity 0, never exceeds the cap, existing handling applies |
| confidence < 0.75 | already forced to `allow` upstream; unchanged |
| `SHIELD_TOOL_OUTPUT_ACTION_CAP=off` | model authoritative, exactly as today |

**Fail-open vs fail-closed:** the cap fails **closed** — any value it cannot
interpret results in no reduction of severity.

## 8. Test plan (Definition of Done)

New file `tests/test_tool_output_action_authority.py`:

1. **Configured `warn` caps a model `block`** — action is `warn`, and the output
   is NOT replaced with the blocked placeholder. The headline behaviour.
2. **Configured `block` changes nothing** — a model `block` still blocks, with
   the same message and placeholder. Guards the default against regression.
3. **The cap never raises severity** — configured `block`, model `allow` stays
   `allow`.
4. **Configured `redact` caps a model `block` to `redact`.**
5. **`mask` and `redact` are the same level** — neither is capped into the other.
6. **An unknown configured action does not cap** (fails closed).
7. **`SHIELD_TOOL_OUTPUT_ACTION_CAP=off` restores model authority.**
8. **`redaction_patterns` is gone from `config/default.yaml`** — a literal
   assertion, so it cannot be reintroduced as decorative config.
9. **The YAML default is `block`** — pins the decision in §4 so a future edit to
   `warn` cannot silently disable blocking fleet-wide.

Regression suites: `tests/test_mcp_dlp_and_scanning.py`,
`tests/test_mcp_enforcement.py`, `tests/test_tool_output*.py`,
`tests/test_mcp_proxy.py`, `tests/test_admin_dockerfile_imports.py`.

**Definition of done:** full suite green in a clean venv; CI `pytest` gate
passes; a live check confirming the known-blocking customer profile still blocks
under the default.
