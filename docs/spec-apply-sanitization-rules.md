---
title: "Spec: make redaction of tool output actually redact"
layout: default
nav_order: 57
permalink: /spec-apply-sanitization-rules/
description: "The redact and mask branches return the original text unmodified, and the model is never asked to produce a redacted version. Redaction has never been implemented by any mechanism."
---

# Spec: make redaction of tool output actually redact

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

**Redaction of tool output has never been implemented.** Not partially, not by a
different path. There is no mechanism that produces masked text.

Two independent halves of the same hole:

**The model is never asked to redact.** The CSV contract is
`has_sensitive, action, confidence, findings`
(`guardrails/agentic/tool/tool_output_sanitization.py:18`). There is no field
for the sanitized content. The model returns a verdict and a description of what
it found, and nothing else.

**The redact branch returns the original.** Lines 191 and 208, the `redact` and
`mask` branches:

```python
elif action == "redact":
    return GuardrailResult(
        passed=False, action=..., 
        details={"sanitized_output": tool_output, ...}   # unmodified input
    )
```

`sanitized_output` is the untouched `tool_output`. A caller reading that field,
which is exactly what `MCPProxy.call_tool` does, receives the raw payload. Only
`block` substitutes anything, and it substitutes a placeholder rather than a
redaction.

Reproduced end to end on 2026-08-22. A tenant configured an output rule
("Never return a national ID, passport number, or SSN") plus rules describing an
Emirates ID and a passport, then called `customer_profile_get` through the MCP
gateway. The model received:

```
Aisha Khan  aisha@example.com  P1234567  784-1990-1234567-1  gold
```

Unredacted, in full.

**A third defect feeds it:** `_format_data_policies`
(`payload_risk.py:282`) renders each sanitization rule as
`"- Sanitize: {description}"`, dropping everything else. So even the intent
reaching the judge is thin.

**Why this is the serious kind of defect.** The portal offers redaction, stores
it, displays it, and reports `action: redact` at runtime while returning the
original bytes. An operator has every reason to believe the control is on. Same
class as the `redaction_patterns` deleted from `config/default.yaml` this week
and the audit sink that was never wired.

**Outcome.** When the policy says redact, the caller receives redacted text, and
`action: redact` means the content changed.

Observable success condition: with an output rule naming national IDs and
passports, the payload above returns to the caller as
`Aisha Khan aisha@example.com [REDACTED] [REDACTED] gold`, with the non-sensitive
fields intact.

### Approach: LLM, not regex

The redaction is produced by the model, consistent with every other guardrail in
this repo. Deliberately **not** regex substitution:

- The rules tenants write are prose (`output_rules`, `sanitization_intent`), and
  the whole point of the reasoning-based path is that they need not enumerate
  patterns.
- Regex on the guard path means tenant-authored patterns with no timeout in
  Python's `re`, which is a hot-path hang waiting to happen.
- A second, differently-behaving mechanism alongside the judge is exactly the
  split-brain that made this defect take hours to trace.

`sanitization_rules[].regex` stays in the schema as an unused hint. §5 covers
what to do about that honestly.

### Non-goals

- **Not** redacting tool *arguments*. Arguments are structured values the tool
  must interpret, and rewriting `account_id` could execute a different operation
  than the caller asked for. Detection on input stays as it is.
- **Not** changing the action cap, the global policy layer, or the
  no-policy-no-judgment rule.
- **Not** adding a regex engine.

## 2. Plane & latency contract

- **Plane:** data plane.
  `guardrails/agentic/tool/tool_output_sanitization.py`, and the policy
  formatter in `guardrails/agentic/tool/payload_risk.py`.
- **Touches the GUARD PATH?** Yes. Every MCP `tools/call` result and
  `/v1/shield/tool/output`.
- **Latency budget: no new LLM call.** The judge already runs on this path; it
  gains one output field. The cost is extra completion tokens on the redact
  path only, bounded by `max_tokens`, which must rise from 60 (§4) since the
  model now returns content rather than a verdict alone.

Worth stating plainly: this makes the redact path more expensive than today,
because today it returns nothing and costs nothing. `allow` and `block` are
unchanged.

## 3. Data model

Unchanged in storage. `DataSanitizationRule` keeps its fields.

One rendering change: `_format_data_policies` includes the rule's
`replacement` alongside its `description`, so the model knows what to substitute
rather than inventing a placeholder per call. Without that the same rule yields
`[REDACTED]`, `***`, and `[ID REMOVED]` across three identical requests, and a
caller cannot parse the result.

## 4. Interface

No HTTP surface change. Response shapes are unchanged; `sanitized_output`
finally carries what its name says.

**The CSV contract gains a field:**

```python
_CSV_FIELDS = ["has_sensitive", "action", "confidence", "findings", "sanitized"]
```

`sanitized` is the redacted rendering of the tool output, and it is required
only when `action` is `redact` or `mask`. The system prompt instructs the model
to reproduce the output verbatim except for the values the policy names,
replacing each with the rule's `replacement` when one is given and `[REDACTED]`
otherwise.

`max_tokens` rises from 60 to accommodate returned content. It is bounded by the
same `max_output_length` truncation already applied to the input.

**The branches use it:**

```python
elif action in ("redact", "mask"):
    return GuardrailResult(..., details={"sanitized_output": sanitized, ...})
```

### The failure that matters

If the model returns `action: redact` with an empty, missing, or malformed
`sanitized`, **the result is escalated to `block`**, not passed through.

This is the one place in the spec that must not be gentle. The current bug is
precisely "we said redact and returned the original", and a lenient fallback
would reintroduce it under a new name. If redaction was required and could not
be produced, withholding is the only safe answer. `details.redaction_failed`
records why, and the escalation is subject to the action cap from
`docs/spec-tool-output-action-authority.md` so configuration still restrains it.

A CSV field containing commas is the obvious parse hazard; `sanitized` is
therefore the **last** field, so everything after the fourth comma is the
content.

## 5. Security & backward compatibility

- **This is a strengthening.** Today `redact` leaks in full. After this it
  redacts or it blocks. There is no configuration under which this returns more
  data than it does now.
- **Behaviour changes only where a policy already asks for redaction.** Tenants
  with no `redact`/`mask` policies see nothing new.
- **Escape hatch:** `SHIELD_LLM_REDACTION=off` restores today's behaviour
  (`redact` returns the original). Present for rollback only, and it should be
  documented as unsafe rather than as a supported mode, because the behaviour it
  restores is the bug.

**The residual weakness, stated plainly — and how far it goes.** Redaction is a
model's output, so its exactness is not guaranteed the way a regex substitution
would be: a sufficiently adversarial payload could induce an imperfect mask.

But the *whether* — redact vs block — turned out to be controllable by policy
wording, not luck. A rule phrased as a pure prohibition ("never return a card
number") defaults to block and flips to redact only sometimes; a rule phrased as
a transform with an explicit action ("use action=redact, do NOT block; mask the
card to its last 4 as `**** **** **** NNNN`") redacts on every call. Verified
deterministic (4/4 and 5/5) live against a tenant. So:

> The block-vs-redact CHOICE is deterministic when the rule is written as a
> transform-with-explicit-action rather than a prohibition. The exact masking of
> a given value is high recall, not bit-exact. A tenant that wants reliable
> masking can have it; it should still not be described as a bit-exact
> deterministic control the way a regex would be.

This wording pattern is documented for operators in
`docs/tool-data-policies.md` ("Redact reliably: write a transform, not a
prohibition").

`sanitization_rules[].regex` remains in the schema and remains unused. Leaving a
field that reads as a deterministic pattern while nothing executes it is the
exact defect this spec exists to fix, one level down. Either mark it deprecated
in the API and portal, or remove it. Recommend deprecating in this PR and
removing in a follow-up, so no tenant silently loses stored data.

## 6. Failure modes & edge cases

| condition | behaviour |
|---|---|
| `action: allow` | Unchanged. Original returned, no `sanitized` expected. |
| `action: block` | Unchanged. Placeholder returned. |
| `action: redact`, valid `sanitized` | Redacted text returned. **The fix.** |
| `action: redact`, empty or missing `sanitized` | **Escalate to block**, capped. `redaction_failed` recorded. |
| `sanitized` identical to the input | Treated as a failure to redact: escalate. The model claimed to redact and did not. |
| `sanitized` longer than the input by a wide margin | Escalate. The model has rewritten rather than redacted, and returning invented content as tool output is worse than withholding. |
| LLM call fails | Unchanged: existing handler passes with the original and an error message. Not made stricter here, since that is a different decision from this one. |
| Confidence below 0.75 | Already forced to `allow` upstream; unchanged. |
| Output truncated first | Redaction operates on the truncated string, as today. |
| `SHIELD_LLM_REDACTION=off` | `redact` returns the original, as today. |

**Fail open vs fail closed:** the redaction path fails **closed**. Every way of
failing to produce a redaction results in withholding, never in passing the
original through. That is the inversion this spec is for.

## 7. Packaging & deploy

- **New pip deps:** none.
- **`Dockerfile.admin`:** no change.
- **Images:** data plane.
- **Env flags:** `SHIELD_LLM_REDACTION` (unset = redact properly).
- **Rollout:** ship, run the §1 reproduction and confirm the passport and
  national ID come back masked with the other fields intact, then confirm a
  deliberately broken model response escalates to block rather than leaking.

## 8. Test plan (Definition of Done)

New file `tests/test_llm_redaction.py`:

1. **The §1 reproduction is redacted.** Exact payload, exact expected shape:
   sensitive values masked, `Aisha Khan` and `gold` intact. The headline.
2. **`sanitized_output` is no longer the input.** The direct regression guard on
   lines 191 and 208.
3. **Empty `sanitized` under `redact` escalates to block.** The lenient-fallback
   guard, and the most important test in the file.
4. **Missing `sanitized` escalates to block.**
5. **`sanitized` equal to the input escalates to block** (claimed redaction, did
   nothing).
6. **The escalation is still capped** by the configured action.
7. **`allow` and `block` are byte-identical to today.**
8. **A `sanitized` value containing commas survives parsing**, since it is the
   last CSV field.
9. **The policy text handed to the model includes the replacement**, not only
   the description, asserted on the captured prompt.
10. **`max_tokens` is large enough** to return a realistic payload, asserted on
    the captured call rather than the constant.
11. **`SHIELD_LLM_REDACTION=off` restores today's behaviour.**
12. **`redaction_failed` is recorded** on every escalation path.

Regression suites: `tests/test_mask_redact.py`,
`tests/test_tool_output_action_authority.py`, `tests/test_global_data_policy.py`,
`tests/test_mcp_dlp_and_scanning.py`, `tests/test_data_policy_prefill_order.py`.

**Definition of done:** full suite green in a clean venv; CI `pytest` gate
passes; the §1 payload verified redacted against the live deployment **through
the MCP gateway**, not only through `/v1/shield/tool/output`, since the gateway
is the path that reads `sanitized_output`.
