---
title: Policy Lifecycle (Monitor → Enforce)
layout: default
nav_order: 6
permalink: /policy-lifecycle/
description: Start from an industry template, run it in monitor mode to see what would block, then flip to enforce — the safe way to ship a guardrail policy.
---

# Policy Lifecycle — Templates, Monitor, Enforce
{: .no_toc }

The safe path to a live guardrail policy, for security and platform operators.
You never have to author a policy from a blank page, and you never have to flip a
brand-new policy straight to "block" in production and hope.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## The three moves

1. **Start from a template** — pick an industry preset instead of an empty config.
2. **Run in monitor mode** — the policy evaluates every request and records what it
   *would* block, but does not block anything. Review it against real traffic.
3. **Flip to enforce** — once the would-block list looks right, the same policy starts
   blocking. One field changes; nothing else moves.

All endpoints below are admin routes — send your admin key as `X-Admin-Key`.

---

## Step 1 — Pick a template

```bash
curl -s http://SHIELD/v1/admin/policy-templates -H "X-Admin-Key: $ADMIN_KEY"
```

```json
{ "templates": [
  { "id": "general",            "name": "General Baseline",                 "recommended_mode": "monitor", ... },
  { "id": "healthcare",         "name": "Healthcare (HIPAA)",               "recommended_mode": "monitor", ... },
  { "id": "financial_services", "name": "Financial Services (PCI DSS / SOX)","recommended_mode": "monitor", ... }
]}
```

Inspect the full guardrail set before applying:

```bash
curl -s http://SHIELD/v1/admin/policy-templates/healthcare -H "X-Admin-Key: $ADMIN_KEY"
```

---

## Step 2 — Apply it (lands in monitor mode)

```bash
curl -s -X POST http://SHIELD/v1/admin/tenants/acme/apply-template \
  -H "X-Admin-Key: $ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"template_id": "healthcare"}'
```

```json
{
  "status": "applied",
  "tenant_id": "acme",
  "template_id": "healthcare",
  "policy_mode": "monitor",
  "input_guardrail_count": 5,
  "output_guardrail_count": 4,
  "note": "Policy is in MONITOR mode — it records what would block but does not enforce. Review, then PUT policy-mode 'enforce'."
}
```

The template replaces the tenant's input/output guardrails and sets `policy_mode: monitor`
(its recommended mode). Traffic is **not** affected yet.

> Want to apply but go straight to enforcing? Pass `{"template_id": "...", "mode": "enforce"}`.

---

## Step 3 — Watch what *would* block

In monitor mode, every decision still runs. A request that the policy *would* block
comes back allowed, but tagged so you (and your SIEM) can see it:

**Tool / agent check** (`POST /v1/shield/tool/check`) and **input check**
(`POST /guardrails/input`) both return:

```json
{
  "allowed": true,
  "action": "monitor",
  "would_block": ["toxicity", "pii_detection"],
  "guardrail_results": [
    { "guardrail": "toxicity", "passed": false, "action": "block", "enforced": false, ... }
  ]
}
```

- `action: "monitor"` — a would-be block was suppressed (vs `"block"` when enforcing).
- `would_block` — exactly which guardrails would have fired. This is your review list.
- `enforced: false` on a result — that finding was observed, not acted on.

These flow into the audit log and SIEM events too, so you can review in the telemetry
dashboard or your own tooling: *"what would this policy have blocked over the last day?"*

Check the current mode any time:

```bash
curl -s http://SHIELD/v1/admin/tenants/acme/policy-mode -H "X-Admin-Key: $ADMIN_KEY"
# {"tenant_id": "acme", "policy_mode": "monitor"}
```

---

## Step 4 — Flip to enforce

When the would-block list looks right — no surprising false positives — enforce it:

```bash
curl -s -X PUT http://SHIELD/v1/admin/tenants/acme/policy-mode \
  -H "X-Admin-Key: $ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"mode": "enforce"}'
```

Now the same policy blocks: `allowed: false`, `action: "block"`. Nothing about the
guardrails changed — only whether their findings are enforced. You can flip back to
`monitor` at any time with the same endpoint.

Every apply and every mode flip is written to the admin audit log
(`apply_policy_template`, `set_policy_mode`) with the actor and timestamp.

---

## Mental model

| | Monitor (dry-run) | Enforce |
|---|---|---|
| Guardrails evaluate | yes | yes |
| Findings recorded / audited | yes | yes |
| Request actually blocked | **no** | yes (on `block`) |
| Top-level `action` on a would-be block | `monitor` | `block` |
| `would_block` list populated | yes | yes |

**Safety guarantee.** Enforce mode is the original behavior, untouched — the monitor
logic only ever *relaxes* a decision, and only for a tenant that explicitly opted into
`monitor`. A tenant with no `policy_mode` set enforces, exactly as before.

---

## Notes

- **Propagation.** Tenant config is cached per process (short TTL), so a mode flip can
  take a few seconds to take effect on every worker.
- **`warn` / `log` are unchanged.** Monitor mode only suppresses *blocks*. Guardrails
  set to `warn` or `log` behave identically in both modes.
- **Per-guardrail monitor** (running only *some* guardrails in dry-run while others
  enforce) is a natural extension of `resolve_mode()` in `core/policy_mode.py` — not
  wired yet.

## Tuning a custom policy that missed

A custom policy that returns `"violations": 0` is not always a clean scan. The
`custom_policy_input` / `custom_policy_output` response carries two extra fields
whenever they apply:

| Field | Meaning | What to do |
|---|---|---|
| `suppressed_by_threshold` | The model DID flag the content, but below the policy's `confidence_threshold` (default `0.8`), so it was not acted on. Each entry has the policy, the confidence, and the threshold it missed. | Lower that policy's threshold, or sharpen its `prompt` so the model commits. |
| `errors` | The policy could not be evaluated at all (LLM error, unparseable verdict). `policies_evaluated` drops below `policies_checked`. | Investigate the upstream. These are NOT passes. |

Long, multi-topic messages are the common cause of a low-confidence miss: the
evaluator is told to scan every sentence rather than summarise the message, but
a violating clause buried in a long unrelated request still scores lower than
the same clause on its own. Watch `suppressed_by_threshold` before assuming a
policy simply does not fire.

**`SHIELD_CUSTOM_POLICY_FAIL_OPEN`** (default `1`) controls what happens to a
policy that failed to evaluate. The default lets it pass, which is the historic
behavior. Set it to `0` when your custom policies are the control rather than
defense in depth, and an unevaluated policy will block instead.

## Where to next

- [Guardrails Catalog]({{ "/guardrails/" | relative_url }}) — what each guardrail in a template does
- [Agentic Integration Guide]({{ "/agentic-integration-guide/" | relative_url }}) — tool RBAC and data policies
- [Developer Quickstart]({{ "/dev-quickstart/" | relative_url }}) — protect an agent in three steps
