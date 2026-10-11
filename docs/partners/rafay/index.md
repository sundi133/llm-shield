---
title: Rafay Integration
nav_order: 21
has_children: true
permalink: /partners/rafay/
description: "Enable Votal Shield multi-tenant AI guardrails on Rafay: overview, integration guide, admin and tenant provisioning, and a customer guide."
---

# Votal Shield x Rafay — partner handoff

In this section:
- [Integration guide](/partners/rafay/integration/) — engineering: auth, runtime calls, telemetry, in-cluster/OpenShift
- [Admin & tenant creation](/partners/rafay/admin/) — provision a Shield tenant + API key per customer
- [For customers](/partners/rafay/customers/) — what a Rafay customer turns on and configures
{: .mb-4 }

**Goal:** let a Rafay customer turn on AI guardrails for their workloads, with
each customer's policy isolated to that customer.

## What Votal Shield does

Inspects AI prompts and model outputs inline and returns an **allow / block /
redact** verdict — PII and secrets, prompt injection, unsafe content, and
agent/tool misuse — governed by per-tenant policy. One API call before the model,
one after.

## How the integration works (the model)

- **One Rafay customer = one Shield tenant**, identified by its own API key.
- Rafay **provisions a tenant + key** per customer when they enable guardrails.
- In Rafay's serving path: call Shield **PreCall** on the user's input, **PostCall**
  on the model's output, passing that customer's key (`X-API-Key`).
- Shield resolves the tenant from the key and applies **that customer's policy** —
  no cross-tenant leakage, no model keys shared with Shield.

```
customer app → Rafay serving → [PreCall /guardrails/input] → model → [PostCall /guardrails/output] → user
                                      │ block → stop                      │ block/redact → sanitize
                                      └──────────── X-API-Key: <customer tenant key> ───────────┘
```

Deploys two ways, same API: **hosted** (`api.guardrails.votal.ai`) or
**in-cluster** (Shield container in the customer's cluster for data residency —
Kubernetes/Helm reference in the integration guide, Appendix A).

## What's in this handoff

| Artifact | Purpose |
|---|---|
| [OpenAPI 3.1 spec](/assets/openapi-partner.json) | The curated partner API (guard, policy, telemetry, agentic surfaces; no admin internals). Import for codegen. |
| [Integration guide](/partners/rafay/integration/) | Full engineering detail: auth, onboarding, runtime calls with schemas, telemetry, failure modes, in-cluster/OpenShift. |
| [Admin & tenant creation](/partners/rafay/admin/) | How Rafay provisions a tenant + key per customer. |
| [For customers](/partners/rafay/customers/) | What a Rafay customer turns on and configures. |
| Sandbox tenant + key *(Votal provides)* | Integrate and validate before go-live. |

## Get started (Rafay engineering, ~a day to first green test)

1. Import `openapi-partner.json`; generate a client.
2. On "enable guardrails," provision the customer's tenant + key; store the key.
3. Wire **PreCall** before the model and **PostCall** after; honor `action` and
   `sanitized_output`.
4. Validate against the sandbox: benign prompt passes, policy-violating prompt
   returns `action=block`, decision appears in telemetry.

## Who provides what

- **Votal provides:** admin/provisioning key, a sandbox tenant + key, base URL(s),
  the OpenAPI + integration guide, and (if in-cluster) the Helm chart + model
  sizing.
- **Rafay builds:** the per-customer onboarding hook, the PreCall/PostCall calls in
  the serving path, and either an embedded Shield policy portal or policy screens
  on the tenant API.

## One deployment setting that matters

The Rafay-facing Shield must run with **`SHIELD_GUARD_REQUIRE_KEY=enforce`** so a
missing/invalid customer key is refused rather than screened without policy. Details
in the integration guide.

---
*Next step: Votal issues the sandbox tenant + admin key and confirms hosted vs
in-cluster; Rafay runs the 4-step get-started against the sandbox.*
