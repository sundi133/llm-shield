---
title: How customers configure guardrails
parent: Rafay Integration
nav_order: 4
permalink: /partners/rafay/configure/
description: "The three ways a Rafay customer's guardrails get configured: a default Rafay applies, Shield's portal with single sign-on, or settings screens in Rafay's own console."
---

# How customers configure guardrails

Each Rafay customer has its own Shield tenant, and its guardrail settings live in
that tenant. They can be set three ways. Most partners use all three: a sensible
default for everyone, the portal for customers who want control, and screens in
their own console later.

| | Who does it | Effort for Rafay | What the customer sees |
|---|---|---|---|
| [1. A default Rafay applies](#1-a-default-rafay-applies) | Rafay, with its admin credential | None after setup | Nothing to do: they are protected from the first request |
| [2. Shield's portal](#2-shields-portal-with-single-sign-on) | The customer's own admins | Connect single sign-on once per customer | Shield's portal, signed in with their company login |
| [3. Rafay's console](#3-settings-screens-in-rafays-console) | The customer, in Rafay's UI | Build the screens | Rafay's UI only |

## 1. A default Rafay applies

When Rafay creates the customer's tenant it applies a starting policy with its
admin credential (see the [onboarding runbook](/partners/rafay/onboarding/#31-create-the-tenant-with-its-starting-policy)).
Shield ships ready-made templates:

| Template | For | Turns on |
|---|---|---|
| `general` | Any assistant | Prompt attack and toxicity blocking; personal data watched |
| `healthcare` | Clinical and patient-facing agents | Health data protections on top of the baseline |
| `financial_services` | Finance (PCI DSS, SOX) | Card and account data protections on top of the baseline |

```bash
curl -s https://api.guardrails.votal.ai/v1/admin/policy-templates -H "X-Admin-Key: $CRED"
```

Rafay can also set or change any customer's guardrails directly with the same
credential, for example when a customer asks Rafay support to turn something on:

```bash
curl -X PUT "https://api.guardrails.votal.ai/v1/admin/tenants/rafay-cust-acme" \
  -H "X-Admin-Key: $CRED" -H "Content-Type: application/json" \
  -d '{"input_guardrails":{
         "adversarial_detection":{"enabled":true,"action":"block"},
         "pii_detection":{"enabled":true,"action":"block","settings":{"score_threshold":0.7}}},
       "output_guardrails":{
         "pii_leakage":{"enabled":true,"action":"block"}}}'
```

Each guardrail takes `enabled`, `action` (`block`, `warn`, `log` or `pass`) and
optional `settings`. The call merges: only the guardrails you name change, and
the rest of the customer's policy stays as it is. Changes apply to the
customer's next request, with no redeploy.

## 2. Shield's portal, with single sign-on

The portal is at `https://shield.votal.ai/tenant`. A customer's admins sign in
and see only their own tenant:

- **Guardrails and policies:** turn each guardrail on or off and choose block,
  redact, warn or log.
- **Custom policies:** rules written in plain language, for example "block
  messages that contain customer account numbers".
- **Monitor or enforce:** watch first, then enforce.
- **Agents and tools:** what each AI agent may do, approvals for risky actions.
- **Activity and audit:** every decision, with the rule that fired.

**How customers sign in.** Rafay connects an identity provider to the tenant
once (runbook step 3.3), then puts this link behind a "Guardrails" button in the
Rafay console:

```
https://shield.votal.ai/v1/tenant/auth/login?tenant=rafay-cust-acme&next=/tenant
```

The link goes straight to the company login. People in the tenant's
`admin_groups` can change settings; other people from that directory who sign in
can only view. A customer can also sign in with a tenant key, but company login
gives named users in the audit trail, and Votal can make a tenant login-only
(`require_sso`) so keys stop working in the portal while still working for API
calls.

Do not send customers to `https://shield.votal.ai/admin`. That is Votal's
operator console.

**Trade-off:** the portal is Votal-branded, so customers see Shield as a
separate product.

## 3. Settings screens in Rafay's console

For a fully Rafay-branded experience, Rafay builds the screens and calls the
customer's tenant API on `https://api.guardrails.votal.ai` with that customer's
**settings key** (the `admin`-scoped key from runbook step 3.2, kept in Rafay's
backend, never in the browser):

| Screen | Call |
|---|---|
| Show current guardrails | `GET /v1/tenant/me/policies` |
| Save guardrails | `PUT /v1/tenant/me/policies` |
| List custom policies | `GET /v1/tenant/me/custom-policies/` |
| Add a custom policy | `POST /v1/tenant/me/custom-policies/` with `name`, `description`, `prompt` (20 to 2000 characters), `action` (`pass`, `warn`, `redact`, `block`), `stage` (`input`, `output`), `confidence_threshold` (0.5 to 1.0), `priority` (1 to 1000) |
| Turn a custom policy on or off | `POST /v1/tenant/me/custom-policies/{id}/enable` or `/disable` |
| Monitor or enforce | `GET` / `PUT /v1/tenant/me/policy-mode` with `{"mode":"enforce"}`, or `{"mode":"monitor","reason":"..."}` (a reason is required to stop blocking, and is audited). Votal can make this Rafay-only with `SHIELD_TENANT_POLICY_MODE_SELF_SERVICE=off`; the call then answers that the mode is managed by the administrator |
| What was blocked | `GET /v1/tenant/me/telemetry` (filters: `status`, `since`, `until`, `q`, `limit`) |
| Usage and audit | `GET /v1/tenant/me/usage`, `GET /v1/tenant/me/audit` |

Never use the serving key (`runtime` scope) for these. On deployments that
enforce key scopes it is refused, and keeping it read-only is what stops a
leaked serving key from turning a customer's guardrails off.

## Send decisions to the customer's SIEM

Security teams usually want every guardrail decision in their own SIEM next to
their other alerts. Each customer can stream its tenant's decisions to
**Splunk** (HTTP Event Collector), **Microsoft Sentinel**, **Elastic**,
**Wazuh**, or any HTTPS endpoint. Set it up in the portal, or with the
customer's settings key on `https://shield.votal.ai` (these settings are served
by the portal host only):

```bash
curl -X POST https://shield.votal.ai/v1/tenant/me/siem \
  -H "X-API-Key: $SETTINGS_KEY" -H "Content-Type: application/json" \
  -d '{"type":"splunk","url":"https://splunk.example.com:8088/services/collector",
       "token":"<HEC token>","statuses":["block","warn"]}'
```

| Field | Meaning |
|---|---|
| `type` | `splunk`, `sentinel`, `elastic`, `wazuh` or `generic` |
| `url`, `token` | The collector URL and its token (Splunk HEC token, Elastic API key, or a bearer token) |
| `workspace_id`, `shared_key`, `log_type` | Sentinel only: the Log Analytics workspace and the table name (default `LLMShield`) |
| `statuses` | Send only these decisions, for example `["block","warn"]`; empty sends everything |
| `events` | Send only these event types; empty sends all |

`POST /v1/tenant/me/siem/test` sends a test event, `GET /v1/tenant/me/siem`
lists destinations, and `DELETE /v1/tenant/me/siem/{siem_id}` removes one. Each
customer's destinations receive only that customer's events.

## Import the customer's Sigma rules

Security teams that already write detections as **Sigma** rules can import them
as Shield policies: `POST /v1/tenant/me/custom-policies/import/sigma` on
`https://api.guardrails.votal.ai` with the customer's settings key and
`{"sigma": "<YAML, one or more rules>", "dry_run": true}` to check them first.
Imported rules screen prompts and model responses deterministically (no model
call); `validate-sigma` checks a rule and `export/sigma` exports policies back.

## Monitor first, then enforce

Whichever way settings are made, roll out the same way:

1. **Monitor:** every decision is recorded, nothing is blocked.
2. **Review** telemetry for a few days: what would have been blocked, and was
   it right.
3. **Enforce:** violations are blocked in real time.

Switch with the portal, `PUT /v1/tenant/me/policy-mode` (settings key), or
`PUT /v1/admin/tenants/{tenant_id}/policy-mode` (Rafay's admin credential).
