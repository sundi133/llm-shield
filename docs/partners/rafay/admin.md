---
title: Admin API reference
parent: Rafay Integration
nav_order: 3
permalink: /partners/rafay/admin/
description: "Every call Rafay makes with its admin credential: create tenants, register and revoke keys, set guardrails, apply templates, switch monitor or enforce, and connect single sign-on."
---

# Admin API reference

Rafay uses **one admin credential** to create a Shield tenant for each customer
and to configure that customer's guardrails. This page lists every call it can
make. For the order to run them in, see the
[onboarding runbook](/partners/rafay/onboarding/).

All calls go to `https://api.guardrails.votal.ai` (or the in-cluster Shield URL)
with the credential in the `X-Admin-Key` header. These endpoints are not in the
partner OpenAPI file, because they act across tenants.

## The admin credential

Votal issues Rafay a **managed admin credential**: a secret starting `shadm_`.
It is not the deployment's root key (`SHIELD_ADMIN_KEY`), and it should never be.

| Property | Value for Rafay |
|---|---|
| Operations | `tenants:read`, `tenants:write` (tenants, keys, guardrails, templates, mode), `oidc:read`, `oidc:write` (single sign-on) |
| Tenants | `*` (Rafay creates tenants as customers sign up; see the note below) |
| Expiry | 90 days; Votal rotates it with `POST /v1/admin/credentials/{id}/rotate` |
| Audit | Every action made with it is recorded as Rafay's |

Store it in Rafay's secret manager. It is the one secret in this integration
that can create, change or remove customer tenants.

> **Limit to know about.** A credential's tenant list takes exact tenant ids or
> `*`. On the shared hosted service, `*` also covers tenants that are not
> Rafay's. Until credentials can be limited to a prefix such as `rafay-cust-*`,
> either run Rafay on a dedicated Shield deployment or review the admin audit for
> actions outside `rafay-cust-*`.

## Tenants

### Create a tenant

`POST /v1/admin/tenants`

```json
{
  "tenant_id": "rafay-cust-acme",
  "name": "ACME Corp",
  "plan": "pro",
  "input_guardrails": {},
  "output_guardrails": {}
}
```

| Field | Rules |
|---|---|
| `tenant_id` | Required. Letters, digits, `-`, `_`; at most 64. Use a stable id such as `rafay-cust-<customer id>` |
| `name` | Label shown in dashboards; at most 256 |
| `plan` | `basic`, `pro` or `enterprise` (sets default quotas) |
| `input_guardrails`, `output_guardrails` | Optional starting policy (same shape as [Set guardrails](#set-a-tenants-guardrails)). Or apply a template afterwards |

Returns `{"status":"created","tenant_id":...,"config":{...}}`. `409` if the
tenant exists: treat it as already provisioned.

### Read, update, delete

| Call | Does |
|---|---|
| `GET /v1/admin/tenants/{tenant_id}` | The tenant's configuration |
| `PUT /v1/admin/tenants/{tenant_id}` | Change `name`, `plan`, guardrails, `rbac`, `quota`, `require_sso` (merges; only the fields sent change) |
| `DELETE /v1/admin/tenants/{tenant_id}` | Remove the tenant (offboarding) |
| `GET /v1/admin/tenants/{tenant_id}/usage` | Request counts and usage |
| `GET /v1/admin/tenants/{tenant_id}/audit` | The tenant's audit trail |

## Keys

Rafay **generates** each key and registers it with Shield. Shield stores only a
hash, so it can never show the key again; Rafay keeps the plaintext in its
secret store.

- Use at least 32 random bytes, for example
  `rfy_` followed by `secrets.token_urlsafe(32)` in Python.
- Never start a key with `sk-test-` (reserved for the sandbox; refused with `400`).
- Never reuse a key across customers (refused with `409`).

### Register a key

`POST /v1/admin/tenants/{tenant_id}/api-keys`

```json
{ "api_key": "rfy_...", "scope": "runtime", "label": "rafay-serving", "expires_in_days": 180 }
```

| Field | Rules |
|---|---|
| `api_key` | Required. The key Rafay generated |
| `scope` | `runtime` (screening only, for the serving path) or `admin` (may also change the tenant's settings, for Rafay's backend). Omitted means an unscoped key, which deployments that enforce scopes refuse for settings changes; always set it |
| `label` | Which key this is, shown in listings |
| `expires_in_days` | The key stops working after this many days |

Give each customer a `runtime` key for the serving path and, if Rafay builds
settings screens, a separate `admin` key used only by Rafay's backend.

### List keys

`GET /v1/admin/tenants/{tenant_id}/api-keys` returns each key's prefix,
fingerprint, label, scope and expiry. Never the key itself. An unknown tenant
returns an empty list.

### Revoke a key

`DELETE /v1/admin/tenants/{tenant_id}/api-keys` with the key in the body:

```json
{ "api_key": "rfy_..." }
```

`404` if that key is not this tenant's. Requests made with a revoked key are
refused immediately.

## Guardrails

### Set a tenant's guardrails

`PUT /v1/admin/tenants/{tenant_id}`

```json
{
  "input_guardrails": {
    "adversarial_detection": { "enabled": true, "action": "block" },
    "pii_detection": { "enabled": true, "action": "block", "settings": { "score_threshold": 0.7 } }
  },
  "output_guardrails": {
    "pii_leakage": { "enabled": true, "action": "block" }
  }
}
```

Each guardrail: `enabled`, `action` (`block`, `warn`, `log`, `pass`), optional
`settings` (a `threshold` must be between 0 and 1). The call merges: guardrails
not named keep their current settings. Effective on the customer's next request.

Custom policies written in plain language are set with the customer's
`admin`-scoped key on `/v1/tenant/me/custom-policies/`, not with the admin
credential. See [How customers configure guardrails](/partners/rafay/configure/#3-settings-screens-in-rafays-console).

### Templates

| Call | Does |
|---|---|
| `GET /v1/admin/policy-templates` | The templates: `general`, `healthcare`, `financial_services` |
| `GET /v1/admin/policy-templates/{template_id}` | What one template turns on |
| `POST /v1/admin/tenants/{tenant_id}/apply-template` | Apply one: `{"template_id":"general"}`, optionally `"mode":"enforce"` |

Applying a template sets the tenant to **monitor** unless `mode` says otherwise.

### Monitor or enforce

| Call | Does |
|---|---|
| `GET /v1/admin/tenants/{tenant_id}/policy-mode` | The current mode |
| `PUT /v1/admin/tenants/{tenant_id}/policy-mode` | `{"mode":"monitor"}` records without blocking; `{"mode":"enforce"}` blocks |

A tenant with no mode set enforces.

## Single sign-on to the portal

| Call | Does |
|---|---|
| `POST /v1/admin/oidc-providers/{tenant_id}` | Connect an identity provider: `name`, `issuer`, `client_id`, `client_secret`, `groups_claim` (default `groups`), `admin_groups` (required for portal login) |
| `GET /v1/admin/oidc-providers/{tenant_id}` | The tenant's providers (never the secret) |
| `DELETE /v1/admin/oidc-providers/{tenant_id}/{name}` | Disconnect one |

The identity provider must allow the redirect URL
`https://shield.votal.ai/v1/tenant/auth/callback`. Customers then sign in at
`https://shield.votal.ai/v1/tenant/auth/login?tenant={tenant_id}&next=/tenant`.
Set `"require_sso": true` on the tenant to stop keys from opening the portal
(keys keep working for API calls).

## Errors

| Status | Meaning |
|---|---|
| `400` | A field is invalid: bad `scope`, a reserved `sk-test-` key, a `threshold` outside 0 to 1 |
| `401` | The admin credential is missing, wrong or expired |
| `403` | The credential is not allowed this operation, or this tenant |
| `404` | Unknown tenant, template or provider; or a key that is not this tenant's |
| `409` | The tenant already exists, or the key belongs to another tenant |
| `503` | A dependency was unavailable; retry |

## Deployment settings that affect these calls

| Setting | Effect |
|---|---|
| `SHIELD_GUARD_REQUIRE_KEY=enforce` | **Required.** Screening calls without a valid customer key are refused instead of being screened with no policy |
| `SHIELD_REGISTRY_WRITE_SCOPE`, `SHIELD_CONFIG_WRITE_SCOPE` | `enforce` makes `runtime` and unscoped keys read-only for settings. Recommended on a Rafay-dedicated deployment |
| `SHIELD_TENANT_POLICY_MODE_SELF_SERVICE=off` | Only the admin credential can switch monitor or enforce; customers cannot |
