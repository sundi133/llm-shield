---
title: Onboarding runbook
parent: Rafay Integration
nav_order: 1
permalink: /partners/rafay/onboarding/
description: "Step by step: what Votal sets up once, what Rafay sets up once, and the exact calls to onboard, verify, rotate, and offboard each Rafay customer."
---

# Onboarding runbook

The whole integration in order, with the exact calls. Three parts:

1. [Once, by Votal](#1-once-by-votal): the deployment and Rafay's credential.
2. [Once, by Rafay](#2-once-by-rafay): storing secrets and choosing defaults.
3. [For every customer](#3-for-every-customer): create, protect, verify.

Then [rotation](#4-rotating-keys), [offboarding](#5-offboarding), and
[what to do when a call fails](#6-errors-and-what-to-do).

## Which host to call

Shield has two hosts. Use the API host for every API call, and the portal
host only for links you show to people.

| Host | Use it for |
|---|---|
| `https://api.guardrails.votal.ai` | Every API call: screening (`/guardrails/*`), provisioning (`/v1/admin/*`), and the customer's settings, telemetry and audit (`/v1/tenant/me/*`) |
| `https://shield.votal.ai` | People: the customer portal (`/tenant`) and its single sign-on link (`/v1/tenant/auth/login`). One API exception: the SIEM settings (`/v1/tenant/me/siem`) are served here only |

For an in-cluster deployment both are the URL of the Shield `Route` or
`Service` in that cluster.

## 1. Once, by Votal

| Step | What | Why |
|---|---|---|
| 1.1 | Set `SHIELD_GUARD_REQUIRE_KEY=enforce` on the deployment Rafay calls | Without it, a call with a missing or wrong key is screened with no customer policy instead of being refused |
| 1.2 | Issue Rafay a **managed admin credential**, never the root `SHIELD_ADMIN_KEY` | It can be limited, expires, can be rotated, and every action made with it is attributed to Rafay |
| 1.3 | Create a sandbox tenant and give Rafay its keys | So Rafay can build and test before touching a real customer |

Step 1.2, run by a Votal operator with the root key:

```bash
curl -X POST https://api.guardrails.votal.ai/v1/admin/credentials \
  -H "X-Admin-Key: $ROOT_ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"name":"rafay-provisioning","expires_in_days":90,
       "scope":{"operations":["tenants:read","tenants:write","oidc:read","oidc:write"],
                "tenants":["*"]}}'
```

The response holds the secret (`shadm_...`) once. Send it to Rafay through a
secret-sharing channel, never chat or email. Rotate it every 90 days with
`POST /v1/admin/credentials/{id}/rotate`.

> **Know the limit of `"tenants":["*"]`.** A credential's tenant list accepts
> exact tenant ids or `*` (all tenants). Rafay creates tenants as customers sign
> up, so it needs `*`, and on the shared hosted service `*` includes tenants
> that are not Rafay's. Until credentials can be limited to a tenant-id prefix
> such as `rafay-cust-*`, give Rafay a dedicated Shield deployment, or accept
> this and monitor the admin audit log for actions on non-Rafay tenants.

Check step 1.1 yourself. A screening call with no key must be refused:

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST https://api.guardrails.votal.ai/guardrails/input \
  -H "Content-Type: application/json" -d '{"message":"hello"}'
```

`401` means it is set. `200` means it is not, and Rafay must not go live yet.

## 2. Once, by Rafay

1. Store the `shadm_...` credential in Rafay's secret manager. It is the only
   secret that can create or change customer tenants.
2. Pick a stable tenant id scheme, for example `rafay-cust-<rafay customer id>`.
   Letters, digits, `-` and `_`, at most 64 characters.
3. Pick the default protection every new customer gets (step 3.1): one of the
   templates `general`, `healthcare` or `financial_services`
   (`GET /v1/admin/policy-templates` lists them with what each turns on).
4. Decide how customers will change their settings: in Shield's portal, in
   Rafay's console, or both. See
   [How customers configure guardrails](/partners/rafay/configure/).

## 3. For every customer

When a customer turns on guardrails in the Rafay console, run these in order.
`$CRED` is Rafay's `shadm_...` credential and `$API` is
`https://api.guardrails.votal.ai`.

### 3.1 Create the tenant, with its starting policy

```bash
curl -X POST "$API/v1/admin/tenants" \
  -H "X-Admin-Key: $CRED" -H "Content-Type: application/json" \
  -d '{"tenant_id":"rafay-cust-acme","name":"ACME Corp","plan":"pro"}'
```

Then apply the default template (or send `input_guardrails` and
`output_guardrails` in the create call instead):

```bash
curl -X POST "$API/v1/admin/tenants/rafay-cust-acme/apply-template" \
  -H "X-Admin-Key: $CRED" -H "Content-Type: application/json" \
  -d '{"template_id":"general"}'
```

Applying a template puts the tenant in **monitor** mode unless you add
`"mode":"enforce"`: decisions are recorded but nothing is blocked. A tenant that
never had a template applied **enforces**. Switch to enforce in step 3.5 once the
customer has reviewed what monitor mode recorded.

A `409` on create means the tenant already exists. Treat it as already
provisioned and continue; never create a second tenant for the same customer.

### 3.2 Create the customer's two keys

Shield does not generate keys on this endpoint: Rafay generates a strong random
key and registers it. Generate each key with at least 32 random bytes, and
never start one with `sk-test-` (reserved for the sandbox):

```bash
SERVING_KEY="rfy_$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
SETTINGS_KEY="rfy_$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
```

Register them with different scopes:

```bash
# Used on every model call. Can screen, cannot change settings.
curl -X POST "$API/v1/admin/tenants/rafay-cust-acme/api-keys" \
  -H "X-Admin-Key: $CRED" -H "Content-Type: application/json" \
  -d "{\"api_key\":\"$SERVING_KEY\",\"scope\":\"runtime\",\"label\":\"rafay-serving\",\"expires_in_days\":180}"

# Used only by Rafay's backend to read and change this customer's settings.
curl -X POST "$API/v1/admin/tenants/rafay-cust-acme/api-keys" \
  -H "X-Admin-Key: $CRED" -H "Content-Type: application/json" \
  -d "{\"api_key\":\"$SETTINGS_KEY\",\"scope\":\"admin\",\"label\":\"rafay-settings\",\"expires_in_days\":180}"
```

Store both in Rafay's secret store against the customer. Shield keeps only a
hash and cannot show them again. Why two keys: the serving key travels with
every request through Rafay's serving path, so if it leaks, it can only screen
text. It cannot switch off the customer's guardrails. Skip the settings key if
customers only use Shield's portal.

### 3.3 Optional: single sign-on to the portal

If customers will use Shield's portal, connect an identity provider to the
tenant so people sign in with their company login instead of a key. Rafay can
use its own identity provider for every customer, with one group per customer:

```bash
curl -X POST "$API/v1/admin/oidc-providers/rafay-cust-acme" \
  -H "X-Admin-Key: $CRED" -H "Content-Type: application/json" \
  -d '{"name":"rafay","issuer":"https://<idp>/realms/<realm>","client_id":"<client id>",
       "client_secret":"<client secret>","groups_claim":"groups",
       "admin_groups":["acme-guardrail-admins"]}'
```

- `issuer` must exactly match the `issuer` in the identity provider's
  `/.well-known/openid-configuration`.
- The identity provider's client must allow the redirect URL
  `https://shield.votal.ai/v1/tenant/auth/callback`.
- Members of `admin_groups` can change settings. Others in the directory who
  sign in can view but not change anything. Shield refuses the login while
  `admin_groups` is empty.

The customer's sign-in link, ready to put behind a "Guardrails" button in the
Rafay console:

```
https://shield.votal.ai/v1/tenant/auth/login?tenant=rafay-cust-acme&next=/tenant
```

It goes straight to the identity provider, with no "enter your organisation"
screen.

### 3.4 Verify before telling the customer it is on

```bash
# 1. A normal prompt passes.
curl -s -X POST "$API/guardrails/input" -H "X-API-Key: $SERVING_KEY" \
  -H "Content-Type: application/json" -d '{"message":"Summarise our Q3 plan"}'
# expect "action": "pass"

# 2. A prompt with sensitive data is caught (recorded in monitor mode, blocked in enforce).
curl -s -X POST "$API/guardrails/input" -H "X-API-Key: $SERVING_KEY" \
  -H "Content-Type: application/json" -d '{"message":"my SSN is 123-45-6789"}'

# 3. The serving key cannot change settings.
curl -s -o /dev/null -w "%{http_code}\n" -X PUT "$API/v1/tenant/me/policies" \
  -H "X-API-Key: $SERVING_KEY" -H "Content-Type: application/json" -d '{}'
# expect 403 where write enforcement is on

# 4. The decision shows up for this customer.
curl -s "$API/v1/tenant/me/telemetry?limit=5" -H "X-API-Key: $SETTINGS_KEY"
```

Also confirm isolation once per release: the serving key of customer A must
never return customer B's policies or telemetry.

### 3.5 Switch from monitor to enforce

When the customer has reviewed what would have been blocked:

```bash
curl -X PUT "$API/v1/admin/tenants/rafay-cust-acme/policy-mode" \
  -H "X-Admin-Key: $CRED" -H "Content-Type: application/json" -d '{"mode":"enforce"}'
```

Customers can also do this themselves in the portal, or Rafay's console can call
`PUT /v1/tenant/me/policy-mode` with the settings key.

### 3.6 Optional: lifecycle webhooks

Rafay's **Create Guardrail Provider** form can send **API key created**, **API
key revoked** and **API key expired** events. To receive them in Shield:

1. The customer's admin (or Votal, for one provider shared by every customer)
   creates an inbox under **Inbound webhooks** and copies its URL and signing
   secret, which are shown once.
2. In **Lifecycle Webhooks**, turn on **Deliver Webhooks**, paste the URL into
   **Webhook URL** and the secret into **Webhook Signing Secret**, and tick the
   three events.
3. Create and revoke a test key in Rafay. Both events appear under
   **Deliveries**, with every header and the body, credentials masked.
4. Open one, click **Use these signature settings**, then set **Unsigned
   deliveries** to **Refuse** so only Rafay's signed deliveries are accepted.

Shield records these events and does not act on them yet. The full guide is
[Receive a partner's webhooks](/webhook-inbox/).

## 4. Rotating keys

Both keys of a tenant work at the same time, so rotation has no downtime:

1. Generate and register a new key (step 3.2) with the same scope.
2. Put the new key into Rafay's serving path (or settings backend).
3. Revoke the old key. Revoking takes the key itself in the body:

```bash
curl -X DELETE "$API/v1/admin/tenants/rafay-cust-acme/api-keys" \
  -H "X-Admin-Key: $CRED" -H "Content-Type: application/json" \
  -d "{\"api_key\":\"$OLD_KEY\"}"
```

`GET /v1/admin/tenants/rafay-cust-acme/api-keys` lists the tenant's keys with a
prefix, fingerprint, label, scope and expiry, never the key itself. Set
`expires_in_days` on every key so a forgotten key stops working on its own.

## 5. Offboarding

1. Revoke both keys (step 4.3). Calls with them are refused immediately.
2. Remove the identity provider if one was connected:
   `DELETE /v1/admin/oidc-providers/rafay-cust-acme/rafay` (the `name` used in step 3.3).
3. Keep the tenant, its policy and its audit for your retention period, or
   delete it with `DELETE /v1/admin/tenants/rafay-cust-acme`.

## 6. Errors and what to do

| Status | Where | Meaning | What to do |
|---|---|---|---|
| `401` | screening | The key is missing, wrong, revoked or expired | Check the key stored for this customer; never retry without one |
| `401` | `/v1/admin/*` | The admin credential is wrong or expired | Rotate the credential with Votal |
| `403` | `/v1/admin/*` | The credential is not allowed this operation or tenant | Check its scope with Votal |
| `403` | `/v1/tenant/me/*` writes | A `runtime` key tried to change settings | Use the customer's settings key |
| `404` | `/v1/admin/tenants/{id}/api-keys` | Unknown tenant, or that key is not this tenant's | Check the tenant id |
| `409` | create tenant | The tenant already exists | Treat as already provisioned |
| `409` | register key | That key string belongs to another tenant | Generate a new key; never reuse one across customers |
| `400` | register key | Bad scope (use `runtime` or `admin`) or a reserved `sk-test-` key | Fix the request |
| `503` | settings writes | Shield could not check the key's scope and refused to be safe | Retry later |
| timeout | screening | Shield did not answer in time | Apply the customer's chosen policy: refuse (recommended for regulated customers) or let the request through and record it |
