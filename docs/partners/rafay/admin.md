---
title: Admin & tenant creation
parent: Rafay Integration
nav_order: 3
permalink: /partners/rafay/admin/
description: "Provision a Shield tenant and API key per Rafay customer with the admin key: create, list, rotate, and revoke."
---

# Admin & tenant creation

For Rafay platform engineering. This is the provisioning side: when a customer
enables guardrails, Rafay creates a **Shield tenant** for them and mints that
tenant's **API key**, which the serving path then uses on every guard call.

> **One Rafay customer = one Shield tenant + its own key.** The key is how Shield
> knows which customer a request belongs to and which policy to apply.

## The admin key

Provisioning is authorized by an **admin key**, sent as the `X-Admin-Key` header.
Votal issues this to Rafay once, out of band.

- It is **privileged** (it can create and revoke any tenant), so store it in
  Rafay's secret manager, never in customer-visible config.
- It is **not** a tenant key, and these admin endpoints are **not** part of the
  public partner OpenAPI (they are given to Rafay separately).

Base URL: `https://api.guardrails.votal.ai` (hosted) or Rafay's in-cluster
Shield Service.

## 1. Create a tenant

```bash
curl -X POST "$BASE/v1/admin/tenants" \
  -H "X-Admin-Key: $RAFAY_ADMIN_KEY" -H "content-type: application/json" \
  -d '{"tenant_id":"rafay-cust-acme","name":"ACME Corp","api_keys":[]}'
```
- `tenant_id` — use a **stable Rafay customer id** (e.g. `rafay-cust-<id>`), so the
  mapping is deterministic and you can find the tenant again.
- `name` — human label for dashboards.
- `api_keys` — leave empty here and mint the key in step 2 (so the plaintext is
  returned explicitly).

## 2. Mint the tenant's key

```bash
curl -X POST "$BASE/v1/admin/tenants/rafay-cust-acme/api-keys" \
  -H "X-Admin-Key: $RAFAY_ADMIN_KEY" -H "content-type: application/json" \
  -d '{"label":"rafay-prod","scope":"guard"}'
```
- The response contains the **plaintext key** — store it in Rafay's secret store,
  keyed to the customer. Shield keeps only a hash, so this is the one time you see it.
- Optional: `expires_in_days` to force rotation.

## 3. List / revoke keys

```bash
# list a customer's keys (ids, labels, created/expiry — never the plaintext)
curl "$BASE/v1/admin/tenants/rafay-cust-acme/api-keys" -H "X-Admin-Key: $RAFAY_ADMIN_KEY"

# revoke one key (offboarding, rotation, or a leak)
curl -X DELETE "$BASE/v1/admin/tenants/rafay-cust-acme/api-keys/<key-id>" \
  -H "X-Admin-Key: $RAFAY_ADMIN_KEY"
```

## The enable-guardrails flow

1. Customer toggles **guardrails on** in the Rafay console.
2. Rafay calls **step 1** (create tenant) then **step 2** (mint key).
3. Rafay stores the key in its secret store against that customer.
4. The serving path uses that key on every guard call
   ([integration guide](/partners/rafay/integration/)).

## Rotation and offboarding

- **Rotate:** mint a new key (step 2), swap it into the serving path, then revoke
  the old one (step 3). No downtime — both keys resolve the same tenant until you
  revoke.
- **Offboard:** revoke the customer's key(s). The tenant's policy and telemetry
  remain for audit unless you ask Votal to delete the tenant.

## Required deployment setting

The Shield deployment Rafay calls must run with
**`SHIELD_GUARD_REQUIRE_KEY=enforce`**. Otherwise a missing or invalid key
**fails open** (screens with no tenant policy) instead of being refused — a silent
multi-tenant isolation gap.

## Checklist

1. `X-Admin-Key` stored in Rafay's secret manager.
2. On enable: create tenant (stable `tenant_id`) + mint key, store key per customer.
3. On rotate/offboard: mint-swap-revoke / revoke.
4. `SHIELD_GUARD_REQUIRE_KEY=enforce` confirmed on the Shield deployment.
