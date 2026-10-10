---
title: Votal Shield — Rafay integration guide (multi-tenant guardrails)
description: How Rafay enables Votal Shield AI guardrails for its customers. Each Rafay customer is one Shield tenant with its own API key; Rafay calls Shield PreCall (input) and PostCall (output) in its AI serving path.
audience: Rafay platform engineering
---

# Votal Shield — Rafay integration guide

This is the partner handoff for enabling **Votal Shield** AI guardrails on the
Rafay platform, multi-tenant. Pair it with the machine-readable contract:

- **OpenAPI 3.1 spec:** `docs/assets/openapi-partner.json` (curated partner
  subset — the guard, policy, and telemetry endpoints only, never the admin
  surface). Import this into Rafay's codegen / API explorer.

## 1. Model in one paragraph

Every Rafay **customer = one Shield tenant**, identified by its own **API key**.
Rafay provisions a tenant + key per customer (section 4), stores the key, and at
request time calls Shield **PreCall** on the user's input and **PostCall** on the
model's output, passing that customer's key. Shield resolves the tenant **from
the key**, applies that tenant's configured guardrails, and returns an
allow/block/redact verdict. Policy is per tenant, so one customer's rules never
touch another's. Shield never needs to store Rafay's model keys or see anything
beyond the text being screened.

```
Rafay customer app ──► Rafay AI serving path
                          │  (1) PreCall:  POST /guardrails/input   ─┐
                          │        block? → return the block to user │  X-API-Key:
                          ▼                                          │  <customer tenant key>
                       LLM / model                                  ├─► Votal Shield
                          │                                          │   (hosted API, or
                          │  (2) PostCall: POST /guardrails/output  ─┘    in-cluster container)
                          ▼        block/redact? → use sanitized_output
                       response to user
```

## 2. Base URL (two deployment shapes, same API)

- **Hosted (fastest):** `https://api.guardrails.votal.ai`
- **In-cluster (data residency):** the Shield guardrail container deployed in the
  customer's cluster; same paths, Rafay sets the base URL per deployment.

Everything below is relative to the chosen base URL.

## 3. Authentication

Send the customer's tenant key on **every guard call**. Header priority:

1. `X-API-Key: <tenant-key>`  ← **preferred** (avoids collision with upstream proxies)
2. `X-Tenant-Key: <tenant-key>`
3. `Authorization: Bearer <tenant-key>`

The key is hashed and mapped to exactly one tenant; the tenant's policy is applied
automatically. **A caller cannot override the tenant** — any `tenant_id` in the
body/headers that disagrees with the key is rejected (IDOR defense).

> **REQUIRED deployment setting for multi-tenant isolation:**
> Deploy the Rafay-facing Shield with **`SHIELD_GUARD_REQUIRE_KEY=enforce`**.
> The default is `off`, under which a call with a missing/invalid key **fails
> open** (screens with no tenant policy) instead of being refused. In a
> multi-tenant deployment that is a silent isolation gap — set it to `enforce`
> so a bad key returns `401 missing_tenant_key` / `invalid_tenant_key`.

## 4. Onboarding a customer ("enable guardrails")

Enabling guardrails for a Rafay customer = **provision a Shield tenant + key** and
store the key against that customer. Two ways:

### 4a. Rafay provisions via the admin API (recommended)
> These admin endpoints are **privileged and intentionally NOT in the partner
> OpenAPI** (`openapi-partner.json` publishes only tenant-scoped surfaces). Votal
> issues Rafay the **admin key and these provisioning endpoints separately** as a
> partner capability. Do not expect them in the imported spec.

Rafay holds a Shield **admin key** (`X-Admin-Key`, issued to Rafay once, out of
band — not a tenant key). Per customer:

```bash
# create the tenant
curl -X POST "$BASE/v1/admin/tenants" \
  -H "X-Admin-Key: $RAFAY_ADMIN_KEY" -H "content-type: application/json" \
  -d '{"tenant_id":"rafay-cust-acme","name":"ACME Corp","api_keys":[]}'

# mint that tenant's key (store the returned key against the customer in Rafay)
curl -X POST "$BASE/v1/admin/tenants/rafay-cust-acme/api-keys" \
  -H "X-Admin-Key: $RAFAY_ADMIN_KEY" -H "content-type: application/json" \
  -d '{"label":"rafay-prod","scope":"guard"}'
```
List/revoke a customer's keys: `GET` / `DELETE /v1/admin/tenants/{tenant_id}/api-keys`.

### 4b. Self-service (customer mints their own)
If the customer has a Shield portal session or an existing key, they can mint:
`POST /v1/tenant/me/api-keys` (returns the plaintext key **once** — store it then).

> The admin key is the one high-privilege secret in this integration. It mints
> and revokes tenants, so Rafay must hold it like any provisioning credential
> (vault, not in customer-visible config). Tenant keys are per customer and
> low-blast-radius by comparison.

## 5. Let the customer choose which guardrails are on

Two options — pick one, or offer both:

- **Embed the Shield tenant portal** (SSO) so the customer configures policy in
  Shield's own UI. Lowest build cost for Rafay.
- **Surface it in Rafay's UI** via the policy API (authed with the customer's key):
  - `GET /v1/tenant/me/policies` → current input/output guardrails + custom policies
  - `PUT /v1/tenant/me/policies` → replace the input/output guardrail config
  - Natural-language / OWASP-style custom rules: `GET|POST /v1/tenant/me/custom-policies/`,
    `POST /v1/tenant/me/custom-policies/{id}/enable` (and `/disable`).
    A custom policy body is: `name`, `description`, `prompt` (20–2000 chars),
    `action` (`pass|warn|redact|block`), `stage` (`input|output`),
    `confidence_threshold` (0.5–1.0), `priority` (1–1000), `multi_turn`.

New/changed policy takes effect on the next guard call for that tenant — no
redeploy.

## 6. Runtime: the guard calls

### 6a. PreCall — screen the user's input
`POST /guardrails/input`

Request (only `message` is required; the tenant's configured guardrails run
automatically — you do not list them per call):
```json
{
  "message": "the user's prompt text",
  "messages": [{"role":"user","content":"..."}],
  "session_id": "rafay-session-123",
  "user_role": "analyst",
  "agent_key": "rafay-app-x"
}
```
```bash
curl -X POST "$BASE/guardrails/input" \
  -H "X-API-Key: $CUSTOMER_KEY" -H "content-type: application/json" \
  -d '{"message":"my SSN is ..."}'
```
Response:
```json
{
  "safe": false,
  "action": "block",
  "guardrail_results": [
    {"guardrail":"pii-detection","passed":false,"action":"block",
     "message":"message contains a Social Security Number","details":{...},"latency_ms":41.2}
  ],
  "inference_time_ms": 44.0
}
```
- **PASS:** `safe=true`, `action="pass"`, every `guardrail_results[].passed=true` → forward the prompt to the model.
- **BLOCK:** `safe=false`, `action="block"` → **do not call the model**; return the
  block to the user. The reason is the failing result's `message`.
- `action` is the highest-severity outcome across guardrails, ranked
  `pass < log < warn < redact < block`. On `redact`, a guardrail may have rewritten
  content — see PostCall for the sanitized payload pattern.

### 6b. PostCall — screen the model's output (and tool results)
`POST /guardrails/output`

Request (`output` required):
```json
{
  "output": "the model's response text",
  "context": {"tool_name":"search","user_role":"analyst","stage":"output"}
}
```
Response adds two conditional fields to the same schema:
- `sanitization` — audit of any data-policy redaction applied
- `sanitized_output` — **present only when the payload was modified**; forward
  **this** to the user instead of the original.

So PostCall handling: if `action=="block"` → suppress the output; else if
`sanitized_output` is present → return it; else return the original.

### 6c. File uploads
`POST /guardrails/file` — same verdict schema plus a `file` block; use it when a
customer uploads a document to an AI tool through Rafay.

### Also in the partner spec (beyond prompt screening)
The curated spec also publishes the **agentic / tool surfaces** Rafay may want for
agent workloads: agent registry (`/v1/agents/registry`), tool-call RBAC
(`/v1/shield/tool/check`, `/v1/shield/tool/output`, `/v1/agents/tools/policies`),
data policies (`/v1/data-policies/...`), and MCP gateway upstreams
(`/v1/tenant/me/mcp-gateway/upstreams`). Same tenant-key auth.

### Optional: one-call gateway (not in the partner spec)
If Rafay prefers Shield to also make the model call, an OpenAI-compatible endpoint
(`POST /v1/shield/chat/completions`) does input-screen → model → output-screen in
one request. It is **not published in the partner subset** — ask Votal to enable
it if Rafay wants Shield to own the model call rather than the split
PreCall/PostCall above.

## 7. Telemetry (per customer)

- `GET /v1/tenant/me/telemetry` — **(in the partner spec)** tenant-scoped
  agent/chat telemetry, keyed by the caller's own key; filters `limit`, `offset`,
  `agent_key`, `status` (`pass|warn|redact|mask|block`), `tool_name`, `q`,
  `since`, `until`. This is the partner-appropriate telemetry call.
- `GET /v1/tenant/me/usage`, `GET /v1/tenant/me/audit`,
  `GET /v1/tenant/me/guardrails/metrics` — usage, audit, and effectiveness (all
  in the partner spec).
- An admin-scoped `GET /v1/shield/decisions/{tenant_id}` also exists for
  cross-tenant enforcement queries, but like the admin provisioning endpoints it
  is **not in the partner subset** — use `/v1/tenant/me/telemetry` from Rafay.

Rafay can surface these in its own dashboard, or link customers to Shield's
Telemetry view.

## 8. Failure modes & latency (state these to customers, don't SLA them)

- **Store/Redis outage:** Shield **fails open** (screens with a warning rather
  than taking the customer's app down). If the deployment must fail *closed*,
  raise it with Votal — it's a deploy posture, not a per-call flag.
- **Timeouts:** Rafay should set a client timeout on the guard call and decide
  its own fail-open vs fail-closed if Shield is unreachable. Recommended: fail
  closed on `PreCall` for regulated tenants, fail open otherwise — Rafay's choice
  per customer.
- **Latency (typical, measured — not an SLA):** Tier-1 keyword/regex `<5 ms`,
  Tier-2 sentiment/topic `~150 ms`, Tier-3 adversarial/PII `~500 ms`. The
  response reports actual `inference_time_ms` / per-result `latency_ms` every
  call. Absolute latency varies with load and model placement; quote ranges, not
  a single number.

## 9. End-to-end Rafay steps (checklist)

1. **Receive** from Votal: the admin key (`X-API-Key`-style `X-Admin-Key`), a
   sandbox tenant + key, the base URL(s), and `docs/assets/openapi-partner.json`.
2. **Import** the OpenAPI into Rafay's API tooling; generate a client.
3. **Deploy posture:** set `SHIELD_GUARD_REQUIRE_KEY=enforce` on the Rafay-facing
   Shield (hosted config confirmed by Votal, or in the in-cluster Helm values).
4. **Onboarding hook:** when a Rafay customer enables guardrails, call §4a to
   create the tenant + mint the key; store the key in Rafay's secret store keyed
   to the customer.
5. **Policy UX:** embed the Shield portal (§5) or build the policy screens on
   `/v1/tenant/me/policies` + `/custom-policies`.
6. **Serving path:** wire §6a PreCall before the model and §6b PostCall after;
   honor `action` and `sanitized_output`.
7. **Observability:** pull §7 telemetry into Rafay's dashboard per customer.
8. **Validate** against the sandbox tenant: a benign prompt passes, a policy-
   violating prompt returns `action=block`, and the decision appears in telemetry.
9. **Go-live:** repeat for a pilot customer, confirm isolation (customer A's key
   never sees customer B's policy or decisions), then roll out.

## 10. What Votal still needs to confirm before sending

- Issue Rafay an **admin/provisioning key** and a **sandbox tenant + key**.
- Confirm the **deployment shape** (hosted vs in-cluster) and, if in-cluster, hand
  over the Helm chart + model sizing.
- Confirm **`SHIELD_GUARD_REQUIRE_KEY=enforce`** is set on the Rafay-facing
  deployment.
- Decide whether policy config is **portal-embed** or **API in Rafay's UI** (or
  both) so section 5 can be trimmed to the chosen path.
