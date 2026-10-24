# Spec: webhook inbox

Status: DRAFT, awaiting approval.

## 1. Problem and outcome

A partner's console registers Shield as a **Guardrail Provider** ("Create
Guardrail Provider"), with a "Lifecycle Webhooks" section: Deliver Webhooks, a
Webhook URL, a Webhook Signing Secret, and Events to Send. The events offered
(2026-10-24) are:

- **API key created**;
- **API key revoked**;
- **API key expired**.

These are the partner's own token factory keys. The webhooks are "delivered
whether or not any router currently references this provider". Shield has no
endpoint that receives them, and nobody here knows yet what each delivery
carries: the key itself, a hash or only an id; the partner's customer or org;
the expiry; and how deliveries are signed. Shield's
own webhooks only go the other way (`core/webhook_dispatcher.py`, signed
`X-Shield-Signature: sha256=<HMAC>`).

Telemetry deliberately keeps no raw requests: they carry customers' prompts
and credentials.

**Outcome.** An inbox has an **owner**: a tenant, or the platform.

- **A tenant inbox** is created by that tenant's admin in the tenant portal
  (**Settings > Inbound webhooks**). Its deliveries belong to that tenant: the
  tenant sees them, other tenants never do, and phase 2 acts only on that
  tenant. This fits a partner that sets up one Guardrail Provider per
  customer, each pointing at that customer's own inbox.
- **A platform inbox** is created by an operator in the admin console, for a
  partner that sends every customer's events through one provider.

Either way, the creator gets:

- a receiving URL;
- a signing secret, shown once.

They paste both into the partner's form. Every delivery is then recorded
**exactly as it arrived**: method, path, query, every header, the body, the
sender's address, and whether its signature verified. Credential headers and
secret-looking body fields are masked. An **Inbound webhooks** page, in the
tenant portal for a tenant inbox and in the admin console for a platform one,
shows each delivery, so the partner's real format is
visible before anyone writes code that acts on it. Operators can also see any
tenant's inboxes, read only, to help a customer debug.

**Non-goals (this spec):**
- **Acting on events,** such as creating a tenant or revoking a key. That is
  phase 2, its own spec, written from the deliveries this records.
- **Replaying deliveries.**
- **Moving an inbox** between tenants, or between a tenant and the platform.
  Delete and create a new one.
- **Recording Shield's guarded traffic** (`/guardrails/*` and so on). That
  stays out of the log by design.

## 2. Plane and latency contract

- **Plane:** admin only (`admin_app.py`, `shield.votal.ai`), for both owners.
  The receiving URL is `https://shield.votal.ai/v1/inbound/{token}`. The tenant
  routes below are mounted on the admin plane only, not with the rest of
  `/v1/tenant/*` on the guardrail service.
- **Guard path:** untouched (`/guardrails/*`, `cap/mint`, `tools/call`), so
  there is no guarded-traffic impact.
- **Latency:** the receiver records the delivery and answers. It does no
  outbound call and no model call.

## 3. Data model

| Key | Value | TTL |
|---|---|---|
| `inbox:{inbox_id}` | `{inbox_id, owner, name, source, created_at, created_by, token_hash, signing: {scheme, header, prefix, encoding, secret}, require_signature: bool, retention_days, enabled}` | none |
| `inboxes:{owner}` (set) | inbox ids for one owner: a tenant id, or `platform` | none |
| `inboxes:owners` (set) | owners with at least one inbox, for the operator's all-tenants view | none |
| `inboxtoken:{sha256(token)}` | `inbox_id` | none (deleted on rotate or delete) |
| `inbox:{inbox_id}:deliveries` (sorted set, score = received_at) | one JSON delivery per member (below) | members trimmed by age (`retention_days`, default 30, at most 90) and count (1,000); key TTL = retention |
| `inbox:{inbox_id}:rate:{minute}` | counter | 120 s |

**One delivery:**
```json
{"id": "dlv_…", "received_at": 1792900000.123, "method": "POST",
 "path": "/v1/inbound/…", "query": {"a": "1"},
 "source_ip": "203.0.113.9", "user_agent": "…",
 "headers": [["content-type", "application/json"], ["x-signature", "sha256=9f2c…"],
             ["authorization", "Bear…(41)"]],
 "content_type": "application/json", "size": 812,
 "body": "{…}", "body_truncated": false, "body_sha256": "…", "body_masked_fields": ["data.api_key"],
 "signature": {"result": "verified|failed|absent|not_configured", "header": "x-signature", "detail": "…"}}
```

- **Token in the path:** the receiving URL ends in a 32-byte random token; only
  its sha256 is stored. Anyone holding the URL can post to the inbox, as with
  any webhook URL. The signature is what proves a delivery came from the
  partner.
- **The signing secret is stored as is,** like the outgoing webhooks'
  (`storage/webhook_store.py`), because HMAC verification needs it. It is shown
  once at creation and never returned again.
- **Scoping:** `owner` is set at creation, from the caller and never from the
  body: a tenant route always writes the caller's tenant id, the operator route
  always writes `platform`. Every tenant route loads the inbox and checks
  `inbox.owner == tenant_id` before anything else, and answers 404 (not 403)
  on a mismatch, so a tenant cannot learn that another tenant's inbox id
  exists. The receiving token maps straight to one inbox, so a URL never
  reaches another owner's inbox.
- **A delivery's tenant:** for a tenant inbox, that tenant. For a platform
  inbox, whatever the payload says; phase 2 decides.

## 4. API and interface (admin plane)

**Receiver, unauthenticated: the token is the address, the signature the proof.**

| Method and path | Answer |
|---|---|
| `POST`, `PUT` or `PATCH /v1/inbound/{token}` | `200 {"received": true, "id": "dlv_…"}` once recorded |
| | Unknown or rotated token: `404` with nothing in the body that says why |
| | Body over 1 MB: `413` |
| | Over 60 a minute: `429` |
| | Inbox disabled: `410` |
| | `require_signature` set and the signature failed or is absent: `401` (still recorded, marked rejected) |
| | Store unavailable: `503`, so the partner retries rather than the delivery being lost |
| `GET /v1/inbound/{token}` | `200 {"ok": true}` and nothing recorded, for partners whose setup sends a verification GET |

**Tenant (tenant portal: an admin SSO session or a settings key; runtime keys
are refused by `require_registry_write` for writes):**

| Method and path | Purpose |
|---|---|
| `POST /v1/tenant/me/inboxes` `{name, source}` | Create. Returns `url` and `signing_secret` **once** |
| `GET /v1/tenant/me/inboxes` | This tenant's inboxes, as the operator list below |
| `PUT /v1/tenant/me/inboxes/{inbox_id}` | Change, as the operator route |
| `POST /v1/tenant/me/inboxes/{inbox_id}/rotate-url` | As the operator route |
| `POST /v1/tenant/me/inboxes/{inbox_id}/rotate-secret` | As the operator route |
| `DELETE /v1/tenant/me/inboxes/{inbox_id}` | As the operator route |
| `GET /v1/tenant/me/inboxes/{inbox_id}/deliveries?limit&cursor` | As the operator route |
| `GET /v1/tenant/me/inboxes/{inbox_id}/deliveries/{id}` | As the operator route |

The tenant's id comes from `_require_tenant(request)`, never from the path or
body. Reads need a tenant session or key (a runtime key can read, as with the
rest of the portal); writes go through `require_registry_write`.

**Operator (admin key or admin SSO session, behind the `/v1/admin` gate).**
These manage platform inboxes; `?owner=` lets an operator **read** a tenant's
inboxes and deliveries (`owner=all` lists every owner):

| Method and path | Purpose |
|---|---|
| `POST /v1/admin/inboxes` `{name, source}` | Create. Returns `url` and `signing_secret` **once** |
| `GET /v1/admin/inboxes` | List: name, source, created, last delivery, deliveries in the last 24 hours, signing scheme. Never a secret or a token |
| `PUT /v1/admin/inboxes/{inbox_id}` | Change the name, `enabled`, `require_signature`, `retention_days` (1 to 90), or `signing` (`scheme`, `header`, `prefix`, `encoding`) |
| `POST /v1/admin/inboxes/{inbox_id}/rotate-url` | A new token; the old URL answers 404 at once |
| `POST /v1/admin/inboxes/{inbox_id}/rotate-secret` | A new signing secret, shown once |
| `DELETE /v1/admin/inboxes/{inbox_id}` | The inbox and its deliveries |
| `GET /v1/admin/inboxes/{inbox_id}/deliveries?limit&cursor` | Newest first: summaries (time, method, size, signature result, the event name if found) |
| `GET /v1/admin/inboxes/{inbox_id}/deliveries/{id}` | One delivery in full |

Admin credential scopes:
- reads need `tenants:read`, cross-tenant (and `tenants:read` on that tenant
  for `?owner=<tenant>`);
- writes need `tenants:write`, cross-tenant, and apply to platform inboxes
  only. An operator who needs to change a tenant's inbox uses the tenant
  portal as that tenant, so the tenant's audit shows it.

**Signature schemes** (`signing.scheme`):

| Scheme | Meaning |
|---|---|
| `none` | Record only (`not_configured`) |
| `hmac-sha256` | HMAC over the raw body with the secret, compared in constant time with the value of `header`, after removing `prefix` (for example `sha256=`) and decoding with `encoding` (`hex` or `base64`) |
| `hmac-sha1` | The same with SHA-1, for older senders |

Timestamped schemes (`t=…,v1=…`) are left out until a partner needs one. The
first deliveries show which applies.

**Event name for the list:** the first non-empty value of the JSON body fields
`type`, `event`, `event_type`, `eventType`, `action`, or of an `X-Event-Type`
or `X-Webhook-Event` header. Display only; nothing acts on it.

**Tenant portal:** **Settings > Inbound webhooks**, the same layout as the
console page below, showing only the tenant's inboxes.

**Admin console:** a new **Inbound webhooks** page, with an owner filter
(Platform, a tenant, All). Tenant inboxes are read only here.
- **Inboxes:** a list, and create, which shows the URL and secret once with
  Copy buttons and a short "paste these into the partner's Lifecycle Webhooks
  form".
- **Each inbox:** its settings, and a deliveries table.
- **A delivery** opens a panel: the request line, the headers as a table with
  masked values marked, the body pretty-printed when JSON, the signature result
  and why, and the size and hash.
- **Escaping:** everything shown came from outside, so all of it is escaped.

## 5. Security and backward compatibility

- **Default and opt-out:** nothing is received until an inbox exists.
  `SHIELD_WEBHOOK_INBOX=off` removes the receiver (404).
- **Masking headers.** These keep their first 4 characters, then `…` and the
  length:
  - `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`;
  - `X-API-Key`, `X-Admin-Key`, `X-Votal-Local-Secret`;
  - any header whose name contains `secret`, `token`, `password`, `apikey`,
    `api-key` or `credential`.

  The configured signature header is **not** masked: it is an HMAC of the
  body, not a secret, and is what you debug against.
- **Masking the body.** JSON values whose key matches `secret`, `token`,
  `password`, `api_key`, `apikey`, `private_key` or `client_secret`
  (case-insensitive, at any depth) are masked the same way and listed in
  `body_masked_fields`. Lifecycle events may carry credentials, such as a
  provisioned key. Non-JSON bodies are stored as received, up to 64 KB of text;
  above that, truncated, with the size and sha256 kept.
- **Limits:**
  - 1 MB per body, 60 deliveries a minute per inbox;
  - 1,000 deliveries kept per inbox, at most 90 days;
  - at most 10 inboxes per tenant, and 50 platform inboxes;
  - the per-minute limit is per inbox, so one tenant's noisy partner never
    slows another tenant's.
- **Who can read deliveries:** for a tenant inbox, that tenant and operators;
  for a platform inbox, operators only, because it may hold several customers'
  data. Reads are not audited; inbox create, change, rotate and delete are (the
  tenant's admin audit for tenant inboxes, the platform's for platform ones).
- **Deleting a tenant** deletes its inboxes and deliveries.
- **Not a way into the platform:** nothing is acted on, and no outbound call is
  made from a delivery, so it cannot cause SSRF.

## 6. Packaging and deploy

- **New modules:** `api/routes_inbound_webhooks.py` (receiver, tenant and
  operator routes, one router mounted only by `admin_app.py`) and
  `storage/webhook_inbox_store.py`. **Both must be COPYed into
  `Dockerfile.admin`**; `tests/test_admin_dockerfile_imports.py` guards it.
- **Auth middleware:** `core/auth.py` lets `/v1/inbound/` through, because
  those routes authenticate by token and signature, the same way as
  `/v1/signup`.
- **Write-scope guard:** `tests/test_tenant_config_write_scope.py` lists the
  receiver's routes as open by design, with the reason.
- **Dependencies:** none new.
- **Images:** the admin image only.

## 7. Failure modes and edge cases

| Case | Behaviour |
|---|---|
| Redis down | Receiver 503 (the partner retries); tenant and operator routes 503 |
| Empty body | Recorded, size 0 |
| Binary body | Recorded as base64 up to 64 KB, flagged `binary` |
| Malformed JSON with `content-type: application/json` | Recorded as text; `body_json_error` noted |
| Header values that are huge or repeated | Each value capped at 8 KB; repeats kept in order |
| Two deliveries at the same instant | Separate ids; the sorted set holds both |
| A rotated URL still used by the partner | 404, and the inbox's list shows "deliveries to an old URL: n" (a counter only) |
| Retention changed | Applies from the next delivery's trim |
| A tenant asks for another tenant's inbox id | 404, the same answer as an id that does not exist |
| A tenant at 10 inboxes creates another | 409 with "delete one first" |
| The tenant is deleted | Its inboxes go; their URLs answer 404 |
| Signature header present, scheme `none` | Recorded, result `not_configured`, with the header visible so the scheme can be chosen |

## 8. Test plan (definition of done)

- **Receiver:**
  - a delivery is recorded exactly: method, path, query, every header in order,
    the body, size and sha256;
  - unknown token gives 404;
  - over 1 MB gives 413; over 60 a minute gives 429; disabled gives 410;
  - `GET` answers and records nothing.
- **Masking:**
  - each credential header is masked, and the signature header is not;
  - JSON secret fields are masked at depth and listed;
  - a non-JSON body passes through; truncation works above 64 KB.
- **Signatures:**
  - `hmac-sha256` in hex and base64, with and without a prefix, verifies;
  - a tampered body fails;
  - an absent header gives `absent`;
  - `require_signature` gives 401 and the delivery is still recorded;
  - comparison is constant-time (`hmac.compare_digest`).
- **Inbox API, for both the tenant routes and the operator routes:**
  - create returns the URL and secret once, and the list never returns either;
  - rotate-url gives the old URL 404 and the new one works;
  - rotate-secret changes verification;
  - delete removes the deliveries;
  - scope checks; audit rows for writes.
- **Tenant isolation:**
  - tenant A cannot list, read, change, rotate or delete tenant B's inbox, or
    read its deliveries (404 each);
  - `owner` in a create body is ignored;
  - a runtime key can read but not create or change;
  - the operator can read a tenant's inboxes with `?owner=` and cannot change
    them;
  - the 10-per-tenant limit;
  - deleting a tenant removes its inboxes.
- **Retention:** trim by age and by count.
- **Store down:** the receiver gives 503 and nothing is half-written.
- **Pages:**
  - the tenant portal page and the admin console page are wired;
  - the tenant page lists only the tenant's own inboxes;
  - every value from a delivery is escaped (test with `<script>` in a header,
    a body and an event name).
- **Regression:** the image import guard, the write-scope guard, the full
  suite in a clean venv, and CI.
- **Browser preview,** done twice, once as a tenant in the portal and once as
  an operator in the console:
  - create an inbox;
  - send a signed delivery with curl;
  - see it, with headers, the masked fields and "verified".

## 9. Tasks (one PR each, in order)

| Task | Scope |
|---|---|
| 1 | `storage/webhook_inbox_store.py` and the receiver `/v1/inbound/{token}`: record, mask, verify, limits; the auth exemption; `Dockerfile.admin`; tests |
| 2 | Inbox API for both owners: `/v1/tenant/me/inboxes*` and `/v1/admin/inboxes*` (create, list, change, rotate URL and secret, delete, deliveries), owner checks, `?owner=` reads, limits, tenant deletion; audit; tests |
| 3 | Tenant portal **Settings > Inbound webhooks** and admin console **Inbound webhooks** page (one shared component): inboxes, create (URL and secret once), settings, deliveries and the delivery panel; browser-checked |
| 4 | Docs: how a tenant, or an operator, connects a partner (paste the URL and secret, choose the events, send a test, read the first deliveries, set the signing scheme, then turn on `require_signature`) |

**Then, phase 2 (its own spec):** acting on the partner's events, written from
the deliveries this inbox records. A sketch, to be confirmed against real
payloads:

| Event | Likely action in Shield |
|---|---|
| API key created | Record the partner key (by id or hash, never the plaintext if Shield can avoid it) and which tenant it belongs to, so traffic carrying it is attributed and governed |
| API key revoked | Stop honouring it in Shield at once, and record why |
| API key expired | The same as revoked, using the expiry the event carries |

For a **tenant inbox** the tenant is already known: an event acts only on the
tenant that owns the inbox. For a **platform inbox** the recorded deliveries
decide which tenant a key maps to (the payload's customer field, or a mapping
the operator sets per inbox). Either way they show whether Shield needs the
key itself or only its id.
