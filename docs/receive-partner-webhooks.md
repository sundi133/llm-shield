---
title: Receive a partner's webhooks
layout: default
nav_order: 75
permalink: /webhook-inbox/
description: "Give a partner a webhook URL and signing secret, and see every delivery exactly as it arrived, with credentials masked. For tenant admins in the portal, and for operators running platform inboxes."
---

# Receive a partner's webhooks
{: .no_toc }

Some partners call you when something happens on their side. Rafay, for
example, sends **API key created**, **API key revoked** and **API key expired**
events from its Guardrail Provider settings. An inbox gives the partner a URL
and a signing secret, and records every delivery exactly as it arrived, so you
can see what the partner really sends.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

## What an inbox does

- **It records each delivery exactly:** the method, path and query, every
  header in the order it was sent, the body, its size and SHA-256, the
  sender's address, and whether the signature verified.
- **It masks credentials before anything is stored.** Headers such as
  `Authorization`, `Cookie` and `X-API-Key`, and any header whose name contains
  `secret`, `token`, `password`, `apikey` or `credential`, keep their first 4
  characters and their length, for example `Bear…(41)`. In a JSON body, fields
  such as `api_key`, `client_secret`, `password`, `token` and `private_key` are
  masked the same way, at any depth, and listed as masked. Ids such as
  `key_id` and `token_id` stay readable.
- **It checks the partner's signature,** once you choose how (below), and can
  refuse deliveries that are not signed correctly.
- **It does nothing else.** A delivery is recorded and shown; nothing in
  Shield changes because of it, and Shield makes no outbound call because of
  it.

An inbox belongs to one owner:

| Owner | Created by | Where | Who sees its deliveries |
|---|---|---|---|
| A tenant | The tenant's admin | Tenant portal, **Inbound webhooks** | That tenant, and Votal operators (read only) |
| The platform | A Votal operator | Admin console, **Inbound webhooks** | Operators only |

Use a **tenant inbox** when the partner is set up once per customer, so each
customer's events arrive in that customer's own inbox. Use a **platform inbox**
when one partner setting sends every customer's events to a single URL.

## 1. Create an inbox

In the tenant portal, open **Inbound webhooks**, give the inbox a name (for
example *Rafay lifecycle*) and, optionally, the partner's name, then click
**Create inbox**.

You get two values. **They are shown once:**

- **Webhook URL,** for example
  `https://shield.votal.ai/v1/inbound/xbOyOya7R0Lee4rJIl39x4ZQfTnT1Y2__u97S36axgU`
- **Webhook signing secret,** starting `whsec_`

Copy both now. If you lose one, make a new one with **New URL** or **New
secret**; the old one stops working at once.

To create one from a script instead, use a tenant key that can change settings
(not a runtime key):

```bash
curl -s -X POST https://shield.votal.ai/v1/tenant/me/inboxes \
  -H "X-API-Key: $SHIELD_TENANT_KEY" -H 'Content-Type: application/json' \
  -d '{"name": "Rafay lifecycle", "source": "rafay"}'
```

The answer holds `url` and `signing_secret`, once.

## 2. Give the URL and secret to the partner

Paste the URL and the secret into the partner's webhook settings.

**Rafay:** in **Create Guardrail Provider**, under **Lifecycle Webhooks**:

1. Turn on **Deliver Webhooks**.
2. **Webhook URL:** the inbox URL.
3. **Webhook Signing Secret:** the inbox secret.
4. **Events to Send:** tick **API key created**, **API key revoked** and **API
   key expired**.

Then make something happen on the partner's side, for example create an API
key in Rafay and revoke it. Each event appears under **Deliveries** within a
second or two; click **Refresh**.

## 3. Send a test yourself

You do not need the partner to try the inbox. Enter the URL and the secret at
hidden prompts (zsh), so they stay out of your shell history:

```bash
read -rs "URL?Webhook URL: " && echo && read -rs "SECRET?Signing secret: " && echo
```

Then send a signed event, the way most partners sign:

```bash
BODY='{"type":"api_key.created","data":{"key_id":"ak_test","api_key":"sk-test-123456789"}}'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $NF}')
curl -i -X POST "$URL" -H 'Content-Type: application/json' \
  -H "X-Signature: sha256=$SIG" --data "$BODY"
```

The answer is `200` with `{"received": true, "id": "dlv_..."}`. Open the
delivery: `api_key` is masked, `key_id` is not, and the event is
`api_key.created`.

## 4. Read a delivery

Click a row under **Deliveries**. The panel shows:

- **The request line,** with the token in the path shortened.
- **When, from where, the size and the SHA-256** of the body as received.
- **The signature result:** *verified*, *failed*, *no signature* or *not
  checked*, and why.
- **Every header,** in the order received, with masked values marked.
- **The body,** formatted when it is JSON, with the masked fields listed. A
  gzip or deflate body is shown decompressed.

The **Event** column comes from the body's `type`, `event`, `event_type`,
`eventType` or `action` field, or an `X-Event-Type` or `X-Webhook-Event`
header.

From a script:

```bash
curl -s -H "X-API-Key: $SHIELD_TENANT_KEY" \
  "https://shield.votal.ai/v1/tenant/me/inboxes/INBOX_ID/deliveries?limit=50"
```

and one delivery in full:

```bash
curl -s -H "X-API-Key: $SHIELD_TENANT_KEY" \
  "https://shield.votal.ai/v1/tenant/me/inboxes/INBOX_ID/deliveries/DELIVERY_ID"
```

## 5. Check the partner's signature

A new inbox records everything and checks nothing: anyone who has the URL can
post to it. Once the partner's first delivery has arrived:

1. Open it. If the inbox's secret verifies one of its headers, the signature
   panel says so, for example *would verify as hmac-sha256, header
   x-rafay-signature, prefix 'sha256=', hex*.
2. Click **Use these signature settings**. New deliveries are now checked.
3. Set **Unsigned deliveries** to **Refuse (401), still recorded** and click
   **Save**. A delivery that is unsigned, or signed with anything but this
   inbox's secret, is now answered with `401` and still recorded, marked
   *refused*, so you can see it.

If no suggestion appears, ask the partner how they sign, and set the fields
yourself:

| Field | Meaning |
|---|---|
| **Signature check** | `hmac-sha256` or `hmac-sha1`: an HMAC of the raw body with the inbox's secret. `none` records only |
| **Signature header** | The header that carries the signature, for example `x-signature` |
| **Prefix** | Text before the signature value, removed before comparing, for example `sha256=` |
| **Encoding** | `hex` or `base64` |

Signatures that include a timestamp (such as `t=...,v1=...`) are not
supported yet; tell us if your partner uses one.

## 6. Change, rotate or delete

| Action | What happens |
|---|---|
| **Receiving: Off** | The URL answers `410` and nothing is recorded |
| **Keep for** | Deliveries are kept 1 to 90 days (30 by default), and at most the newest 1,000 |
| **New URL** | A new URL, shown once. The old one answers `404` at once; deliveries still sent to it are counted on the inbox ("to an old URL") |
| **New secret** | A new secret, shown once. Deliveries signed with the old one fail the check |
| **Delete** | The inbox and every delivery it recorded. Its URL answers `404` |

Every create, change, rotation and deletion is in the audit log.

## What the partner gets back

| Answer | When |
|---|---|
| `200 {"received": true, "id": "dlv_..."}` | Recorded |
| `401` | **Refuse** is on and the signature is missing or wrong (still recorded) |
| `404` | Unknown, rotated or deleted URL |
| `410` | The inbox is turned off |
| `413` | Body over 1 MB (not recorded) |
| `429` | Over 60 deliveries a minute to this inbox |
| `503` | Shield's store is briefly unavailable; the partner should retry |

A `GET` to the URL answers `200 {"ok": true}` and records nothing, for
partners that check the URL when you save it. `POST`, `PUT` and `PATCH` are
recorded.

## Limits

- **10 inboxes per tenant,** 50 platform inboxes.
- **1 MB per delivery;** the first 64 KB of the body is kept, with the full
  size and SHA-256.
- **60 deliveries a minute per inbox.** One inbox's traffic never slows
  another's.
- **1,000 deliveries kept per inbox,** for 1 to 90 days.
- Header values are kept up to 8 KB each.

## Who can do what

| Caller | Read inboxes and deliveries | Create, change, rotate, delete |
|---|---|---|
| Tenant admin signed in to the portal | Own tenant | Own tenant |
| Tenant key that can change settings | Own tenant | Own tenant |
| Runtime key (screening only) | Own tenant | No |
| Votal operator | Any tenant, read only, and platform inboxes | Platform inboxes only |

Another tenant's inbox answers `404`, exactly like one that does not exist.

## For operators

### Platform inboxes

In the admin console, open **Inbound webhooks**. Inboxes you create there
belong to the platform. The filter shows **Platform**, **All owners**, or **A
tenant** (type its id and press Enter). A tenant's inbox opens read only;
changes to it are made in that tenant's portal.

The same from the admin API:

| Call | Purpose |
|---|---|
| `POST /v1/admin/inboxes` | Create a platform inbox; `url` and `signing_secret` once |
| `GET /v1/admin/inboxes?owner=platform` | Platform inboxes (`owner=all`, or `owner=<tenant id>`, to read others) |
| `GET /v1/admin/inboxes/{inbox_id}` | One inbox |
| `PUT /v1/admin/inboxes/{inbox_id}` | Change a platform inbox |
| `POST /v1/admin/inboxes/{inbox_id}/rotate-url` | New URL, once |
| `POST /v1/admin/inboxes/{inbox_id}/rotate-secret` | New secret, once |
| `DELETE /v1/admin/inboxes/{inbox_id}` | Delete a platform inbox |
| `GET /v1/admin/inboxes/{inbox_id}/deliveries` | Deliveries, newest first |
| `GET /v1/admin/inboxes/{inbox_id}/deliveries/{delivery_id}` | One delivery |

A managed admin credential needs `tenants:read` to read and `tenants:write` to
change. One limited to certain tenants reads only those tenants' inboxes.

### Deployment

- **Where it runs:** the admin service only (`shield.votal.ai`), not the
  guardrail service. It adds nothing to the guard path.
- **`SHIELD_PORTAL_BASE_URL`** (for example `https://shield.votal.ai`) sets the
  host in the URL shown on creation. Without it, the URL uses the host the
  service sees, which behind a proxy may be wrong.
- **`SHIELD_WEBHOOK_INBOX=off`** turns the receiver off: every inbox URL
  answers `404`. Inboxes and deliveries are kept.
- **Storage:** the same Redis as the rest of Shield. Deliveries expire with
  their inbox's retention and are trimmed to 1,000 per inbox. Deleting a tenant
  deletes its inboxes.
- **Check it is live** after a deploy:

```bash
curl -i https://shield.votal.ai/v1/inbound/not-a-real-token
```

`404 {"detail":"Not Found"}` means the receiver is up. `401` means an older
admin image is still running.

## Tenant API reference

All on the admin service, with a portal session or `X-API-Key`.

| Call | Purpose |
|---|---|
| `POST /v1/tenant/me/inboxes` | Create; `{"name": "...", "source": "..."}`. Returns `url` and `signing_secret` once |
| `GET /v1/tenant/me/inboxes` | Your inboxes, with the last delivery time and counts |
| `PUT /v1/tenant/me/inboxes/{inbox_id}` | Change `name`, `source`, `enabled`, `require_signature`, `retention_days`, `signing` (`scheme`, `header`, `prefix`, `encoding`) |
| `POST /v1/tenant/me/inboxes/{inbox_id}/rotate-url` | New URL, once |
| `POST /v1/tenant/me/inboxes/{inbox_id}/rotate-secret` | New secret, once |
| `DELETE /v1/tenant/me/inboxes/{inbox_id}` | Delete the inbox and its deliveries |
| `GET /v1/tenant/me/inboxes/{inbox_id}/deliveries` | Deliveries, newest first; `limit` (up to 200) and `cursor` (the `next_cursor` of the last page) |
| `GET /v1/tenant/me/inboxes/{inbox_id}/deliveries/{delivery_id}` | One delivery in full |

Example: turn on signature checking for Rafay's format and refuse anything
else.

```bash
curl -s -X PUT "https://shield.votal.ai/v1/tenant/me/inboxes/INBOX_ID" \
  -H "X-API-Key: $SHIELD_TENANT_KEY" -H 'Content-Type: application/json' \
  -d '{"signing": {"scheme": "hmac-sha256", "header": "x-rafay-signature", "prefix": "sha256=", "encoding": "hex"}, "require_signature": true}'
```

## Troubleshooting

| What you see | Why, and what to do |
|---|---|
| The partner reports `404` | The URL is wrong, was rotated, or the inbox was deleted. Check it starts with `https://shield.votal.ai/v1/inbound/`; make a new URL if needed |
| The partner reports `401` | **Refuse** is on and the signature did not verify. Open the refused delivery: the panel says whether the header was missing or the value did not match. Check the partner has the current secret |
| Nothing arrives | Check **Receiving** is **On**, the partner's webhooks are switched on, and the events are ticked. Send the test in step 3 to rule out Shield |
| **Signature: not checked** on every delivery | No signature check is set yet. Follow step 5 |
| *No header verifies with this inbox's secret yet* | The partner signs with a different secret, a timestamped scheme, or not at all. Paste the current secret into the partner's form again, or ask how they sign |
| "to an old URL" is counting up | The partner still has a URL you rotated. Paste the current one |

## Security notes

- **Treat the URL like a password.** Anyone who has it can post to the inbox
  until you turn on **Refuse**. Only a SHA-256 of the URL's token is stored,
  which is why the URL is shown once.
- **The signing secret is stored,** because checking a signature needs it. It
  is never shown again after creation or rotation.
- **Masking covers headers, JSON bodies and query parameters.** A body that is
  not JSON (for example form-encoded) is stored as received, so ask partners to
  send JSON.
- **Deliveries are data, never instructions.** Shield does not act on them.
