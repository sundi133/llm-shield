---
title: "Spec: API key lifecycle"
layout: default
nav_order: 50
permalink: /spec-api-key-lifecycle/
description: "A tenant cannot list its own API keys, so rotation is guesswork and revocation is done by deleting a key and finding out what broke. The minimum that answers a security questionnaire honestly, without putting a write on the guard path."
---

# Spec: API key lifecycle
{: .no_toc }

`apikey:{sha256} → tenant_id` is the whole model. No creation date, no label,
no expiry, no last-used, and **no way to enumerate a tenant's keys.** Revoking
a key means deleting it and finding out what broke.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. Problem & outcome

Four questions a security review asks, and today's answers:

| Question | Today |
|---|---|
| Can you enumerate credentials? | No |
| Can they be rotated without interruption? | Mechanically yes, operationally no — you cannot see what exists |
| Do they expire? | No |
| When was this last used? | Unanswerable |

Enumeration is the one the others rest on. Rotation already works —
`add_api_key` and `remove_api_key` are independent, so two keys are valid at
once — but a tenant cannot see that it now has two, cannot tell which is the
old one, and cannot tell whether anything is still using it. So the safe
sequence is available and nobody can follow it.

### Outcome

A tenant can list its keys with a label, an age, an optional expiry and a
last-used timestamp; mint a replacement; watch traffic move; and revoke the old
one knowing it is idle. Every existing key keeps working, unchanged, forever.

### Non-goals

- **Plaintext recovery.** Keys are stored as SHA-256 and stay that way. A list
  shows a prefix and a hash, never the secret.
- **Automatic rotation.** Shield will not revoke a key on a timer. An expiry a
  tenant sets deliberately is different from Shield deciding to break their
  integration.
- **Per-key permissions.** Scope already exists
  ([spec-registry-write-authorization](/spec-registry-write-authorization/)).
- **Usage analytics.** `last_used` is a timestamp, not a counter or a report.

## 2. Plane & latency contract

**Admin plane** for listing and minting. The guard path is touched in exactly
one place and it needs justifying rather than asserting away.

`resolve_tenant_by_api_key()` runs on every guarded request: a 60-second
in-process cache, and one Redis GET on a miss. Two features want to reach it.

**Expiry costs nothing.** A Redis TTL on `apikey:{hash}` itself. Redis expires
the key, the existing GET returns nil, the key stops working. The lookup is
byte-identical. The price is that an expired key is indistinguishable from an
invalid one in the error text, which is documented rather than paid for with a
second read.

**`last_used` is recorded on the cache MISS only,** where a Redis round trip is
already happening. The 60-second cache bounds it: at most one write per key per
process per minute, regardless of traffic. A key serving 1,000 requests a minute
pays for one of them.

| | |
|---|---|
| Added work per guarded request (cache hit) | none |
| Added work on a cache miss | one Redis SET, fire-and-forget |
| Worst case per key, per process | 1 write / 60s |

Best-effort: a failed `last_used` write is swallowed. Losing a timestamp must
never fail a guarded request, and `SHIELD_API_KEY_TRACK_USAGE=0` disables it
outright for anyone who disagrees with the trade.

**The version this spec refuses:** writing `last_used` per request. It is the
obvious implementation, it is what gets built when nobody writes this paragraph,
and it puts a Redis write on `/guardrails/*` — the exact bottleneck the
throughput work already identified. Stated as a non-option, not a preference.

## 3. Data model

A sidecar, for the same reason as key scopes: the `apikey:{hash}` value stays a
bare tenant id, so `resolve_tenant_by_api_key` is unchanged and there is no
migration.

```
apikey:{sha256}      →  tenant_id          unchanged, gains an optional TTL
apikeyscope:{sha256} →  "runtime"|"admin"  existing
apikeymeta:{sha256}  →  JSON               new

{
  "tenant_id":  "acme",
  "label":      "ci-pipeline",     # free text, so a human can tell keys apart
  "prefix":     "sk-ci-a1b2",      # first 12 chars, for recognition only
  "created_at": 1786...,
  "expires_at": 1786... | null,
  "last_used":  1786... | null
}
```

`prefix` is the one deliberate concession: a list of bare hashes is useless for
deciding which key to revoke. Twelve characters identify a key to someone who
holds it and are not enough to reconstruct it.

**Absent metadata is legal and permanent.** Every key in every deployment
predates this. A key with no record lists with nulls and works forever.

`tenant_id` is duplicated into the metadata so listing does not require
scanning `apikey:*` and reading each value — that scan already exists in
`delete_tenant` and is the pattern to avoid, not follow.

## 4. API / interface

| Route | Purpose |
|---|---|
| `GET /v1/admin/tenants/{tenant_id}/api-keys` | list: prefix, label, scope, created, expires, last used |
| `POST /v1/admin/tenants/{tenant_id}/api-keys` | gains optional `label`, `expires_in_days` |
| `DELETE /v1/admin/tenants/{tenant_id}/api-keys` | unchanged |
| `GET /v1/tenant/me/api-keys` | the same list, for the tenant's own keys |

Listing returns no plaintext and no full hash — prefix and a short fingerprint,
which is enough to match a row to a key someone holds without handing over
anything reusable.

## 5. Security & backward compatibility

**Nothing changes for an existing key.** No metadata means no expiry and no
last-used; the key resolves exactly as it does today. `add_api_key`'s new
arguments default to none.

**Expiry is opt-in per key,** set at mint time. Shield never applies one on its
own — an expiry a tenant chose is a policy; one Shield invented is an outage.

**Listing is an administrative read** and must not become an oracle: an unknown
tenant returns an empty list, exactly like a tenant with no keys, so this cannot
enumerate tenants.

**A revoked key's metadata is deleted with it.** Leaving it behind would list
credentials that no longer exist, which is worse than not listing at all.

### The honest limit

`last_used` has up to 60 seconds of lag and is best-effort. It answers "is this
key idle" — the question that makes revocation safe — and must not be described
as an audit trail. The tamper-evident audit is the audit trail.

## 6. Packaging & deploy

**No new dependency.** No new module: this goes in `storage/tenant_store.py`,
which owns `apikey:*` and is already in the `Dockerfile.admin` COPY list.

| Flag | Default |
|---|---|
| `SHIELD_API_KEY_TRACK_USAGE` | on |

Rebuild both images: the data plane records `last_used`, the admin plane serves
the list.

## 7. Failure modes & edge cases

**Redis down.** Metadata reads return nulls and the list is empty rather than an
error; `last_used` writes are dropped. Authentication is unaffected, because the
value that authenticates is the one that was always there.

**A key minted before this exists.** Nulls throughout. Tested, because it is
every key today.

**An expired key.** `apikey:{hash}` is gone, so authentication fails with
"invalid API key". The metadata survives until revoked, so the list can still
show *why* — that asymmetry is deliberate and is what makes the confusing error
diagnosable.

**The in-memory fallback has no TTL.** So expiry is also checked against
`expires_at` in the metadata when it is present, which is how a Redis-less
deployment honours it at all. Same belt-and-braces as portal sessions.

**Clock skew** between workers can make `last_used` appear to move backwards by
seconds. Not corrected; it is a "roughly when" field.

**Concurrent writes** to the same metadata record can lose a `last_used`
update. Acceptable: the next miss rewrites it.

## 8. Test plan (Definition of Done)

**The guard path** — the load-bearing group
- a cache HIT performs no store operation at all, spied across 50 calls
- a cache miss performs exactly one extra write, not one per request
- with `SHIELD_API_KEY_TRACK_USAGE=0`, no write ever
- a failing `last_used` write does not fail resolution
- `resolve_tenant_by_api_key` returns the same tenant with and without metadata

**Backward compatibility**
- a key with no metadata authenticates and lists with nulls
- `add_api_key(tenant, key)` with no new arguments behaves exactly as before
- existing callers of `add_api_key` are unchanged (there are three)

**Expiry**
- a key past `expires_at` fails to authenticate, via TTL and via the metadata
  check, so the in-memory path is covered
- a key with no expiry never expires
- an expiry in the past at mint time is a 400, not a key that never worked

**Listing**
- no plaintext and no full hash in any response
- an unknown tenant returns an empty list identical to a tenant with none
- a revoked key disappears from the list
- keys are ordered newest first

**Rotation, end to end** — the sequence this exists to enable: mint a second
key, both authenticate, the list shows two with distinct labels, `last_used`
moves on the new one only, revoke the old, the survivor still authenticates.

**Gate** — clean venv green; CI `pytest`; `test_admin_dockerfile_imports`.

## 9. Task breakdown

| # | Scope | Size |
|---|---|---|
| 1 | Metadata storage, `last_used` on cache miss, expiry. Guard-path tests. | medium |
| 2 | Listing endpoints, `label` and `expires_in_days` on minting. | small |
| 3 | Portal: key list with age, expiry and last-used; rotate flow. | medium |
| 4 | Docs: the rotation sequence, and the honest limit on `last_used`. | small |

## 10. Decisions taken

Recorded rather than asked, since the brief was the minimum for enterprise
adoption and each of these has a defensible default:

1. **`last_used` on cache miss, not per request and not derived from
   telemetry.** Per-request is a write on the guard path. Deriving it from the
   audit needs the key hash added to every telemetry record and a scan to read
   it back — more moving parts for a field whose only job is "is this idle".
2. **Expiry via Redis TTL plus a metadata check.** TTL alone would not work on
   the in-memory fallback; the metadata check alone would cost a guard-path read.
3. **A 12-character prefix in listings.** A list of bare hashes cannot be acted
   on. Twelve characters are recognisable and not reconstructable.
4. **No automatic expiry on existing keys.** Ever. Shield inventing an expiry
   for a key a tenant has deployed is an outage with our name on it.
