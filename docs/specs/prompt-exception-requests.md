---
title: "Spec: Prompt exception requests"
layout: default
nav_exclude: true
permalink: /specs/prompt-exception-requests/
description: A user whose prompt was blocked can ask for an exception. An admin approves it once with a signed, single-use grant bound to that exact prompt, or a larger model overturns a wrong block automatically.
---

# Spec: Prompt exception requests

> Status: **APPROVED 2026-10-02** (user: "approved"). Tasks 1 to 5 built; task 6 open.
> Builds on: `docs/spec-hitl-breakglass.md` (signed approval grants and the
> approval queue, shipped), the browser extension
> (`examples/browser-extension`), `/guardrails/input`.

## 0. The two cases, and why they need different answers

A blocked prompt is one of two things:

1. **The guardrail was wrong** (a false positive). Nobody should have to wait
   for a human. A second look by a larger model can fix it in seconds.
2. **The guardrail was right, but the user is authorised** (sharing a margin
   with a partner under NDA). That is a business decision. A model must not
   make it; a person must.

So the flow has tiers. This spec builds tier 3 first, because it covers both
cases and reuses the most existing code, then tier 2.

| Tier | Decides | Wait | For |
|---|---|---|---|
| 1. Give a reason | the user | none | exists on the device agent ("justify"); unchanged here |
| 2. Second opinion | a larger model | seconds | blocks that came from a model's judgement (task 6, opt-in) |
| 3. Exception request | an admin | minutes to hours | everything appealable (tasks 2 to 5) |
| 4. Not appealable | nobody at request time | n/a | guardrails the tenant marks as hard rules |

## 1. Problem & outcome

**Today:** the extension shows "Blocked by Shield: custom_policy_input" and
the user is stuck. They cannot tell what was wrong, cannot ask for a review,
and the admin never learns the policy misfired. The usual result is the user
moving to a personal device.

**Outcome**

1. The block banner says which policy blocked the prompt and why, and has a
   **Request exception** button.
2. The user adds a reason and submits. The request appears in the portal with
   the prompt, the reason, the user, the device and the policy that blocked it.
   Admins are notified by webhook.
3. An admin approves or denies. Approval issues a signed, single-use grant
   bound to that exact prompt, user and destination.
4. The extension shows "Approved. Send again." The resend carries the grant,
   and Shield lets that prompt through once.
5. Every request and decision is audited, and each policy shows how often its
   blocks were overturned.

**Non-goals (v1)**

- File attachments. Prompts only.
- The device agent's local decisions. Its prompts never leave the laptop, and
  it already has "justify". Exception requests are for the path where the
  extension or an API client screens against Shield.
- Standing exemptions ("this user is exempt"). Every approval is for one
  prompt, once.
- "Approve and change the policy" in one click. An approver who thinks the
  policy is wrong marks the request as a false positive; editing the policy
  stays a separate, deliberate act.
- Tool calls. Those already have approvals (`docs/hitl-approvals.md`).

## 2. Plane & latency contract

- **Data plane:** create and poll a request (`/v1/shield/exceptions`), and
  honour a grant on `/guardrails/input`.
- **Admin + data plane:** the review queue (`/v1/tenant/me/exceptions`), like
  the other tenant APIs.
- **Guard path: `/guardrails/input` is touched, minimally.**
  - A request without the grant header pays one header lookup. Nothing else
    changes.
  - A request with the header pays the grant check only when the pipeline's
    verdict is a block: an Ed25519 signature check, then about six store
    operations (settings, two revocation checks, the request, the single-use
    marker, the request's new status). The pipeline always runs in full first;
    a grant never skips screening.
  - Budget: under 1 ms added without a grant. With one, a handful of store
    round trips, once per approved request.
- Creating a request re-screens the prompt once (§4.1). That is a pipeline run
  on a request the user is waiting on anyway, not on the inline guard call, and
  it is rate-limited.

## 3. Data model

| Redis key | Value | TTL |
|---|---|---|
| `prompt_exc:{tenant}:{request_id}` | the request (below) | `request_ttl_s` + 7 days |
| `prompt_exc_idx:{tenant}` | sorted set of `request_id` by `created_at` | trimmed with the requests |
| `prompt_exc_user:{tenant}:{user_hash}` | this user's open request ids, for the per-user limit and for finding a duplicate | 7 days |
| `prompt_exc_fp:{tenant}` | one hash of counters per guardrail and policy: `requested`, `approved`, `false_positive` | none |
| `prompt_exc_settings:{tenant}` | the tenant's settings | none |
| `prompt_exc_block:{tenant}:{user_hash}:{destination_hash}:{sha256}` | `{at, blocked_by}`: what blocked this prompt, written by `/guardrails/input` in the background | 1 hour |

Request record:

```
request_id, tenant_id, status (pending | approved | denied | expired | used),
created_at, expires_at, decided_at,
user_id, device_id, destination,
prompt_sha256, prompt (up to 4000 characters), prompt_len,
reason (up to 500 characters),
blocked_by: [{guardrail, policy, message}],     # from the server's own re-screen
decision: {approver, method, reason, false_positive},
grant_id
```

- **The prompt text is stored.** A reviewer cannot judge a prompt they cannot
  read. It is kept until the request's TTL ends, then gone. The extension tells
  the user before they submit that reviewers will see the prompt.
- **Tenant scoping:** keys are prefixed by the tenant resolved from the API
  key. A request id from another tenant is a 404.
- Tenant settings have their own key and their own routes
  (`GET` and `PUT /v1/tenant/me/exceptions/settings`), not the agentic
  control-plane config: a `PUT` there replaces every section it is not given,
  so a settings change here could have reset a tenant's tool approval rules.

```json
{"enabled": false, "non_appealable": [], "request_ttl_s": 86400,
 "grant_ttl_s": 900, "max_pending_per_user": 3, "auto_review": false}
```

  A request's status is decided by the deadline stored in the request, never
  by a Redis expiry.

## 4. API / interface

### 4.1 Request an exception (data plane)

`POST /v1/shield/exceptions`, tenant key, `X-Agent-Key` (user) and
`X-Device-Id` as the extension already sends.

```json
{"prompt": "...", "destination": "chatgpt.com", "reason": "Partner is under NDA"}
```

What blocked the prompt is always Shield's finding, never the caller's. When
`/guardrails/input` blocks a prompt it records, in the background, what blocked
it for that tenant, user, destination and prompt hash, for an hour
(`prompt_exc_block:*`). A request uses that record. Only without one does Shield
screen the prompt again. This matters for policies judged by a model: they can
block a prompt and pass the same prompt a moment later, and a request that
relied on a second screen was refused as "no longer blocked" (found in the
first production test, 2026-10-02).

| Result | Status |
|---|---|
| Created | 201 `{request_id, status: "pending", expires_at, blocked_by}` |
| Same user, same prompt, already pending | 200 with the existing request |
| The prompt is not blocked now | 409 `not_blocked` (the policy changed; just resend) |
| Blocked by a non-appealable guardrail | 403 `not_appealable`, naming it |
| Too many pending requests for this user | 429 |
| Feature off for the tenant, or no signing key | 404 / 503 |

### 4.2 Poll (data plane)

`GET /v1/shield/exceptions/{request_id}` returns `status` and, once approved,
`grant` (the signed token) and `approver`. Only the same tenant key with the
same `X-Agent-Key` may read it.

### 4.3 Review (both planes)

- `GET /v1/tenant/me/exceptions?status=pending`
- `POST /v1/tenant/me/exceptions/{id}/approve` `{reason, false_positive}`
- `POST /v1/tenant/me/exceptions/{id}/deny` `{reason}`

Approval records the decision. The grant is minted by the data plane when the
requester polls an approved request, so its short lifetime (`grant_ttl_s`)
starts when they are there to use it, not when the reviewer clicked. It uses
the existing `core.approvals.mint_grant`: `tool = "prompt_exception"`,
`resource = "prompt:<sha256>@<destination>"`, `agent_id = <user_id>`, the
approver's identity, and a hash of the guardrails it may waive. Each poll mints
a fresh grant; the request can still be redeemed only once, because redeeming
claims a per-request marker atomically. Writes go through the registry write
gate; the approver must not be the requester; the first decision stands (a
second gets 409).

### 4.4 Using the grant (guard path)

The resend adds `X-Shield-Exception-Grant: <token>` to `/guardrails/input`.

After the pipeline has run, and only if its verdict is a block:

1. Verify the signature, audience, expiry and tenant.
2. Check the grant's resource equals the SHA-256 of this exact message and
   this destination, and its `agent_id` equals this caller's user id.
3. Check every guardrail that failed now is in the request's `blocked_by` and
   none is non-appealable.
4. Claim the request's single-use marker.

Nothing is spent until every check has passed, so a resend that does not match
leaves the approval usable. If all four pass, the response is `safe: true`, `action: "pass"`, with the
failed results kept and marked `exception_granted`, an `exception` object
naming the request and approver, and the request becomes `used`. If any fails,
the block stands and the response carries `exception_error` with the reason
(`grant_mismatch`, `grant_expired`, `grant_used`, `grant_invalid`,
`new_violation`, `not_appealable`, `exceptions_disabled`,
`store_unavailable`).

The prompt hash is over the text after Unicode NFC normalisation and trimming
outer whitespace, so the user must resend the same prompt.

### 4.5 Notification

A webhook event `exception_requested` (and `exception_decided`) through the
existing webhook delivery, with the request id, user, policy and a link to the
portal. Never the prompt text.

### 4.6 Extension

- Banner: the policy's name and message instead of the guardrail's internal
  name.
- **Request exception** opens a small form: a reason, and the notice that
  reviewers will see the prompt.
- A pending request is remembered per tab and polled every 30 seconds while
  the tab is open. The banner then shows approved, denied (with the reviewer's
  reason) or expired.
- On approval, the next send of the same prompt attaches the grant.

## 5. Security & backward compatibility

- **Opt-in.** `exceptions.enabled` defaults to false. With it off, no route
  accepts requests and the grant header is ignored. No existing default
  changes.
- **The grant cannot be forged or reused.** It is the same signed,
  single-use, short-lived token tool approvals use, with its own resource
  namespace. A grant for one prompt does nothing for another, for another
  user, or for another destination.
- **A grant never widens.** If the same prompt now also fails a guardrail it
  did not fail when requested, the block stands.
- **Hard rules stay hard.** Guardrails in `non_appealable` cannot be requested
  or waived.
- **The reviewer model (tier 2) cannot be argued with.** It sees the policy
  text and the prompt. The user's reason is never given to it.
- **Abuse.** Per-user pending limit, request expiry, requester cannot approve,
  and every request and decision is in the admin audit log.
- **What a malicious caller can do:** with a tenant key, create requests up to
  the rate limit for prompts that really are blocked. Nothing is released
  without an approver.

## 6. Packaging & deploy

- New modules `core/prompt_exceptions.py` (store, hashing, grant check),
  `api/routes_exceptions.py` (ask and poll, data plane only, because asking
  runs the screening pipeline) and `api/routes_exception_review.py` (settings
  and review, both planes). `admin_app.py` mounts the review module, so it and
  `core/prompt_exceptions.py` are in `Dockerfile.admin`'s COPY list; the two
  admin image tests enforce it.
- No new pip dependency.
- Requires `SHIELD_APPROVAL_TOKEN_PRIVATE_KEY` on both planes (already needed
  for tool approvals).
- Tier 2 only: `SHIELD_EXCEPTION_REVIEW_MODEL` and its endpoint, data plane.
- Extension version 1.3.0: repack the self-hosted package and update the
  store listing.
- Rebuild both images.

## 7. Failure modes & edge cases

| Case | Behaviour |
|---|---|
| Grant for a different prompt, user or destination | Ignored; the block stands; recorded as `grant_mismatch` |
| Grant expired before the resend | Block stands; the extension offers to request again |
| Grant already used | Block stands |
| Redis down when burning the nonce | **Fail closed:** the block stands. A grant that cannot be marked used could be replayed |
| Redis down when creating a request | 503; the block itself is unaffected |
| User edits the prompt after approval | Different hash: block stands. The banner says the approval was for the original text |
| Policy changed between request and approval | The grant only waives what blocked it at request time; a new failure still blocks |
| Tenant in monitor mode | Nothing is blocked, so nothing can be requested (409 `not_blocked`) |
| Prompt longer than 4000 characters | Stored truncated; the hash covers the whole prompt; the reviewer sees the truncation notice |
| Two approvers act at once | First decision wins; the second gets the decided record |
| Approver is the requester | 403 |
| Request never answered | `expired` after `request_ttl_s`; the user is told |

## 8. Test plan (Definition of Done)

- Create: blocked prompt creates a request with the server's `blocked_by`;
  unblocked prompt is 409; non-appealable is 403; duplicate returns the same
  request; the per-user limit is 429; feature off is 404.
- Poll: only the requester reads it; another tenant gets 404.
- Approve and deny: status changes, grant minted with the right claims,
  requester cannot approve, write gate enforced, admin audit rows written.
- Guard path: a valid grant turns a block into a pass exactly once; then
  every row of §7 (wrong prompt, wrong user, wrong destination, expired, used,
  new failure, non-appealable, Redis down).
- No grant header: `/guardrails/input` responses are byte-identical to today
  (existing tests unchanged).
- Webhook events carry no prompt text.
- Counters: requested, approved and false-positive per policy.
- Extension unit tests: banner text, request, polling, resend with grant.
- Admin image import guard; full suite green in a clean venv; CI `pytest`
  gate passes.

## Tasks

One branch, one PR, in this order.

1. **Better block message in the extension:** policy name and reason. Useful
   on its own.
2. **Requests:** store, create and poll routes, tenant settings, limits,
   webhook events.
3. **Review and grant:** approve and deny routes, grant minting, the grant
   check on `/guardrails/input`.
4. **Portal:** the review queue with approve, deny and false-positive.
5. **Extension:** request form, status, resend with the grant; version 1.3.0.
6. **Second opinion (opt-in), after there is data from tasks 2 to 5:** on
   create, a larger model reviews blocks that came from model-judged
   guardrails; an overturn issues the grant at once with the approver recorded
   as the model.
