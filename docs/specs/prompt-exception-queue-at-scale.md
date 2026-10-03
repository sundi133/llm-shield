---
title: "Spec: Exception queue at scale"
layout: default
nav_exclude: true
permalink: /specs/prompt-exception-queue-at-scale/
description: Keep the Exception Requests page fast and usable with hundreds of requests, by indexing requests by status and policy, paging them, and pointing admins at the policy that is producing them.
---

# Spec: Exception queue at scale

> Status: **APPROVED 2026-10-03** (user: "approved"). Task 1 built; task 2 open.
> Builds on: `docs/specs/prompt-exception-requests.md` (approved, shipped in
> #454, #456 and #457).

## 1. Problem & outcome

The Exception Requests page works for a handful of requests. With hundreds:

- **Loading is slow.** The list reads the newest 1,000 request ids and then
  each request one at a time. Production's Redis answers over HTTP, so a few
  hundred reads in a row take seconds. Filtering to "pending" still reads
  everything, because there is one index for all statuses.
- **The nav count costs a full list.** It loads the pending list at every
  portal sign-in.
- **The page is one long column of full cards,** with every prompt open, no
  paging, no search, and no way to deal with fifty requests for one policy
  together.
- **Requests older than the newest 1,000 drop off the page** (they remain in
  the audit log).

**Outcome**

1. The page opens on the oldest pending requests, 25 at a time, as compact
   rows. Opening a row shows the prompt, reason and actions.
2. Admins can filter by policy, user and AI site, and search the prompt,
   reason and user.
3. A **By policy** view shows how many requests each policy has waiting. A
   policy with many is a policy to fix, and the page says so.
4. Admins can deny many requests at once with one note.
5. The nav count, and any page, loads in a few store round trips whatever the
   size of the queue.

**Non-goals**

- **Bulk approve.** Each approval releases one specific prompt. Approving
  dozens unread defeats the review. Approvals stay one at a time.
- **Full-text search over all history.** Search covers the newest 1,000
  requests of the chosen status, and the page says how many it searched.
- Changing what a request, a grant or a decision is. This spec changes how
  requests are stored, listed and shown, not the rules.

## 2. Plane & latency contract

- **Admin + data plane:** the review routes (both planes, as today).
- **Guard path:** one change. When a grant is redeemed on `/guardrails/input`,
  the request moves from the "approved" index to the "used" index: two more
  store operations, only on an approved resend, which already does about six.
  Nothing changes for any other request.
- Creating a request (`POST /v1/shield/exceptions`) adds it to two or three
  indexes. That route is not on the guard path.

## 3. Data model

New keys, beside the existing ones:

| Key | Value | Notes |
|---|---|---|
| `prompt_exc_st:{tenant}:{status}` | sorted set of request ids | One per status: pending, approved, used, denied, expired. **Score is the request's `expires_at`**, so the live pending count is one `ZCOUNT` from now, with no sweep needed |
| `prompt_exc_pol:{tenant}:{policy_key}` | sorted set of pending request ids, score `expires_at` | One per policy that has blocked a requested prompt. `policy_key` is a hash of guardrail and policy id (or name) |
| `prompt_exc_pols:{tenant}` | hash `policy_key -> {guardrail, policy, policy_id}` | The policies the By policy view lists |

- **Transitions move an id between indexes:** created (into pending and its
  policies' sets), approved or denied (out of pending and the policy sets),
  used, expired. A request blocked by two policies is in both policy sets.
- **Expiry needs no job.** A pending id whose score is in the past is expired.
  Counts use `ZCOUNT(now, +inf)`. Expired ids are moved to the expired index
  when a page touches them.
- **Batch reads.** A page of 25 is read with one `MGET` (both the Upstash and
  redis-py clients have it), not 25 calls.
- **Retention.** Decided indexes keep the newest 5,000 ids each. An id whose
  record has expired (7 days after its request expired) is skipped and removed
  when a page meets it.
- **Migration.** The first list call for a tenant without the new indexes
  builds them from the existing `prompt_exc_idx`. No downtime and nothing to
  run by hand. `prompt_exc_idx` stays, for the "All" view.

Tenant scoping is unchanged: every key starts with the tenant from the API
key.

## 4. API / interface

All under `/v1/tenant/me/exceptions`, both planes, tenant key, as today.

**List:** `GET /v1/tenant/me/exceptions`

| Parameter | Meaning |
|---|---|
| `status` | pending (default), approved, used, denied, expired, all |
| `policy` | a `policy_key` from the counts |
| `user`, `destination` | exact match |
| `q` | text search: prompt, reason, user, device, site (case-insensitive) |
| `limit` | 1 to 100, default 25 |
| `cursor` | from the previous page |

Returns `{requests, next_cursor, total}`. With `user`, `destination` or `q`,
Shield reads the status index in batches of 100 up to the newest 1,000 and
adds `searched` (how many it looked at) so the page can say "searched the
newest 1,000". Pending is oldest first; the other statuses newest first.

**Counts:** `GET /v1/tenant/me/exceptions/counts` returns
`{pending, approved, used, denied, expired, by_policy: [{policy_key,
guardrail, policy, pending, requested, approved, false_positive}]}`. The nav
item and the By policy view use this, not the list.

**Bulk deny:** `POST /v1/tenant/me/exceptions/deny` with
`{request_ids: [...], reason}`, up to 100 ids, a reason required. Each request
is decided exactly as a single deny is: own audit row, own
`exception_decided` webhook, first decision stands. Returns
`{denied: [...], skipped: [{request_id, status}]}`.

Single approve and deny are unchanged.

### Portal

- **Status tabs with counts** (Pending 37, Approved 4, ...) replace the
  dropdown.
- **Compact rows:** user, AI site, policy, age, the first line of the reason,
  and a checkbox. Clicking a row opens the prompt, the reason in full, and
  Approve once, Deny and "policy was wrong".
- **25 per page** with "Load more".
- **Filters:** policy (from the counts), user, AI site, and a search box.
- **By policy first when it matters:** if one policy has 10 or more pending
  requests, the page leads with "37 waiting for 'pricing confidential data
  policy'. Many requests for one policy usually mean the policy needs
  rewording." with links to filter by it and to open the policy.
- **Bulk deny:** select rows (or "select all on this page"), "Deny selected",
  one required note.
- **Cleaner "Blocked by" text:** the policy's own reason, without the
  "1 custom input policy violation(s). Worst: ..." wrapper (the extension
  already strips it).

## 5. Security & backward compatibility

- No change to who can see or decide requests, or to what a decision does.
- Bulk deny can only deny. It is limited to 100 per call, needs a reason, and
  writes one audit row per request.
- The migration only reads existing records and writes indexes. If it fails,
  the list falls back to today's behaviour.
- The single-request routes and response shapes are unchanged. The list route
  gains fields and parameters; the default (no parameters) now returns 25
  pending requests oldest first, where it returned up to 100 newest first. The
  portal is the only caller; the API change is noted in the docs.

## 6. Packaging & deploy

- Changes in `core/prompt_exceptions.py` (including the index move on
  redemption, which happens there), `api/routes_exception_review.py` and
  `static/tenant.html`. The list response keeps `by_policy` (the all-time
  counters) so the current page works until task 2 replaces it. No new module, so no `Dockerfile.admin` change.
- No new dependency, no new environment variable.
- Rebuild both planes.

## 7. Failure modes & edge cases

| Case | Behaviour |
|---|---|
| An index and a record disagree (a write failed between them) | The record wins: a page skips an id whose record says another status, and moves it to the right index |
| A pending request expires while nobody looks | Not counted as pending (score in the past); moved to expired when a page touches it |
| A record has expired but its id is still indexed | Skipped and removed when met |
| Bulk deny with ids already decided, or from another tenant | Skipped, listed under `skipped`; another tenant's ids look like unknown ids |
| Search over a status with more than 1,000 requests | Searches the newest 1,000 and says so |
| Two admins deny overlapping selections | First decision stands; the second gets them under `skipped` |
| Migration runs on two planes at once | Index writes are idempotent (`ZADD` of the same id and score) |
| Redis unreachable | The page shows the error; nothing is decided |

## 8. Test plan (Definition of Done)

- Every transition puts the id in exactly the right status and policy indexes,
  including approve, deny, redemption on the guard path, and expiry.
- Pending count is correct with expired ids still in the index.
- Paging: 60 pending requests, three pages of 25, 25 and 10, oldest first, no
  repeats, stable when a request is decided between pages.
- A page of 25 is one batch read (assert the number of store calls).
- Filters by policy, user and site; search over prompt, reason and user; the
  `searched` cap.
- Bulk deny: up to 100, reason required, skipped ids reported, one audit row
  and one webhook per request.
- Migration from the old index; idempotent when run twice.
- Index and record disagreement is repaired by the record.
- Portal wiring test (element ids, routes) and escaping of everything users
  typed.
- A load check: 500 requests in the fake store, the pending page and the
  counts each take a fixed small number of store calls.
- Full suite green in a clean venv; CI `pytest` gate passes.

## Tasks

One branch, one PR.

1. **Server:** status and policy indexes, transitions (including the guard-path
   move on redemption), batch reads, paging, filters, search, counts, bulk
   deny, migration.
2. **Portal:** status tabs with counts, compact rows with an expanding detail,
   paging, filters and search, the By policy lead, bulk deny, cleaner "Blocked
   by" text; the nav count from the counts route.
