---
title: "Spec: non-fakeable HITL approval and break-glass"
layout: default
nav_exclude: true
permalink: /spec-hitl-breakglass/
description: "Draft spec for human approval that an agent cannot forge."
---

# Spec: Non-fakeable Human-in-the-Loop approval + break-glass

Status: **DRAFT — for approval.** Spec-first per `CLAUDE.md`; no code until sign-off.

## 1. Problem & outcome

Shield has the *bones* of HITL but the security-critical link is fakeable:

- `sensitive_action_confirmation` issues an **in-memory, cleartext** token
  (`sha256(...)[:16]`, `guardrails/agentic/tool/sensitive_action_confirmation.py`).
  Anyone who holds the token passes the gate; there is no human routing, no
  signing, no record of who approved.
- The control-plane approval store is real (`create/consume_approval_request`,
  `storage/agentic_control_plane.py`) and there are human approve/deny endpoints
  (`api/routes_agentic_control_plane.py`), **but** the approver is a
  **caller-asserted string** (`body.approver`) with no authenticated identity, and
  "approved" is a plain Redis status flag — forgeable by anyone with Redis/backup
  access.
- `POST /v1/shield/cap/mint` has **no approval gate**: a high-risk tool cap is
  minted with no human in the loop; `scope_constraints` is unused for approvals.
- There is no notify/wait: the agent gets `pending_confirmation` and must poll; the
  human is never told a request is waiting.

**Outcome:** a high-risk action cannot execute unless an **authenticated human**
issued a **cryptographically signed, single-use approval grant** bound to the exact
`(tool, resource, params, agent instance, session)` — verifiable on the guard path
like a capability, non-repudiable, and audited. Plus a **controlled break-glass**
path: a deliberately loud, time-boxed, elevated-auth emergency override (and its
mirror, emergency deny via existing revocation).

**Non-goals.** Not a UI (portal wires to these APIs). Not approval for every tool —
opt-in per tool. Not a replacement for RBAC — this is an *additional* gate on top of
`tool/check` + `cap/mint`.

## 2. Plane & latency contract

- **Guard path:** the approval **verify** is presented by the caller (a signed
  grant) and checked at `tool/check` / `cap/mint` — one Ed25519 verify + one nonce
  check, identical cost profile to `cap/verify` (~microseconds, no extra network).
  Approval-required is **opt-in per tool**, so tools without it pay **+0**.
- **Off hot path:** approval *creation*, human *decision*, listing, notify, and
  break-glass issuance run on the admin/control plane — never in the guarded
  request.

## 3. Data model

**Approval request** (exists — extend, don't replace): add `params_hash =
sha256(canonical(tool_params))` and `requested_clearance`. Keep `required_approvals`
(quorum), `single_use`, `expires_at`.

**NEW — signed approval grant** (issued when quorum of authenticated humans
approve). Ed25519 (reuse the existing signer from `core/capabilities.py` /
`core/agent_tokens.py` — **no new key, no new dep**). Claims:
```
{ iss:"shield", aud:"shield-approvals",
  tenant_id, agent_id, agent_instance_id, session_id,
  tool, resource, params_hash,          # binds the grant to the exact action
  approvers:[{sub, method, at}],         # authenticated human identities
  request_id, grant_id, nonce,           # single-use (nonce burned on consume)
  iat, exp }                             # short TTL, e.g. ≤300s
```
Stored: `approval:grant:{tenant}:{grant_id}`; nonce burn set
`approval:nonce:{tenant}:{nonce}`. Break-glass grants use `aud:"shield-breakglass"`
with `breakglass:true`, `reason`, `authorized_by` (admin identity), shorter TTL.

**Approver identity (the core fix):** the approve endpoint must derive the approver
from an **authenticated session** (SSO/OIDC/portal login or a signed approver
token), not from a request-body string. `approvers[].sub` is the verified identity;
`method` records how (oidc/portal/mtls).

Tenant scoping: all keys `:{tenant}`-prefixed; approver must belong to the tenant.

## 4. API / interface

- `GET  /v1/tenant/me/agentic/approvals?status=pending` — **humans discover** waiting
  requests (missing today). Auth: tenant session/key.
- `POST /v1/tenant/me/agentic/approvals/{request_id}/approve|deny` — **existing**;
  change: derive approver from the authenticated principal (reject unauthenticated /
  body-asserted approver); on reaching quorum, **issue the signed grant** and return
  it (and fire a webhook `approval_granted`).
- `GET  /v1/tenant/me/agentic/approvals/{request_id}` — caller/agent **polls**
  status; returns the grant once approved.
- **Guard-path gate:** at `POST /v1/shield/cap/mint` (and `tool/check` for the
  cooperative path), if the tool is `approval_required`, require a valid signed
  approval grant matching `(tool, resource, params_hash, instance, session)`;
  else return `403`/`pending_confirmation` with the `request_id`. Burn the nonce on
  mint so a grant is single-use.
- `POST /v1/shield/breakglass` — **elevated** (admin key + `reason`, rate-limited,
  alerted): issue a time-boxed break-glass grant. Mirror: emergency **deny** uses
  the existing `POST …/auth/revoke` (instance/jti/user).
- Notify: reuse the **existing webhook** infra — new events `approval_requested`,
  `approval_granted`, `breakglass_used`.

Deprecate the cleartext `sensitive_action_confirmation` token for *security* use
(keep only as optional non-security "are-you-sure" UX), documented as non-binding.

## 5. Security & backward compatibility

- **Opt-in, non-breaking.** A tool gates on approval only if its policy sets
  `approval_required` (or clearance ≥ threshold). Tools without it are unchanged.
  Global escape hatch `SHIELD_HITL_ENFORCE=0` to disable enforcement in an
  emergency (documented; distinct from per-tool config).
- **Non-fakeable:** approval is an Ed25519 grant bound to the action + authenticated
  approver, verified on the guard path — a Redis/backup attacker can't forge it
  (no private key), and a caller can't self-assert an approver. Replaces the
  forgeable status-flag + cleartext token.
- **Non-repudiation:** `approvers[].sub` are verified identities, written to the
  (soon tamper-evident, `spec-tamper-evident-audit.md`) audit log.
- **Break-glass is loud by design:** elevated auth, mandatory reason, short TTL,
  rate-limited, emits `breakglass_used` webhook + high-severity SIEM event; every
  use is audited. It's an escape hatch that can't be used quietly.
- **What it can't do:** stop a legitimate approver from approving a bad action
  (that's policy/segregation-of-duties — quorum `required_approvals ≥ 2` mitigates).

## 6. Packaging & deploy

- **New module** `core/approvals.py` (sign/verify grants). If `admin_app.py` imports
  it (it will — approve/issue on the admin plane) → **add to `Dockerfile.admin`
  COPY** (guarded by `tests/test_admin_dockerfile_imports.py`). Flagged.
- **No new pip dep** — reuse the Ed25519 signer already present + `hashlib`; reuse
  existing webhook + revocation modules.
- **Env flags:** `SHIELD_HITL_ENFORCE` (default on once a tool opts in),
  `SHIELD_APPROVAL_GRANT_TTL` (default 300s), `SHIELD_BREAKGLASS_TTL` (default 900s),
  `SHIELD_BREAKGLASS_RATE`. Rebuild: data-plane (mint/verify gate) + admin (issue).

## 7. Failure modes & edge cases

- **Approver spoofing (today's bug):** fixed — approver from authenticated principal,
  reject body-asserted `approver`.
- **Grant replay:** nonce burned on consume; second mint fails.
- **Wrong params / TOCTOU:** grant binds `params_hash`; if the agent changes params
  after approval, verify fails.
- **Redis down:** approval store unreachable ⇒ approval-required tools **fail closed**
  (block), with break-glass as the sanctioned override.
- **Quorum & expiry:** `required_approvals` honored; expired request → new one; grant
  TTL short so a stale grant can't be hoarded.
- **Break-glass abuse:** rate-limited + alerted + short TTL + full audit; requires
  admin identity, not the agent's.
- **Clock skew:** ±5s tolerance like tokens; integrity is signature+nonce based.

## 8. Test plan (Definition of Done)

- **Unit:** approve reaching quorum issues a valid grant; grant verifies at
  `cap/mint`; mismatched `params_hash`/tool/instance/session → reject; replay (reuse
  nonce) → reject; unauthenticated/body-asserted approver → reject; deny → no grant;
  Redis-down → fail closed; break-glass issues elevated grant, burns rate limit,
  emits webhook; disabling `SHIELD_HITL_ENFORCE` restores prior behavior; cleartext
  `sensitive_action_confirmation` no longer satisfies a security-gated tool.
- **Regression guard:** `test_admin_dockerfile_imports.py` covers the new admin
  import; a test pins the grant canonicalization/claims.
- **Clean venv:** full `pytest tests -q` green; CI `pytest` gate passes.

## Invariant risk flags
- ⚠️ **Hot path** — mitigated: one signature verify + nonce check at `cap/mint`,
  opt-in per tool, +0 for non-gated tools.
- ⚠️ **Admin import** — `core/approvals.py` → add to `Dockerfile.admin`.
- ⚠️ **Behavior change** — only for tools that opt into `approval_required`; global
  escape hatch `SHIELD_HITL_ENFORCE=0`; migration note.
- ✅ No new pip dep (reuse Ed25519 signer, webhook, revocation).

## Task breakdown (one branch, ordered)
1. `core/approvals.py` — sign/verify approval grant + nonce burn + unit tests
   (signer + fakeredis). Not wired to endpoints yet.
2. Authenticated approver on approve/deny + issue signed grant on quorum + list-
   pending + poll endpoints + webhook events.
3. Gate `cap/mint` (and `tool/check`) on the grant for `approval_required` tools;
   deprecate cleartext confirmation for security; `Dockerfile.admin` + docs.
4. `POST /v1/shield/breakglass` (elevated, rate-limited, alerted) + audit wiring.

## Open questions (for approval)
1. **Default quorum** for approval-required tools — 1 approver, or 2 (segregation of
   duties) for the highest clearance?
2. **Approver identity source** — portal SSO session only, or also accept a signed
   "approver token" so external systems (ServiceNow/Slack approval) can approve?
3. **Gate location** — enforce the grant at `cap/mint` only (L3, non-bypassable), or
   also at cooperative `tool/check` (defense in depth for non-cap integrations)?
   Recommend both.
