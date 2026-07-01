---
title: "Spec: A2A Inter-Agent Enforcement"
layout: default
nav_exclude: true
permalink: /specs/a2a-inter-agent-enforcement/
description: Close the A2A enforcement bypass — route /a2a/tasks/send through delegation_control + RBAC + identity, plus inter-agent message signatures. Targets OWASP Agentic T12/T13/T14.
---

# Spec: A2A Inter-Agent Enforcement

> Status: **DRAFT — awaiting approval.** No feature code until approved.
> Closes OWASP Agentic **T12** (Agent Communication Poisoning), **T13** (Rogue
> Agents in MAS), **T14** (Human Attacks on MAS). Source: gap analysis vs.
> *State of Agentic AI Security and Governance v1.0* (roadmap item #1).

## 1. Problem & outcome

**Problem.** `/a2a/tasks/send` ([api/routes_a2a.py:71](../../api/routes_a2a.py))
runs **only input/output content guardrails** (`_run_input_guardrails`). It does
**not** invoke the agentic authorization guards that protect the REST and MCP
paths — `delegation_control`, `rbac_guard`, `cert_identity`. An agent reaching
Shield over A2A can therefore perform delegations and actions that
`/v1/shield/tool/check` and `/v1/shield/agent/check` would block. This is an
**enforcement bypass of guards that already exist**, not a missing control.

The same path also accepts a fully **unauthenticated-at-the-agent-level**
message: identity is only the tenant (API key / OAuth), so any caller holding a
tenant key can impersonate any agent by putting a `from_agent` in metadata.
There is no proof the message came from the agent it claims.

**Outcome (observable success).**
1. With enforcement enabled, an A2A task whose caller→target delegation violates
   depth/cycle/clearance rules, or whose role may not reach the target tool, is
   **rejected** (`TaskStatus.FAILED`, guardrail reason) — matching the verdict
   the REST path would give for the same `(agent_key, delegate_to, tenant_id)`.
2. A `from_agent` that disagrees with the authenticated/ signed identity is
   **rejected as impersonation** (mirrors the existing `X-Agent-Key` vs body
   reconciliation, deep-rbac-009).
3. Every A2A authorization decision is written to the decision audit with the
   deciding guard + reason (same record shape as `/agent/check`).
4. **Default behavior is unchanged** until a tenant opts in (flag below).

**Non-goals.**
- Not building a new approval/HITL workflow (that is roadmap #4, separate spec).
- Not adding tamper-evident audit hash-chaining (roadmap #3, separate spec).
- Not changing the A2A *content* guardrails or the task data model.
- Cross-vendor public-key distribution beyond the agent card (kept minimal; see
  §4 Task 3).

## 2. Plane & latency contract

- **Plane:** Data plane (`core/app.py:146`) **and** admin plane
  (`admin_app.py:1115`) — `routes_a2a` is mounted on both.
- **Touches the guard path?** Yes — `/a2a/tasks/send` is request-path on the
  data plane. **Latency budget justification:** the three reused guards are all
  `tier="fast"` (deterministic, Redis/registry lookups, **no vLLM call**):
  `delegation_control`, `rbac_guard`, `cert_identity` each report sub-/low-ms
  `latency_ms`. Ed25519 verify (Task 3) is ~tens of µs. Net added latency is a
  few fast-tier lookups — same order as the existing `/tool/check` chain. **No
  new model inference is introduced on the A2A path.**
- A2A is **not** one of the named hot paths (`/guardrails/*`, `cap/mint`,
  `tools/call`); this change does not touch those.

## 3. Data model

Reuses existing keys — **no new persistent schema** for Tasks 1–2.

| Key | Shape | TTL | Owner |
|---|---|---|---|
| `delegation:{session_id}:chain` | `list[agent_key]` | 3600s | `agentic_state` (existing, reused) |
| `agents:{tenant_id}` | `{agent_key: {role_permissions, status, ...}}` | — | registry (existing) |
| `shield:a2a:task:{task_id}` | A2ATask JSON | 86400s | A2A task store (existing) |
| `decisions:{tenant_id}` / `decisions:global` | decision audit JSON list | TTL | `storage.decision_audit` (existing) |

- **session_id mapping:** for a continuing task, `session_id = task_id`; for a
  new task, a fresh `session_id` is minted so the delegation chain is scoped to
  one A2A conversation. Stored in `task.metadata["session_id"]` so subsequent
  messages reuse the same chain.
- **Tenant scoping:** unchanged — `resolve_request_tenant_id(request)` already
  gates every task endpoint; all reused keys are tenant-scoped. No cross-tenant
  read is introduced.

**Task 3 only** adds agent public keys for signature verification:

| Key | Shape | Notes |
|---|---|---|
| agent registry entry gains `public_key` (Ed25519, base64) | string | published in the agent card; used to verify `metadata.signature` |

## 4. API / interface

No new endpoints. Behavior is added to the **existing** `/a2a/tasks/send`.

**Request additions (optional, backward-compatible):**
```jsonc
"params": {
  "message": { ... },                 // unchanged
  "metadata": {
    "from_agent": "agent-key",         // claimed caller identity (Task 2 reconciles)
    "to_agent":   "target-agent-key",  // delegation target (delegate_to)
    "user_role":  "manager",           // role for RBAC resolution
    "signature":  "base64-ed25519",    // Task 3: signature over canonical message
    "session_id": "..."                // optional; else derived from task_id
  }
}
```

**Response (unchanged shape).** On block, the existing rejection envelope is
returned (`status.state = FAILED`, artifact text = `Blocked by guardrails:
<reason>`), so existing A2A clients parse it identically.

**Auth header(s):** unchanged — `X-API-Key` (tenant) or OAuth Bearer. Agent-level
identity comes from `from_agent` (Task 2, reconciled) and, in Task 3, the
signature.

**Mount:** both planes already include `a2a_router`; no router changes.

## 5. Security & backward compatibility

**Default behavior:** **OFF — non-breaking.** New escape-hatch flag:

| Flag | Values | Default | Effect |
|---|---|---|---|
| `SHIELD_A2A_ENFORCE` | `off` \| `monitor` \| `on` | `off` | `off`=current behavior (content guards only); `monitor`=run authz guards, **log would-block to decision audit but allow**; `on`=enforce (reject on block) |
| `SHIELD_A2A_REQUIRE_SIGNATURE` | `0`\|`1` | `0` | Task 3: when `1`, an unsigned/invalid-signature message is rejected |

- **Migration note (shipped with the change):** to move from `off`→`on`, a tenant
  must (a) register the calling agents in the registry with `role_permissions`,
  (b) send `from_agent`/`to_agent`/`user_role` in metadata, and (Task 3) (c)
  publish each agent's `public_key` and sign messages. Recommended rollout:
  `monitor` for one cycle, review the decision audit for would-blocks, then `on`.
  This mirrors the Policy Lifecycle monitor→enforce pattern.
- **Authz — what a malicious caller can/can't do:** with `on`, a caller holding a
  tenant key can no longer (1) impersonate another agent (`from_agent`
  reconciliation), (2) delegate past depth/cycle/clearance limits
  (`delegation_control`), (3) reach a tool/scope its role is denied (`rbac_guard`),
  or (4) use a trust-gated target below its trust level (`cert_identity`). With
  `off`/`monitor`, behavior is exactly as today (fail-open content guards).
- **Fail-open vs fail-closed:** content guards remain fail-open (unchanged). The
  new authz chain in `on` mode is **fail-closed on a definite block verdict**,
  but **fail-open on guard *error*** (exception/Redis down) in `monitor`, and
  configurable in `on` via the guard's `configured_action` — default deny only on
  an explicit policy violation, not on infrastructure failure (consistent with
  the existing agent-check chain). Stated explicitly so review can confirm.

## 6. Packaging & deploy

- **`Dockerfile.admin` (INVARIANT RISK — must fix in the same PR).** `routes_a2a`
  is imported by `admin_app.py`, so any module it newly imports must be in the
  admin image's per-file COPY allowlist. Already present: `core/rbac.py`,
  `core/signers.py`, `core/agent_tokens.py`, `guardrails/agentic/rbac_guard.py`,
  `storage/state_store.py`, `api/routes_a2a.py`. **Missing — must add:**
  - `guardrails/agentic/scope/delegation_control.py`
  - `guardrails/agentic/identity/cert_identity.py`
  - `guardrails/agentic/identity/cert_registry.py`
  - `storage/decision_audit.py` (if not already copied — verify)

  Guarded by `tests/test_admin_dockerfile_imports.py`, which will fail the build
  if we miss one — but we add them deliberately, in this PR.
- **Dependencies:** **none new.** Ed25519 signing/verify uses the existing
  `core/signers.py` stack (already a declared dep). No `requirements*.txt` change.
- **Env flags:** `SHIELD_A2A_ENFORCE`, `SHIELD_A2A_REQUIRE_SIGNATURE` — register
  in `core/feature_flags.py` next to `CERT_IDENTITY_ENABLED`/`DECISION_AUDIT_ENABLED`.
- **Rebuild:** both images (`core` data plane + admin) — the path is on both.

## 7. Failure modes & edge cases

| Case | Expected behavior |
|---|---|
| Flag `off` (default) | Identical to today; authz guards not run. |
| `metadata` absent / no `from_agent`/`to_agent` | No agent identity → authz guards **skip** (their existing "missing context, pass" branch). Content guards still run. Not a hard block (non-breaking). |
| `from_agent` ≠ authenticated identity | **Reject** (impersonation) when enforce=`on`; log-only in `monitor`. |
| Caller agent not in registry (managed tenant) | `rbac_guard` denies (unknown agent) — same as REST. |
| Delegation cycle / depth exceeded | `delegation_control` blocks; chain in `details`. |
| Redis down (chain or registry) | Guards degrade per their existing fail-open-on-error branches; `monitor` never blocks; `on` blocks only on explicit verdict, not on lookup error. |
| Huge/empty message text | Content guards already handle; authz guards operate on metadata, not text size. |
| Concurrent messages same `session_id` | Delegation chain uses `agentic_state` set with TTL; last-writer-wins on chain (same semantics as `/agent/check` today). Note as accepted. |
| Signature present but `REQUIRE_SIGNATURE=0` | Verified if `public_key` known; mismatch logged; not blocking unless flag set (Task 3). |
| Missing optional module (cert_registry) | Import guarded; cert_identity skipped with warning, not a 500. |

## 8. Test plan (Definition of Done)

**Task 1 — authz chain wired (PR1):**
- `monitor` runs guards and logs would-block to decision audit but returns the
  normal completed task (allow).
- `on` rejects a delegation-cycle task; rejects an RBAC-denied target; allows a
  permitted delegation. Verdict matches `/agent/check` for the same context.
- `off` (default) is byte-for-byte the current behavior (regression test against
  existing A2A tests).
- Decision audit record written with deciding guard + reason.

**Task 2 — identity reconciliation (PR1):**
- `from_agent` mismatch → reject in `on`, log in `monitor`.
- Absent `from_agent` → skip (non-breaking), content guards still run.

**Task 3 — message signatures (PR2):**
- Valid Ed25519 signature over canonical message verifies; tampered body fails.
- `REQUIRE_SIGNATURE=1` rejects unsigned; `=0` allows unsigned.
- Agent card exposes `public_key`.

**Cross-cutting:**
- `tests/test_admin_dockerfile_imports.py` green (new COPY lines present).
- Full suite green in a **clean venv**; CI `pytest` gate passes.
- Regression guard: a test asserting `routes_a2a`'s imports are all in
  `Dockerfile.admin` (the drift-prone coupling).

---

## Task breakdown (one branch, ordered increments)

> Per the single-branch workflow: these land as ordered commits on one feature
> branch; the user opens the PR(s). Each increment is independently reviewable.

1. **PR1 — A2A authz enforcement + identity reconciliation.**
   Add `SHIELD_A2A_ENFORCE` flag (`off`/`monitor`/`on`); build the agentic
   context from auth + metadata; run `delegation_control` → `rbac_guard` →
   `cert_identity` in `/a2a/tasks/send`; reconcile `from_agent`; write decision
   audit; **add the 3–4 `Dockerfile.admin` COPY lines** + import-drift test.
   Tests per §8 Task 1 + Task 2. *(Bulk of T13/T14.)*

2. **PR2 — Cryptographic inter-agent message signatures.**
   Add `public_key` to registry + agent card; verify `metadata.signature` with
   `core/signers.py`; `SHIELD_A2A_REQUIRE_SIGNATURE` flag. Tests per §8 Task 3.
   *(Closes T12 message integrity / spoofing.)*

**Recommended:** ship PR1 in `monitor` to a tenant, review would-blocks, then
flip `on`. PR2 follows once key publication is in place.
