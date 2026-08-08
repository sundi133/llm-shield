---
title: "Spec: proven delegation chains and depth limits"
layout: default
nav_order: 40
permalink: /spec-delegation-chain-depth/
description: "parent_agent_id is copied from the request body into a signed token, verified by nothing and read by nothing. Bounding the depth of a chain that was never proven limits nothing. Prove the parent link first, then bound it."
---

# Spec: proven delegation chains and depth limits
{: .no_toc }

An agent can name any other agent as its parent, and Shield signs that claim. A
depth limit over an unproven parent link is decoration: the caller picks the
depth. This makes the link provable, then bounds it.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. Problem & outcome

`POST /auth/agent-token` accepts `parent_agent_id` as a plain optional field on
the request body ([routes_agent_auth.py:77](../api/routes_agent_auth.py)) and
passes it straight into `mint_agent_token()`
([routes_agent_auth.py:279](../api/routes_agent_auth.py)). The same pattern
repeats at lines 938 and 964. Nothing verifies that the named parent exists,
that it delegated anything, or that the caller has any relationship to it.

Downstream, `parent_agent_id` is carried in `IdentityTuple`
([core/identity.py:30](../core/identity.py)) and serialized. Grepping the
non-test tree for consumers outside `core/agent_tokens.py` returns the mint
call sites and the dataclass field. **No authorization decision reads it.**

So today:

- The parent link is **asserted**, not proven.
- The chain has **no length**, because there is no chain — just a string.
- `parent_cap_id` in `core/capabilities.py` has the same shape: written at
  [capabilities.py:223](../core/capabilities.py), read by nothing outside that
  module.

This matters beyond tidiness. The security claim an agentic platform makes is
"an agent cannot delegate its way around its own grant." Shield cannot make that
claim: an agent with a valid token can mint a child naming any parent, and no
limit applies because no limit can be computed from an unverified field.

**Outcome.** Two changes, in this order:

1. **Provenance.** A child token's `parent_agent_id` is derived from a
   *verified parent token* the caller presents. The body field is ignored when
   proof is required.
2. **Bound.** A `delegation_depth` claim, computed from the verified parent,
   refused above a configured maximum.

Observable success condition: with proof required and depth 1, an agent can
mint one child; the child cannot mint a grandchild; and a caller naming a
parent it does not hold a token for is refused.

### Non-goals
- **Not** capability chaining. `parent_cap_id` has the same defect and deserves
  the same treatment, but `cap/mint` is the hottest path in the system and
  mixing the two makes one PR unreviewable. Flagged in §9 as follow-on.
- **Not** AAuth sub-agent identifier syntax (`planner.7f3c+search1@domain`).
  Shield's `agent_id` namespace is tenant-scoped and already registered; adding
  a derived-identifier grammar is a separate decision.
- **Not** a change to `X-On-Behalf-Of` delegation (`core/delegation.py`). That
  is agent-acting-for-*user*; this is agent-delegating-to-*agent*. Different
  axis, untouched.
- **Not** revocation cascade. Revoking a parent does not currently revoke
  children, and this spec does not add that. Noted in §7 as a known limit.

## 2. Plane & latency contract

**Planes: both, asymmetrically.**

- **Admin plane** (`admin_app.py` mounts `routes_agent_auth` at
  [admin_app.py:1109](../admin_app.py)) — where minting happens and where all
  the new work lives.
- **Data plane** — verification only.

**Touches the guard path: marginally, and by design.**

`POST /auth/agent-token` is **not** on the guard path. Verifying a presented
parent token there costs one Ed25519 verification on an admin endpoint that
already does `_require_admin`, `_enforce_tenant_binding`,
`_enforce_user_sub_binding` and `_require_registered_agent` — four checks, at
least one of which hits Redis. One more signature check is noise.

On the guard path, the only addition is an **integer comparison** against a
claim already present in the verified token. `verify_agent_token()` has already
parsed the claims; reading `delegation_depth` and comparing it to a cached env
int is nanoseconds and involves no I/O.

**Latency budget: < 1 µs on `/guardrails/*`, `cap/mint` and `tools/call`.** The
expensive half is off the hot path entirely. This is the reason depth is stamped
into the token at mint rather than recomputed by walking a chain at verify: a
chain walk would be N Redis reads per guarded request, which is exactly the kind
of thing this repo's invariants exist to prevent.

## 3. Data model

### New token claim

`mint_agent_token()` gains one optional claim:

    delegation_depth   int, omitted when 0

Omitted rather than `0` so an existing caller's tokens stay byte-compatible, in
the same spirit as the existing `roles` claim
([agent_tokens.py:190](../core/agent_tokens.py)). A token with no
`delegation_depth` is depth 0 — a root token, minted directly for a user.

`IdentityTuple` ([core/identity.py](../core/identity.py)) gains a matching
`delegation_depth: int = 0` field so the value survives verification and reaches
the audit.

### Redis

**No new keys.** Depth travels in the token; it is not stored.

This is deliberate. A Redis-backed chain registry would need a write at every
mint, a read at every verify, tenant-scoped keys, TTL reconciliation against
token expiry, and a story for what happens when the two disagree. The claim
is signed by the same key that signs everything else, cannot be edited by the
caller, and expires with the token. It is strictly less machinery for strictly
more guarantee.

### Tenant scoping

Inherited, not added. `_enforce_tenant_binding` already runs on the mint
endpoint, and the presented parent token carries `tenant_id`. **A parent from a
different tenant is refused** — see §5.

## 4. API / interface

### Config

```
SHIELD_DELEGATION_PARENT_PROOF = off | required     # default: off
SHIELD_MAX_DELEGATION_DEPTH    = <int>              # default: unset = unlimited
```

`off` is today's behaviour exactly: the body's `parent_agent_id` is trusted and
stamped as-is.

`required` means the body field is **ignored**, and `parent_agent_id` is derived
solely from a verified parent token.

`SHIELD_MAX_DELEGATION_DEPTH` is only meaningful when proof is `required`. When
proof is `off`, the depth is caller-controlled and the limit bounds nothing.
Setting the max without the proof flag MUST log a warning at startup naming
this, and MUST NOT silently appear to enforce. An operator who thinks they have
a depth limit and does not is worse off than one who knows they have none.

Both are read through a small cached accessor in `core/agent_tokens.py`
mirroring `role_binding_mode()`, so tests can monkeypatch and the guard path
does not re-read the environment per request.

### Mint request

`AgentTokenRequest` ([routes_agent_auth.py:77](../api/routes_agent_auth.py))
gains:

```python
parent_agent_token: Optional[str] = Field(
    None, description="Verified parent's agent token. Required to set "
                      "parent_agent_id when SHIELD_DELEGATION_PARENT_PROOF=required.")
```

Resolution in `issue_agent_token()`:

```python
parent_id, depth = None, 0
if parent_proof_required():
    if body.parent_agent_token:
        try:
            parent = verify_agent_token(body.parent_agent_token)
        except TokenError as e:
            raise HTTPException(400, f"invalid parent_agent_token: {e}")
        if parent.tenant_id != body.tenant_id:
            raise HTTPException(403, "parent token belongs to a different tenant")
        parent_id = parent.agent_id
        depth = parent.delegation_depth + 1
        max_depth = max_delegation_depth()
        if max_depth is not None and depth > max_depth:
            raise HTTPException(403, f"delegation depth {depth} exceeds limit {max_depth}")
    # body.parent_agent_id is deliberately NOT read here.
elif body.parent_agent_id:
    parent_id = body.parent_agent_id          # legacy, unproven
```

Note the tenant check is `!=` against the *requested* tenant, not merely
"present." A parent token from tenant A cannot seed a chain in tenant B even
though both are valid tokens.

### Responses

| condition | status | body |
|---|---|---|
| depth exceeds limit | 403 | `{"detail": "delegation depth N exceeds limit M"}` |
| parent token invalid or expired | 400 | `{"detail": "invalid parent_agent_token: ..."}` |
| parent token from another tenant | 403 | `{"detail": "parent token belongs to a different tenant"}` |
| proof required, no parent token, no parent claimed | 200 | root token, depth 0 |

400 for a malformed credential, 403 for a well-formed one that is not allowed —
consistent with how the endpoint already distinguishes `TokenError` (400) from
binding failures.

### Guard-path check

`verify_agent_token()` gains a final check: if `SHIELD_MAX_DELEGATION_DEPTH` is
set and the token's `delegation_depth` exceeds it, raise `TokenError`. This
catches tokens minted before the limit was lowered, without waiting for them to
expire. One int comparison, per §2.

### Second mint site

Lines 938 and 964 of `routes_agent_auth.py` are a second `mint_agent_token`
call with the same `parent_agent_id` field. **Both must be changed together.**
Fixing one and not the other leaves a bypass, and a bypass is worse than the
current honest absence of a control. This is the single most likely way to get
this PR wrong.

## 5. Security & backward compatibility

**Default behaviour: unchanged.** `SHIELD_DELEGATION_PARENT_PROOF` defaults to
`off` and `SHIELD_MAX_DELEGATION_DEPTH` defaults to unset. A deployment that
sets neither behaves exactly as today, including still accepting an unproven
`parent_agent_id`. No migration required.

**What a malicious caller can do today:** mint a token naming any
`parent_agent_id`, including an agent it has no relationship with, and have
Shield sign it. Since nothing reads the field, the practical impact is limited
to poisoning the audit trail — which is not nothing, given the tamper-evident
audit work exists precisely so the record can be trusted.

**What a malicious caller can do after:** with proof `required`, nothing. It can
only name a parent whose valid, unexpired, same-tenant token it holds. Holding
that token already implies more authority than the child will have.

**Escalation direction.** Depth increases monotonically and is derived from a
verified parent, so a caller cannot mint a lower-depth token than its parent.
There is no path to depth 0 except a direct mint, which is already gated by
`_require_admin`.

**Cross-tenant.** Explicitly refused, with a test. Worth stating because
`verify_agent_token` succeeding is *not* sufficient — a token valid for tenant A
is a perfectly valid token, and the naive implementation accepts it.

**Migration path for an operator turning proof on:**

1. Set `SHIELD_DELEGATION_PARENT_PROOF=required` with no max depth. Chains are
   now proven but unbounded. Nothing breaks that was not already asserting an
   unproven parent.
2. Watch the audit for `delegation_depth` distribution. This is why the claim
   reaches the audit before the limit is enforced.
3. Set `SHIELD_MAX_DELEGATION_DEPTH` at or above the observed maximum.
4. Lower it deliberately.

Turning both on simultaneously without step 2 is how you take down a customer's
legitimate three-hop workflow. State this in the runbook.

## 6. Packaging & deploy

- **New module:** none. Changes are confined to `core/agent_tokens.py`,
  `core/identity.py` and `api/routes_agent_auth.py`, all of which exist in both
  images.
- **`Dockerfile.admin`:** no change. `core/agent_tokens.py`
  ([Dockerfile.admin:58](../Dockerfile.admin)) and `core/identity.py` are
  already in the allowlist, and `routes_agent_auth` is already mounted
  ([admin_app.py:1109](../admin_app.py)). `tests/test_admin_dockerfile_imports.py`
  must still pass.
- **New pip dependency:** none.
- **Images to rebuild:** both. The admin image mints, the data plane verifies,
  and a data plane that does not know the `delegation_depth` claim will ignore
  it — which is safe but means the guard-path check silently does not run.
  Deploy the data plane first or simultaneously; never admin-first.
- **Rollback:** unset both env vars. Tokens already minted carry a
  `delegation_depth` claim that older code ignores as an unknown claim. No data
  migration.

## 7. Failure modes & edge cases

Fail-closed on the mint path, fail-closed on the guard path.

| condition | behaviour | posture |
|---|---|---|
| proof `required`, `parent_agent_token` absent | depth 0 root token; body `parent_agent_id` ignored | closed (no unproven parent recorded) |
| proof `required`, parent token expired | 400 | closed |
| proof `required`, parent token revoked (instance or jti) | 400 — `verify_agent_token` already checks both | closed |
| proof `required`, parent from another tenant | 403 | closed |
| proof `required`, parent token malformed or empty string | 400 | closed |
| max depth set, proof `off` | limit not enforceable; **startup warning** | open, loudly |
| max depth set to 0 | no delegation at all; any parent token refused | closed |
| max depth negative or non-integer | treated as unset, warning logged | open, loudly |
| token minted at depth 3, limit later lowered to 2 | `verify_agent_token` refuses it on the guard path | closed |
| old token with no `delegation_depth` claim | treated as 0 | open by design (that is what it is) |
| parent token itself over the limit | its own verification fails first | closed |
| Redis down during mint | `_require_registered_agent` already fails; unchanged | unchanged |
| concurrent mints from the same parent | independent; depth derives from the parent token, not shared state | safe by construction |

**Known limit, stated rather than hidden:** revoking a parent does **not**
revoke its children. A child token remains valid until its own `exp` (≤15
minutes, per `MAX_TOKEN_TTL_SECONDS`). Cascading revocation needs a chain
registry, which §3 deliberately rejected. The 15-minute ceiling is the
mitigation, and it must be written in the customer docs rather than discovered.

## 8. Test plan (Definition of Done)

New file `tests/test_delegation_chain_depth.py`.

**Provenance**
1. Proof `off`: body `parent_agent_id` is stamped into the token — the current
   behaviour, asserted so the default cannot drift.
2. Proof `required`: body `parent_agent_id` is **ignored** when no parent token
   is presented; result is depth 0 with `parent_agent_id is None`.
3. Proof `required` + valid parent token: `parent_agent_id` equals the
   *verified parent's* `agent_id`, not whatever the body said. Send a body value
   that disagrees with the token and assert the token wins.
4. Proof `required` + expired parent token → 400.
5. Proof `required` + revoked parent instance → 400.
6. Proof `required` + parent token from another tenant → 403.
7. Proof `required` + garbage parent token → 400.

**Depth**
8. Root token has no `delegation_depth` claim; `IdentityTuple.delegation_depth == 0`.
9. Child of a root is depth 1; grandchild is depth 2.
10. Limit 1: root mints child (200); child cannot mint grandchild (403).
11. Limit 0: any parent token refused (403).
12. Limit unset: chain of depth 5 mints fine.
13. Token minted at depth 3, limit then set to 2, `verify_agent_token` raises.
14. Negative and non-integer limits treated as unset, warning emitted.

**Both mint sites**
15. Every test in the Provenance and Depth groups is parameterised across
    **both** endpoints (line 271 and line 956). Not a copy of the file — a
    fixture parameterised on the route. This is the regression guard for the
    §4 warning, and it is the reason to write the fixture before the feature.

**Regression guards**
16. A token minted with proof `off` and no parent verifies byte-identically to
    one minted before this change (compare claim sets, excluding `jti`/`iat`).
17. `IdentityTuple` round-trips `delegation_depth` through serialization.
18. Startup with `SHIELD_MAX_DELEGATION_DEPTH` set and proof `off` logs the
    warning — asserted with `caplog`, because a warning nobody tests is a
    warning that gets deleted.
19. `tests/test_agent_auth_portal.py` and `tests/test_signers.py` pass
    unmodified.
20. `tests/test_admin_dockerfile_imports.py` passes.

**Gate**
21. `python -m pytest tests -q` green in a clean venv.
22. CI `pytest` gate green.

## 9. Task breakdown (one PR each)

**PR 1 — parameterised fixture over both mint endpoints, current behaviour only.**
Tests 1 and 15's harness against today's code. No feature. This exists so PR 2
physically cannot fix one endpoint and forget the other.

**PR 2 — provenance.** `SHIELD_DELEGATION_PARENT_PROOF`, `parent_agent_token`,
verified derivation, tenant check, tests 2 to 7. No depth yet. Shippable and
useful alone: it makes the audit trail honest.

**PR 3 — depth.** `delegation_depth` claim, `IdentityTuple` field,
`SHIELD_MAX_DELEGATION_DEPTH`, mint-time and verify-time checks, startup
warning, tests 8 to 18.

**PR 4 — docs.** Runbook migration sequence from §5, the revocation-cascade
limit from §7, and a `delegation_chain_demo.py` in the
`examples/langchain/keycloak_binding_demo.py` style that mints a chain and shows
hop N+1 refused.

**Follow-on, not in this spec:** `parent_cap_id` has the identical defect on the
`cap/mint` path. Same treatment, own spec, because the latency argument there is
entirely different.
