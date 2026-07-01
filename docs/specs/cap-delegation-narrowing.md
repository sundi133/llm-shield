# Spec: capability delegation narrowing (parent → child enforcement)

Status: draft, awaiting approval. Feature 1 of 3 (governance-to-enforcement);
features 2 (auto-trim) and 3 (behavioral blocking) get their own specs/PRs.

## 0. Critical semantics note (read first)

The IETF drafts (txn-tokens-for-agents, identity-chaining) phrase narrowing as
"child scope MUST be a subset of parent scope" — that language assumes OAuth
scopes = *permissions*. In Shield, the cap `scope` claim is a list of
**constraints** the verifier enforces at the tool boundary
(`api/routes_agent_auth.py:408-411`: "Taint, delegation intersection, and
sensitive-action confirmation are designed-for hooks that the caller can stamp
into scope_constraints"). Under constraint semantics, *narrower = more
constraints*, so the enforced direction is:

    set(parent.scope) ⊆ set(child.scope)   — child carries ALL parent
                                             constraints, may add more

plus permission-like clamps where the claim IS a ceiling:

    rank(child.clearance_max) ≤ rank(parent.clearance_max)
    child.exp ≤ parent.exp

Getting the direction wrong would *widen* delegated authority. Tests must
lock the direction in.

## 1. Problem & outcome

- Today `parent_cap_id` is minted into cap claims (`core/capabilities.py:239`)
  and surfaced by `verify_cap` (`:356`) but **nothing enforces** any
  relationship between a delegated child cap and its parent. A child can be
  minted with fewer constraints, higher clearance, or a later expiry than the
  parent that spawned it.
- Investigation result: **zero call sites pass `parent_cap_id` today** (grep
  across repo) and the HTTP `POST /cap/mint` endpoint does not accept it.
  The delegation link is a dormant designed-for hook — so enforcement has no
  existing traffic to break.
- Outcome: a delegated agent can never hold a cap more powerful than its
  parent's. Observable success: minting through the new `parent_cap_token`
  path yields a child whose scope/clearance/exp are provably narrowed, and
  `verify_cap` rejects any token whose claims violate the invariant.
- Non-goals: delegation *depth* limits (agent-token layer concern);
  cross-tool semantic policy (each child's tool/resource is still
  independently authorized by `_decide_authz` RBAC); persisting cap records
  (caps stay stateless JWTs); RFC 8693 `act` chains on the OAuth plane.

## 2. Plane & latency contract

- Plane: **data plane** (`core/app.py` mounts `api/routes_agent_auth.py`).
  The same router file also serves portal reads on the admin plane; all
  touched files are already in the `Dockerfile.admin` COPY list (lines 47,
  70, 94) — no packaging change.
- Touches the GUARD PATH: **yes — `cap/mint` and `cap/verify`** (this is an
  enforcement feature on the authz path itself, not a governance feature
  leaking onto it). Budget & justification:
  - `POST /cap/verify`: **zero added I/O**. The backstop check is a pure
    in-memory set comparison, and only runs when the token carries the new
    `parent_scope` claim. Legacy tokens pay one dict `.get()` (~ns).
  - `POST /cap/mint` without `parent_cap_token`: **zero change** (one `is
    None` branch).
  - `POST /cap/mint` with `parent_cap_token` (new, opt-in per request):
    one extra in-process `verify_cap(burn_nonce=False)` = 1 EdDSA verify
    (~60µs) + the existing revocation lookups (≤2 Redis GETs). Total added
    < 1 ms, paid only by callers using delegation. No new network hops.

## 3. Data model

- **No new Redis keys.** No cap persistence. Enforcement data rides inside
  the child JWT:
  - `parent_cap_id` (existing claim, now actually populated on the HTTP path)
  - `parent_scope: list[str]` (NEW claim) — the parent's scope list, embedded
    at mint so the verifier can enforce the invariant with zero I/O.
- `CapClaims` dataclass gains `parent_scope: Optional[List[str]] = None`
  (default keeps all existing constructors/tests valid).
- Tenant scoping: delegation may not cross identity — enforced at mint:
  `child.tenant_id == parent.tenant_id` and `child.user_sub ==
  parent.user_sub`. Cross-tenant delegation is rejected outright.
- Size bound: the unioned scope list is capped at **256 entries**; mint
  raises `CapabilityError` beyond that (deterministic, tested) so a hostile
  caller can't bloat JWTs.

## 4. API / interface

- `POST /v1/shield/cap/mint` (existing, data plane; auth = `X-Agent-Token`
  via `AgentIdentityMiddleware`, unchanged):
  - Request: `CapMintRequest` gains `parent_cap_token: Optional[str] = None`.
  - Behavior when present and narrowing is `enforce`:
    1. Verify parent via `verify_cap(parent_cap_token, expected_tool=
       parent's own tool, burn_nonce=False)` — signature, exp, revocation
       (cap_id + instance) checked; nonce NOT burned (referencing a parent
       is not consuming it).
    2. Reject 403 if parent invalid/expired/revoked, or identity mismatch
       (`user_sub`/`tenant_id`).
    3. Auto-narrow (RFC 8693 "AS may narrow" philosophy, matches
       intersection-RBAC style): child.scope := requested ∪ parent.scope;
       child.clearance_max := min(requested, parent); child.exp :=
       min(now+ttl, parent.exp). Effective values are in the returned cap;
       when `SHIELD_VERBOSE_REASONS=1`, `decision` also reports
       `{"delegated": true, "narrowed": {...}}`.
    4. Child minted with `parent_cap_id` + `parent_scope` embedded.
  - Status codes: 403 parent-invalid / identity-mismatch (same
    `public_denial_payload` shape as RBAC denials, M3-quiet by default);
    400 malformed parent token / scope-union overflow; else unchanged.
- `POST /v1/shield/cap/verify` (existing): response `claims` dict
  additionally includes `parent_cap_id` and `parent_scope` when present
  (additive, no removals).
- `verify_cap()` (library, called by the endpoint and importable by tool
  servers): after existing checks, if `parent_scope` claim is present and
  not `set(parent_scope) <= set(scope)` → `CapabilityError("cap scope
  wider than parent (delegation narrowing violated)")`. Claim-presence-
  driven, so it is self-consistent across processes regardless of env flags.
- Audit: reuse `record_event` — `EVENT_CAP_DENIED` with
  `reason="parent_invalid: …"` on mint rejection; `EVENT_CAP_MINTED` gains
  nothing new (parent linkage is in the token); `EVENT_CAP_INVALID` covers
  verify-time violations (existing event, new reason string).

## 5. Security & backward compatibility

- Default behavior: **unchanged for every existing caller.** The HTTP path
  never accepted parent linkage before; the Python `parent_cap_id=` kwarg
  has zero callers. Enforcement triggers only on (a) the new
  `parent_cap_token` request field or (b) tokens carrying the new
  `parent_scope` claim — both cannot exist before this PR ships.
- Env flag: `SHIELD_CAP_DELEGATION_NARROWING` = `enforce` (default) |
  `warn` | `off`, read at call time (same pattern as
  `SHIELD_ENFORCE_CAP_CLEARANCE`, `api/routes_agent_auth.py:395-400`).
  - `enforce`: behavior in §4.
  - `warn`: parent is still verified (invalid parent still rejects — a
    dangling reference is a correctness bug, not a rollout concern), but
    narrowing is computed + audit-logged only; child minted as requested,
    **without** `parent_scope` embedded (so the verify backstop — which is
    claim-driven — stays consistent). Staged-rollout mode for future direct
    `mint_cap` adopters.
  - `off`: `parent_cap_token` accepted but treated as today's dormant
    `parent_cap_id` passthrough (id stamped, nothing verified). Escape
    hatch per repo invariant.
- Secure-by-default is satisfiable with `enforce` as default *because the
  path is dormant* — there is no legacy traffic to break, so no migration
  note is needed beyond the changelog entry.
- Authz: caller still needs a valid `X-Agent-Token`, and `_decide_authz`
  RBAC still gates the child's tool/resource independently. A malicious
  caller with a stolen parent cap can only mint children *narrower* than
  the parent, within the parent's remaining ≤60 s lifetime, for
  tools/resources its own RBAC allows. It cannot widen scope, raise
  clearance, extend lifetime, or cross user/tenant.

## 6. Packaging & deploy

- No new modules; no new pip deps. Touched files (`core/capabilities.py`,
  `api/routes_agent_auth.py`, `storage/revocation.py` untouched-but-read)
  are already in `Dockerfile.admin`'s COPY allowlist — verified lines 47/70/94.
- Env flag documented in the changelog + `docs/agent-governance.md` note.
- Images: data-plane image rebuild; admin image rebuild picks up the same
  files (no allowlist edit).

## 7. Failure modes & edge cases

- Parent expired / revoked (cap_id or instance) / bad signature / wrong
  iss-aud → mint rejected **fail-closed** (403).
- Parent nonce already burned: still delegable — nonce guards *execution*,
  not *reference*; possession within the ≤60 s lifetime is the proof.
  Documented deliberately.
- Redis down during parent revocation lookup: inherits `verify_cap`'s
  existing posture (`storage/revocation.py::_exists` falls back to the
  in-process store → revocation soft-fails open, signature/exp checks are
  local and always enforced). No new decision introduced; stated for
  honesty.
- Empty parent scope `[]`: union no-op; subset check trivially true —
  a parent with no constraints imposes none. Valid.
- Child requests higher clearance than parent: clamped down (not rejected),
  effective value visible in the returned token; audited in verbose mode.
- Child TTL exceeding parent's remaining lifetime: exp clamped to parent's.
  If parent already expired → 403 (never mint an already-dead child).
- Grandchild chains: each hop re-narrows against its immediate parent;
  monotonic by induction. Depth limits are a non-goal (agent-token layer).
- Scope union > 256 entries → 400, deterministic.
- Legacy 2-segment cap format: `parent_scope` never present in legacy
  tokens → backstop never fires; unchanged.
- Concurrency: no shared mutable state added (stateless JWT claims); no
  new races.

## 8. Test plan (Definition of Done)

New `tests/test_cap_delegation_narrowing.py`:
- **Direction lock-in**: child missing one parent constraint → verify_cap
  raises; child with parent constraints + extras → passes. (Guards §0.)
- Mint happy path: scope union, clearance clamp, exp clamp, `parent_cap_id`
  + `parent_scope` stamped; effective values decode from the returned JWT.
- Mint rejections: expired parent, revoked cap_id, revoked instance,
  tampered signature, user_sub mismatch, tenant_id mismatch → 403; scope
  overflow → 400.
- Verify backstop: hand-mint (test signer) a violating child → verify_cap
  rejects with the narrowing error; legacy token without `parent_scope` →
  passes untouched (regression).
- Nonce independence: delegating does not burn the parent's nonce; parent
  still executes once afterwards.
- Flag matrix: `enforce` (default) / `warn` (mint as requested, no
  `parent_scope` embedded, audit event recorded) / `off` (passthrough).
- HTTP e2e (per `tests/test_agent_auth_e2e.py` conventions): token →
  cap/mint(parent) → cap/verify chain over the wire.
- Full suite `python -m pytest tests -q` green in a **clean venv**
  (`python -m venv /tmp/x && /tmp/x/bin/pip install -r
  requirements-test.txt`); CI pytest gate passes.
