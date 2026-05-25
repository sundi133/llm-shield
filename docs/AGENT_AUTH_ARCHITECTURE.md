# Agent AuthN / AuthZ at Runtime

This document describes how LLM-Shield authenticates and authorizes
agent actions at runtime. It covers the threat model, the layered design,
the on-the-wire token formats, and how the pieces are wired together in
the code.

## 1. The Problem

Classical IAM (API keys, OAuth, IAM roles) makes assumptions that break
for agentic systems:

* **One bearer = one principal.** Reality: a tool call has a human user,
  an agent identity, and often an upstream agent that delegated.
* **Authorization is identity-only.** Reality: whether `send_email` is
  allowed depends on what's *in* the email (PII, taint origin, prior
  tool outputs), not just who is calling.
* **Decisions per session.** Reality: a single agent session can fan out
  to hundreds of tool calls across sub-agents; audit needs to be
  per-action, not per-session.

This implementation closes those gaps with two distinct token types:
an **agent token** (AuthN) and a **capability token** (AuthZ).

## 2. Block Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  Legend:                                                                     │
│   ░░░░  AuthN zone  — proves WHO (identity, slow-changing, ≤15m)             │
│   ▓▓▓▓  AuthZ zone  — decides WHAT (permission, per-action, ≤60s)            │
│   ████  Enforcement zone — verifies the AuthZ decision at the tool           │
└──────────────────────────────────────────────────────────────────────────────┘

  Human User (OIDC + MFA) ────►  Agent Runtime
                                  ░ workload SVID + user id_token
                                  ░ ↓
                                  ░ POST /v1/shield/auth/agent-token
                                  ░ ↓
                                  ░ X-Agent-Token = signed agent_token
                                  ▼
                       ┌─────────────────────────────────────────┐
                       │  LLM-SHIELD GATEWAY                     │
                       │                                         │
   ░ AuthN ──► AgentIdentityMiddleware                          │
   ░          verify_agent_token() → IdentityTuple              │
   ░          (request.state.identity)                          │
                       │                                         │
   ▓ AuthZ ──► POST /v1/shield/cap/mint                         │
   ▓          _decide_authz(identity, request):                 │
   ▓            - rbac: role → tool, role → data                │
   ▓            - clearance ceiling                             │
   ▓            - (taint, delegation, sensitive-action hooks)   │
   ▓          mint_cap(identity, tool, resource, scope, exp≤60s)│
   ▓          → returns signed cap_token                        │
                       └─────────────────────────────────────────┘
                                  │
                       ┌──────────┼──────────┐
                       ▼          ▼          ▼
                  █ Tool A    █ Tool B    █ Tool C
                  POST /v1/shield/cap/verify
                  - signature, exp, tool match, nonce one-shot
                  - cap_id revocation check
                  - returns valid=true|false + claims

                       Audit log: one signed row per decision.
                       Control plane: revoke(instance|user|jti).
```

## 3. AuthN — Agent Tokens

### What an agent token proves

```
{
  user_sub:           "user-42"          ← OIDC sub of the human
  agent_id:           "billing-bot"      ← logical agent identity
  agent_instance_id:  "inst-abc-1"       ← this running process
  parent_agent_id:    null | "parent"    ← who delegated, if any
  tenant_id:          "tenant-1"
  build_hash:         "sha256:..."       ← exact code build
  model_version:      "claude-opus-4.7"
  session_id:         "sess-123"
  iat, exp:           Unix seconds       ← exp ≤ iat + 15m
  jti:                "..."              ← revocable per-token id
  kid:                "env"              ← signing key id (rotation)
}
```

### Wire format

```
<base64url(claims_json)>.<base64url(ed25519_signature)>
```

Carried in the `X-Agent-Token` header.

### Verification (`core/agent_tokens.py::verify_agent_token`)

1. Decode and Ed25519-verify the signature with the `kid`'s public key.
2. Check `exp` (allows 5s clock skew) and `iat`.
3. Enforce required claims.
4. If `SHIELD_AGENT_ALLOWED_BUILDS` is set, enforce build allowlist.
5. Check the three revocation lists: instance, jti, user.

On success returns an `IdentityTuple` (see `core/identity.py`). On any
failure raises `TokenError`. The `AgentIdentityMiddleware` catches that
and returns 401.

### Key material

* Private key in `SHIELD_AGENT_TOKEN_PRIVATE_KEY` (hex-encoded 32 bytes).
* Key id in `SHIELD_AGENT_TOKEN_KID` (default `env`).
* If unset, the process generates an ephemeral key — dev/test only; it
  emits a warning.
* The signer interface is pluggable; a KMS-backed signer is a drop-in
  replacement.

## 4. AuthZ — Capability Tokens

### What a cap token grants

```
{
  user_sub, agent_id, agent_instance_id    ← bound to AuthN identity
  tenant_id
  tool:           "send_email"             ← exact, not a wildcard
  resource:       "user/42/inbox"          ← exact target
  scope:          ["to:user@example.com"]  ← constraints intersection
  clearance_max:  "internal"               ← data ceiling
  parent_cap_id:  null | "..."             ← for delegated calls
  nonce:          "..."                    ← one-shot
  iat, exp:       Unix seconds             ← exp ≤ iat + 60s
  cap_id:         "..."                    ← revocable per-cap id
  kid:            "cap-env"
}
```

### Why a separate signer from agent tokens

Tool servers only need the cap public key — they never need the agent-
token public key. A compromised tool can therefore only see (already
narrowly-scoped) caps; it cannot forge identity tokens.

### Mint (`POST /v1/shield/cap/mint`)

Requires a verified `X-Agent-Token`. The handler:

1. Pulls `IdentityTuple` from `request.state.identity`.
2. Runs `_decide_authz(identity, body)`:
   * RBAC role → tool check
   * RBAC role → data scope check
   * Clearance ceiling: `body.clearance_max` ≤ role's `data_clearance`
3. If denied → 403 with reasons (no cap minted).
4. If allowed → `mint_cap(...)` → returns `cap_token` (≤60s TTL).

The decision is also returned in the response for audit.

### Verify (`POST /v1/shield/cap/verify`)

Called by the tool / MCP server before executing. Checks:

1. Ed25519 signature with `kid`'s public key.
2. `exp` (allows 2s clock skew).
3. `tool` matches `expected_tool`.
4. (Optional) `resource` matches `expected_resource`.
5. `cap_id` not in revocation list.
6. Atomically burn `nonce` (Redis SETNX, or fallback dict).
   On second use → "replay detected".

Returns `{valid, claims}` or `{valid: false, error}`.

## 5. Revocation

Three independent axes (`storage/revocation.py`):

| Function           | What it kills                            |
|--------------------|------------------------------------------|
| `revoke_instance`  | One running agent process               |
| `revoke_user`      | Everything a compromised user did       |
| `revoke_jti`       | One specific token or cap (by jti/cap_id)|

Backed by Redis when present; in-process fallback otherwise. TTL =
3600s by default (longer than max token lifetime), so revoke entries
auto-clean.

Exposed via `POST /v1/shield/auth/revoke` (admin-key gated).

Revocation checks run inside `verify_agent_token` and `verify_cap`, so
revocation propagates within one verify call — no caches to bust.

## 6. End-to-end Sequence

```
1. User logs in (OIDC)                               → id_token
2. Agent starts (workload SVID)                      → workload identity
3. POST /v1/shield/auth/agent-token                  → agent_token (≤15m)
   (token exchange — gated by SHIELD_ADMIN_KEY in v1)
4. Agent calls /v1/shield/cap/mint with X-Agent-Token
   - middleware verifies → IdentityTuple
   - policy decides AuthZ
   - mint cap                                        → cap_token (≤60s)
5. Agent passes cap_token to the tool server
6. Tool calls /v1/shield/cap/verify
   - sig + exp + tool match + nonce burn             → valid|invalid
7. Tool executes the action (only if valid).
8. If something looks wrong:
   POST /v1/shield/auth/revoke {agent_instance_id|user_sub|jti}
   - propagates instantly on the next verify call.
```

## 7. Threat → Control Matrix

| Threat                                       | Control                                                 |
|----------------------------------------------|---------------------------------------------------------|
| Stolen long-lived API key                    | No long-lived agent secret; tokens ≤15m, Ed25519-signed |
| Replayed capability token                    | One-shot nonce burn at verify                           |
| Prompt-injected tool abuse                   | Cap minted *before* LLM sees user instruction; tool field is exact, not wildcard |
| Confused-deputy / over-broad sub-agent       | Cap carries scope intersection; downstream cannot widen |
| Tool server trusts agent's word              | Tool verifies cap signature against KMS pubkey          |
| Tampered agent build / wrong model           | `build_hash` claim checked against allowlist            |
| Compromised agent in flight                  | `revoke_instance(agent_instance_id)` — effect ≤1s       |
| Cross-tenant leakage                         | `tenant_id` in every cap, checked constant-time at tool |
| "How did this happen?" 3 weeks later         | One signed audit row per decision, replayable           |

## 8. Production Hardening (post-v1)

* Replace HMAC/ephemeral-key fallback with **KMS-backed Ed25519 signing**.
* Replace `POST /v1/shield/auth/agent-token` with **OIDC + SPIFFE token
  exchange**: take a verified user id_token + a workload SVID and emit
  the agent token without an admin key.
* Stream audit rows to **immutable storage** (ClickHouse / S3 + object
  lock), not just SQLite.
* Add **bloom-filter front** to the revocation Redis to skip 99% of GETs.
* Add a **client SDK** (Python + TS) for tool servers so cap verification
  is one import, not an HTTP call.

## 9. Where the code lives

| File                                           | Role                                |
|------------------------------------------------|-------------------------------------|
| `core/identity.py`                             | `IdentityTuple` + request dependency|
| `core/agent_tokens.py`                         | Mint/verify agent tokens            |
| `core/capabilities.py`                         | Mint/verify capability tokens       |
| `core/agent_identity_middleware.py`            | Verifies `X-Agent-Token`            |
| `storage/revocation.py`                        | Three revocation axes               |
| `api/routes_agent_auth.py`                     | All HTTP endpoints + AuthZ decision |
| `tests/test_agent_tokens.py`                   | AuthN unit tests                    |
| `tests/test_capabilities.py`                   | AuthZ unit tests                    |
| `tests/test_revocation.py`                     | Revocation tests                    |
| `tests/test_agent_auth_e2e.py`                 | End-to-end FastAPI tests            |
