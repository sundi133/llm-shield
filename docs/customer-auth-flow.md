# Customer Auth Flow: Step-by-Step Guide

This document shows how customers integrate agent authentication (AuthN)
and authorization (AuthZ) with LLM Shield. Every success and failure path
is shown with exact HTTP requests and responses.

---

## Overview: Three Tokens, Three Layers

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │                                                                     │
  │   LAYER 1          LAYER 2              LAYER 3                     │
  │   Tenant Key       Agent Token          Capability Token            │
  │   (API key)        (AuthN — WHO)        (AuthZ — WHAT)              │
  │                                                                     │
  │   ┌──────────┐     ┌──────────────┐     ┌──────────────────┐        │
  │   │ X-API-Key│────>│ X-Agent-Token│────>│ cap_token (bearer)│       │
  │   │ per tenant│     │ per agent    │     │ per tool call    │       │
  │   │ long-lived│     │ ≤15 min JWT  │     │ ≤60s JWT         │       │
  │   │ in header │     │ in header    │     │ single-use nonce │       │
  │   └──────────┘     └──────────────┘     └──────────────────┘        │
  │       │                   │                      │                  │
  │   Proves: this            Proves: this is       Grants: this agent  │
  │   request comes           billing-bot running   may call send_email │
  │   from tenant-1           as user-42            on user/42/inbox    │
  │                                                                     │
  └─────────────────────────────────────────────────────────────────────┘
```

---

## Complete Request Flow

```
  ┌──────────┐         ┌────────────────────────────────┐        ┌───────────┐
  │ Customer │         │         LLM SHIELD              │        │   Tool    │
  │  Agent   │         │         Gateway                 │        │  Server   │
  └────┬─────┘         └──────────┬─────────────────────┘        └─────┬─────┘
       │                          │                                     │
       │  STEP 1: Get Agent Token │                                     │
       │  ─────────────────────── │                                     │
       │                          │                                     │
       │  POST /v1/tenant/me/     │                                     │
       │    agent-auth/agent-token│                                     │
       │  Headers:                │                                     │
       │    X-API-Key: sk-xxx     │                                     │
       │  Body: {user_sub,        │                                     │
       │    agent_id, build_hash, │                                     │
       │    ...}                  │                                     │
       │ ────────────────────────>│                                     │
       │                          │                                     │
       │                     ┌────┴────────────────────┐                │
       │                     │ 1. AuthMiddleware:       │                │
       │                     │    validate X-API-Key    │                │
       │                     │    → resolve tenant_id   │                │
       │                     │                          │                │
       │                     │ 2. Rate limit check:     │                │
       │                     │    60/min, 100k/day      │                │
       │                     │                          │                │
       │                     │ 3. mint_agent_token():   │                │
       │                     │    sign JWT (EdDSA)      │                │
       │                     │    tenant_id LOCKED to   │                │
       │                     │    API key (no override) │                │
       │                     └────┬────────────────────┘                │
       │                          │                                     │
       │  200 OK                  │                                     │
       │  {                       │                                     │
       │   "agent_token": "eyJ..",│                                     │
       │   "expires_in": 600      │                                     │
       │  }                       │                                     │
       │ <────────────────────────│                                     │
       │                          │                                     │
       │                          │                                     │
       │  STEP 2: Mint Capability │                                     │
       │  ─────────────────────── │                                     │
       │  (BEFORE the LLM sees   │                                     │
       │   user input — prevents  │                                     │
       │   prompt injection)      │                                     │
       │                          │                                     │
       │  POST /v1/shield/        │                                     │
       │    cap/mint              │                                     │
       │  Headers:                │                                     │
       │    X-Agent-Token: eyJ..  │                                     │
       │    X-API-Key: sk-xxx     │                                     │
       │  Body: {                 │                                     │
       │    tool: "send_email",   │                                     │
       │    resource: "user/42",  │                                     │
       │    clearance_max:        │                                     │
       │      "internal"          │                                     │
       │  }                       │                                     │
       │ ────────────────────────>│                                     │
       │                          │                                     │
       │                     ┌────┴────────────────────┐                │
       │                     │ 1. AgentIdentityMW:     │                │
       │                     │    verify_agent_token() │                │
       │                     │    → IdentityTuple      │                │
       │                     │                          │                │
       │                     │ 2. Rate limit check:     │                │
       │                     │    600/min per instance  │                │
       │                     │                          │                │
       │                     │ 3. _decide_authz():      │                │
       │                     │    ├─ RBAC role→tool     │                │
       │                     │    ├─ RBAC role→data     │                │
       │                     │    └─ clearance ceiling  │                │
       │                     │                          │                │
       │                     │ 4. If allowed:           │                │
       │                     │    mint_cap() → JWT      │                │
       │                     │    (separate Ed25519 key)│                │
       │                     └────┬────────────────────┘                │
       │                          │                                     │
       │  200 OK                  │                                     │
       │  {                       │                                     │
       │   "cap_token": "eyJ..",  │                                     │
       │   "expires_in": 30,      │                                     │
       │   "decision": {          │                                     │
       │     "allowed": true,     │                                     │
       │     "tool": "send_email",│                                     │
       │     "resource": "user/42"│                                     │
       │   }                      │                                     │
       │  }                       │                                     │
       │ <────────────────────────│                                     │
       │                          │                                     │
       │                          │                                     │
       │  STEP 3: Call Tool with Cap                                    │
       │  ──────────────────────────────────────────────                │
       │                          │                                     │
       │  Agent passes cap_token  │                                     │
       │  to the tool server      │                                     │
       │  (bearer credential)     │                                     │
       │ ──────────────────────────────────────────────>│                │
       │                          │                     │                │
       │                          │                ┌────┴──────────┐    │
       │                          │                │ Tool verifies │    │
       │                          │                │ cap BEFORE    │    │
       │                          │                │ executing:    │    │
       │                          │                │               │    │
       │                          │  POST /v1/shield/cap/verify    │    │
       │                          │  {cap_token, expected_tool}    │    │
       │                          │ <─────────────────────────────│    │
       │                          │                               │    │
       │                     ┌────┴────────────────────┐          │    │
       │                     │ Verification checks:     │          │    │
       │                     │  1. Ed25519 signature    │          │    │
       │                     │  2. Not expired (≤60s)   │          │    │
       │                     │  3. Tool name matches    │          │    │
       │                     │  4. Resource matches     │          │    │
       │                     │  5. Cap not revoked      │          │    │
       │                     │  6. Nonce burn (one-shot)│          │    │
       │                     └────┬────────────────────┘          │    │
       │                          │                               │    │
       │                          │  {valid: true, claims: {...}} │    │
       │                          │ ─────────────────────────────>│    │
       │                          │                               │    │
       │                          │                │ Tool executes│    │
       │                          │                │ send_email   │    │
       │                          │                └────┬─────────┘    │
       │                          │                     │              │
       │  Result                  │                     │              │
       │ <──────────────────────────────────────────────│              │
       │                          │                                    │
       ▼                          ▼                                    ▼
```

---

## Step 1: Get Agent Token (AuthN)

### SUCCESS

```http
POST /v1/tenant/me/agent-auth/agent-token
X-API-Key: sk-tenant-prod-abc123
Content-Type: application/json

{
  "user_sub":           "user-42",           // OIDC sub of the human
  "agent_id":           "billing-bot",       // logical agent identity
  "agent_instance_id":  "inst-abc-001",      // unique per process
  "build_hash":         "sha256:a1b2c3d4",   // exact code build
  "model_version":      "claude-opus-4",     // LLM version
  "session_id":         "sess-789",          // conversation ID
  "ttl_seconds":        600                  // 10 min (max: 900)
}
```

```http
HTTP/1.1 200 OK

{
  "agent_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImVudiJ9.eyJhZ2...",
  "expires_in": 600
}
```

The token is a **standard JWT** with `alg: EdDSA` — verifiable by any JWT library:

```
┌─────────────────────────────────────────────────────────────────┐
│  JWT Header                                                     │
│  {"alg": "EdDSA", "typ": "JWT", "kid": "env"}                  │
├─────────────────────────────────────────────────────────────────┤
│  JWT Payload                                                    │
│  {                                                              │
│    "iss": "shield",               ← issuer binding              │
│    "aud": "shield-agent-tokens",  ← audience binding            │
│    "user_sub": "user-42",                                       │
│    "agent_id": "billing-bot",                                   │
│    "tenant_id": "tenant-1",       ← LOCKED to API key           │
│    "build_hash": "sha256:a1b2c3d4",                             │
│    "exp": 1748192400,             ← 10 min from now              │
│    "jti": "a1b2c3d4e5f6...",      ← revocable token ID          │
│    ...                                                          │
│  }                                                              │
├─────────────────────────────────────────────────────────────────┤
│  Ed25519 Signature (64 bytes)                                   │
└─────────────────────────────────────────────────────────────────┘
```

### FAILURES

```
  ┌──────────────────────────────────────────────────────────────────┐
  │                  STEP 1 FAILURE MODES                            │
  ├──────────────────────┬───────┬───────────────────────────────────┤
  │  Scenario            │ Code  │ Response                          │
  ├──────────────────────┼───────┼───────────────────────────────────┤
  │  No X-API-Key        │ 401   │ {"detail":"Tenant API key         │
  │  header sent         │       │  required"}                       │
  ├──────────────────────┼───────┼───────────────────────────────────┤
  │  Invalid API key     │ 403   │ {"detail":"invalid api key"}      │
  │                      │       │                                   │
  ├──────────────────────┼───────┼───────────────────────────────────┤
  │  Missing required    │ 422   │ {"detail":[{"loc":["body",        │
  │  fields (e.g.        │       │  "agent_instance_id"],"msg":      │
  │  agent_instance_id)  │       │  "field required"...}]}           │
  ├──────────────────────┼───────┼───────────────────────────────────┤
  │  Rate limit hit      │ 429   │ {"detail":"rate limit exceeded    │
  │  (>60/min)           │       │  (token issuance)"}               │
  ├──────────────────────┼───────┼───────────────────────────────────┤
  │  TTL too large       │ 422   │ {"detail":[{"loc":["body",        │
  │  (>900s)             │       │  "ttl_seconds"],"msg":            │
  │                      │       │  "≤ 900"...}]}                    │
  ├──────────────────────┼───────┼───────────────────────────────────┤
  │  Empty user_sub or   │ 400   │ {"detail":"missing required       │
  │  agent_id            │       │  claim"}                          │
  └──────────────────────┴───────┴───────────────────────────────────┘
```

---

## Step 2: Mint Capability Token (AuthZ)

### SUCCESS

```http
POST /v1/shield/cap/mint
X-Agent-Token: eyJhbGciOiJFZERTQSIs...       <-- from Step 1
X-API-Key: sk-tenant-prod-abc123
Content-Type: application/json

{
  "tool":              "send_email",           // exact tool name
  "resource":          "user/42/inbox",        // exact target
  "clearance_max":     "internal",             // data ceiling
  "scope_constraints": ["to:billing@co.com"],  // scope narrowing
  "ttl_seconds":       30                      // max: 60
}
```

```http
HTTP/1.1 200 OK

{
  "cap_token": "eyJhbGciOiJFZERTQSIs...",
  "expires_in": 30,
  "decision": {
    "allowed": true,
    "tool": "send_email",
    "resource": "user/42/inbox"
  }
}
```

Cap token internals:

```
┌─────────────────────────────────────────────────────────────────┐
│  Cap JWT Claims                                                 │
│  {                                                              │
│    "aud": "shield-capabilities",  ← DIFFERENT from agent token  │
│    "tool": "send_email",          ← exact, not wildcard         │
│    "resource": "user/42/inbox",   ← exact target                │
│    "scope": ["to:billing@co.com"],← constraints                 │
│    "clearance_max": "internal",   ← data ceiling                │
│    "nonce": "f7a8b9c0...",        ← one-shot (burned on verify) │
│    "exp": 1748191230,             ← 30 seconds from now         │
│    "cap_id": "d4e5f6...",         ← revocable                   │
│    ...identity fields baked in from AuthN...                    │
│  }                                                              │
│                                                                 │
│  Signed with SEPARATE Ed25519 key (not the agent token key)     │
│  → compromised tool cannot forge identity tokens                │
└─────────────────────────────────────────────────────────────────┘
```

### FAILURES

```
  ┌──────────────────────────────────────────────────────────────────┐
  │                  STEP 2 FAILURE MODES                            │
  ├──────────────────────┬───────┬───────────────────────────────────┤
  │  Scenario            │ Code  │ Response                          │
  ├──────────────────────┼───────┼───────────────────────────────────┤
  │  No X-Agent-Token    │ 401   │ {"detail":"No verified agent      │
  │                      │       │  identity. Send a signed          │
  │                      │       │  X-Agent-Token."}                 │
  ├──────────────────────┼───────┼───────────────────────────────────┤
  │  Expired agent token │ 401   │ {"error":"invalid_agent_token",   │
  │  (>15 min old)       │       │  "detail":"token expired"}        │
  ├──────────────────────┼───────┼───────────────────────────────────┤
  │  Revoked instance    │ 401   │ {"error":"invalid_agent_token",   │
  │                      │       │  "detail":"agent_instance_id      │
  │                      │       │  revoked"}                        │
  ├──────────────────────┼───────┼───────────────────────────────────┤
  │  Tampered agent      │ 401   │ {"error":"invalid_agent_token",   │
  │  token               │       │  "detail":"invalid signature"}    │
  ├──────────────────────┼───────┼───────────────────────────────────┤
  │  RBAC: tool denied   │ 403   │ {"detail":"authz_denied"}         │
  │  for this role       │       │ (reasons hidden by default,       │
  │                      │       │  full reasons in audit log)       │
  ├──────────────────────┼───────┼───────────────────────────────────┤
  │  Clearance exceeds   │ 403   │ {"detail":"authz_denied"}         │
  │  role's data ceiling │       │                                   │
  ├──────────────────────┼───────┼───────────────────────────────────┤
  │  Cap mint rate limit │ 429   │ {"detail":"rate limit exceeded"}  │
  │  (>600/min/instance) │       │                                   │
  └──────────────────────┴───────┴───────────────────────────────────┘
```

---

## Step 3: Verify Cap at Tool Server

### SUCCESS

```http
POST /v1/shield/cap/verify
Content-Type: application/json

{
  "cap_token":          "eyJhbGciOiJFZERTQSIs...",
  "expected_tool":      "send_email",
  "expected_resource":  "user/42/inbox"         // optional strict check
}
```

No auth headers needed — the cap IS the credential.

```http
HTTP/1.1 200 OK

{
  "valid": true,
  "claims": {
    "user_sub": "user-42",
    "agent_id": "billing-bot",
    "agent_instance_id": "inst-abc-001",
    "tool": "send_email",
    "resource": "user/42/inbox",
    "scope": ["to:billing@co.com"],
    "clearance_max": "internal",
    "tenant_id": "tenant-1",
    "cap_id": "d4e5f6...",
    "exp": 1748191230
  },
  "error": null
}
```

### FAILURES (always HTTP 200 — check the `valid` field)

```
  ┌──────────────────────────────────────────────────────────────────┐
  │                  STEP 3 FAILURE MODES                            │
  │  (All return HTTP 200 with valid=false and error message)        │
  ├──────────────────────┬──────────────────────────────────────────┤
  │  Scenario            │ error                                    │
  ├──────────────────────┼──────────────────────────────────────────┤
  │  Replay attack       │ "cap replay detected (nonce already      │
  │  (same cap twice)    │  used)"                                  │
  ├──────────────────────┼──────────────────────────────────────────┤
  │  Wrong tool name     │ "cap tool mismatch: token='send_email'   │
  │                      │  expected='delete_user'"                 │
  ├──────────────────────┼──────────────────────────────────────────┤
  │  Wrong resource      │ "cap resource mismatch:                  │
  │                      │  token='user/42/inbox'                   │
  │                      │  expected='admin/settings'"              │
  ├──────────────────────┼──────────────────────────────────────────┤
  │  Tampered JWT        │ "invalid signature"                      │
  │                      │                                          │
  ├──────────────────────┼──────────────────────────────────────────┤
  │  Expired cap         │ "token expired"                          │
  │  (>60s + 2s skew)    │                                          │
  ├──────────────────────┼──────────────────────────────────────────┤
  │  Revoked cap_id      │ "cap revoked"                            │
  │                      │                                          │
  ├──────────────────────┼──────────────────────────────────────────┤
  │  Retired signing key │ "cap kid retired: cap-env"               │
  │                      │                                          │
  └──────────────────────┴──────────────────────────────────────────┘
```

---

## Step 4: Emergency Revocation

Three independent kill switches, any combination:

```
  POST /v1/shield/auth/revoke
  X-Admin-Key: <admin-key>

  ┌──────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │  AXIS 1: Kill one process                                       │
  │  {"agent_instance_id": "inst-abc-001"}                          │
  │  → All tokens for inst-abc-001 fail on next verify              │
  │                                                                  │
  │  AXIS 2: Kill one user                                          │
  │  {"user_sub": "user-42"}                                        │
  │  → ALL tokens for user-42 (across all agents) fail              │
  │                                                                  │
  │  AXIS 3: Kill one token                                         │
  │  {"jti": "a1b2c3d4..."}                                        │
  │  → Only that specific token/cap fails                           │
  │                                                                  │
  │  Effect: immediate (next verify call checks revocation)          │
  │  TTL: 3600s default (auto-cleans after token would have expired) │
  │                                                                  │
  └──────────────────────────────────────────────────────────────────┘
```

---

## Full Lifecycle Diagram

```
  TIME ──────────────────────────────────────────────────────────────────────►

  CUSTOMER AGENT                    LLM SHIELD                   TOOL SERVER
  ══════════════                    ══════════                   ═══════════

  Boot up
  ──────
  │
  │ ░░░ STEP 1: AuthN ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
  │
  │ POST /v1/tenant/me/agent-auth/agent-token
  │ X-API-Key: sk-xxx
  │ {user_sub, agent_id, ...}
  │ ─────────────────────────────────►
  │                                   validate API key
  │                                   rate limit check
  │                                   mint JWT (EdDSA)
  │ ◄─────────────────────────────────
  │ {agent_token, expires_in: 600}
  │
  │ Store agent_token (refresh before expiry)
  │
  │
  │ User sends a message:
  │ "Send the Q4 invoice to billing@acme.com"
  │
  │
  │ ▓▓▓ STEP 2: AuthZ (BEFORE LLM processes the message) ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
  │
  │ POST /v1/shield/cap/mint
  │ X-Agent-Token: eyJ...
  │ {tool: "send_email",
  │  resource: "billing@acme.com",
  │  clearance_max: "internal"}
  │ ─────────────────────────────────►
  │                                   verify agent token
  │                                   RBAC: role→tool check
  │                                   clearance ceiling check
  │                                   mint cap JWT (separate key)
  │ ◄─────────────────────────────────
  │ {cap_token, expires_in: 30}
  │
  │
  │ ███ STEP 3: Execute with Cap ████████████████████████████████████████████
  │
  │ Call tool with cap_token as bearer
  │ ──────────────────────────────────────────────────────►
  │                                                        │
  │                                                        │ POST /cap/verify
  │                                                        │ {cap_token,
  │                                                        │  expected_tool:
  │                                   ◄────────────────────│  "send_email"}
  │                                   sig check            │
  │                                   expiry check         │
  │                                   tool match           │
  │                                   nonce burn           │
  │                                   ────────────────────►│
  │                                   {valid: true}        │
  │                                                        │
  │                                                        │ Execute
  │                                                        │ send_email(...)
  │ ◄──────────────────────────────────────────────────────│
  │ Result: email sent                                     │
  │
  │
  │ ░▓█ STEP 3b: Replay blocked █▓░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
  │
  │ Attacker tries to reuse the same cap_token
  │ ──────────────────────────────────────────────────────►
  │                                                        │ POST /cap/verify
  │                                   ◄────────────────────│ (same cap)
  │                                   nonce already burned │
  │                                   ────────────────────►│
  │                                   {valid: false,       │
  │                                    error: "replay      │
  │                                    detected"}          │
  │                                                        │ REJECT
  │ ◄──────────────────────────────────────────────────────│
  │ Error: action denied
  │
  │
  │ ░▓█ STEP 4: Revocation ░░▓▓▓███████████████████████████████████████████░
  │
  │                      POST /v1/shield/auth/revoke
  │                      X-Admin-Key: xxx
  │                      {agent_instance_id: "inst-abc-001"}
  │                      ◄──────────────────────────── (admin/portal)
  │                                   │
  │                                   store revocation in Redis
  │                                   │
  │ Tries to mint new cap             │
  │ POST /v1/shield/cap/mint ────────►│
  │                                   verify_agent_token()
  │                                   → "agent_instance_id revoked"
  │ ◄─────────────────────────────────│
  │ 401: agent_instance_id revoked    │
  │                                   │
  ▼                                   ▼                                    ▼
```

---

## OAuth 2.1 / MCP Flow (Alternative to API-Key)

For MCP clients and external integrations, Shield supports standard
OAuth 2.1 with PKCE:

```
  ┌──────────┐                         ┌─────────────────┐
  │ MCP      │                         │   LLM SHIELD    │
  │ Client   │                         │   OAuth Server  │
  └────┬─────┘                         └────────┬────────┘
       │                                        │
       │ 1. Discover OAuth metadata             │
       │ GET /.well-known/                      │
       │   oauth-authorization-server           │
       │ ──────────────────────────────────────►│
       │ ◄──────────────────────────────────────│
       │ {authorization_endpoint,               │
       │  token_endpoint, jwks_uri, ...}        │
       │                                        │
       │ 2. Register client (RFC 7591)          │
       │ POST /oauth/register                   │
       │ {client_name, redirect_uris, ...}      │
       │ ──────────────────────────────────────►│
       │ ◄──────────────────────────────────────│
       │ {client_id: "shield-abc123"}           │
       │                                        │
       │ 3. Authorization request (with PKCE)   │
       │ GET /oauth/authorize                   │
       │   ?response_type=code                  │
       │   &client_id=shield-abc123             │
       │   &code_challenge=<S256_hash>          │
       │   &code_challenge_method=S256          │
       │   &redirect_uri=http://localhost/cb    │
       │ ──────────────────────────────────────►│
       │ ◄──────────────────────────────────────│
       │ 302 redirect with ?code=xxx&state=yyy  │
       │                                        │
       │ 4. Exchange code for tokens            │
       │ POST /oauth/token                      │
       │ {grant_type: "authorization_code",     │
       │  code: "xxx",                          │
       │  code_verifier: "<original_verifier>", │
       │  client_id: "shield-abc123",           │
       │  redirect_uri: "http://localhost/cb"}  │
       │ ──────────────────────────────────────►│
       │ ◄──────────────────────────────────────│
       │ {access_token: "eyJ...",               │
       │  token_type: "Bearer",                 │
       │  expires_in: 600,                      │
       │  refresh_token: "xxx"}                 │
       │                                        │
       │ 5. Use access token for MCP calls      │
       │ POST /mcp/message                      │
       │ Authorization: Bearer eyJ...           │
       │ ──────────────────────────────────────►│
       │                                        │
       │ 6. Fetch JWKS for local verification   │
       │ GET /oauth/jwks                        │
       │ ──────────────────────────────────────►│
       │ ◄──────────────────────────────────────│
       │ {"keys": [{"kty":"OKP","crv":"Ed25519",│
       │   "x":"...", "kid":"env", ...}]}       │
       │                                        │
       ▼                                        ▼
```

---

## Token Exchange (RFC 8693) — Enterprise IdP Integration

For customers with existing IdPs (Keycloak, Okta, Auth0, Azure AD):

```
  ┌──────────┐     ┌──────────┐     ┌─────────────────┐
  │ Customer │     │ External │     │   LLM SHIELD    │
  │  Agent   │     │   IdP    │     │   Token Exch.   │
  └────┬─────┘     └────┬─────┘     └────────┬────────┘
       │                │                     │
       │ 1. Authenticate│with IdP             │
       │ ──────────────►│                     │
       │ ◄──────────────│                     │
       │ id_token (JWT) │                     │
       │                │                     │
       │ 2. Exchange id_token for Shield token│
       │ POST /oauth/token                    │
       │ {grant_type: "urn:ietf:params:       │
       │    oauth:grant-type:token-exchange",  │
       │  subject_token: "<id_token_from_idp>",│
       │  subject_token_type: "urn:ietf:       │
       │    params:oauth:token-type:id_token"} │
       │ ────────────────────────────────────►│
       │                                      │
       │                       ┌──────────────┤
       │                       │ Validate     │
       │                       │ id_token:    │
       │                       │  - fetch JWKS│
       │                       │    from IdP  │
       │                       │  - verify sig│
       │                       │  - check iss │
       │                       │  - check aud │
       │                       │  - map claims│
       │                       │ Mint Shield  │
       │                       │ access token │
       │                       └──────────────┤
       │                                      │
       │ ◄────────────────────────────────────│
       │ {access_token: "eyJ...",             │
       │  issued_token_type: "...access_token",│
       │  token_type: "Bearer",               │
       │  expires_in: 600}                    │
       │                                      │
       │ Now use access_token as agent token  │
       ▼                                      ▼
```

---

## Security Architecture Summary

```
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                     DEFENSE-IN-DEPTH LAYERS                            │
  ├─────────────────────────────────────────────────────────────────────────┤
  │                                                                        │
  │  ┌─── Transport ──────────────────────────────────────────────────┐    │
  │  │  mTLS (workload-to-workload)                                   │    │
  │  │  SPIFFE SVID (workload identity)                               │    │
  │  │                                                                 │    │
  │  │  ┌─── AuthN ─────────────────────────────────────────────┐     │    │
  │  │  │  Agent Token (JWT EdDSA, ≤15 min)                     │     │    │
  │  │  │  3 revocation axes: instance | user | jti             │     │    │
  │  │  │  Build hash allowlist                                  │     │    │
  │  │  │  iss/aud binding (cross-deployment defense)            │     │    │
  │  │  │                                                        │     │    │
  │  │  │  ┌─── AuthZ ────────────────────────────────────┐     │     │    │
  │  │  │  │  Capability Token (JWT EdDSA, ≤60s)          │     │     │    │
  │  │  │  │  SEPARATE signing key from agent tokens      │     │     │    │
  │  │  │  │  SEPARATE audience ("shield-capabilities")   │     │     │    │
  │  │  │  │  Single-use nonce (replay-proof)             │     │     │    │
  │  │  │  │  Exact tool+resource binding (no wildcards)  │     │     │    │
  │  │  │  │  RBAC role→tool, role→data, clearance ceiling│     │     │    │
  │  │  │  │                                              │     │     │    │
  │  │  │  │  ┌─── Enforcement ─────────────────────┐    │     │     │    │
  │  │  │  │  │  Tool verifies cap before executing │    │     │     │    │
  │  │  │  │  │  Scope intersection (no widening)   │    │     │     │    │
  │  │  │  │  │  Per-action audit trail             │    │     │     │    │
  │  │  │  │  └─────────────────────────────────────┘    │     │     │    │
  │  │  │  └──────────────────────────────────────────────┘     │     │    │
  │  │  └───────────────────────────────────────────────────────┘     │    │
  │  └─────────────────────────────────────────────────────────────────┘    │
  │                                                                        │
  │  Rate Limits:  token issuance 60/min · cap minting 600/min/instance    │
  │  Key Rotation: kid claim + SHIELD_RETIRED_KIDS blocklist               │
  │  Denial Mode:  reasons hidden (M3), full reasons in audit log only     │
  │                                                                        │
  └─────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Reference: All Endpoints

```
  ┌──────────────────────────────────────────────────────────────────────────┐
  │  CUSTOMER ENDPOINTS (tenant API key)                                    │
  ├────────┬───────────────────────────────────────────┬────────────────────┤
  │ Method │ Path                                      │ Auth               │
  ├────────┼───────────────────────────────────────────┼────────────────────┤
  │ POST   │ /v1/tenant/me/agent-auth/agent-token      │ X-API-Key          │
  │ POST   │ /v1/shield/cap/mint                       │ X-Agent-Token      │
  │ POST   │ /v1/shield/cap/verify                     │ (none — cap=bearer)│
  │ GET    │ /v1/tenant/me/agent-auth/stats             │ X-API-Key          │
  │ GET    │ /v1/tenant/me/agent-auth/recent            │ X-API-Key          │
  ├────────┴───────────────────────────────────────────┴────────────────────┤
  │  OAUTH 2.1 ENDPOINTS (MCP / standard clients)                          │
  ├────────┬───────────────────────────────────────────┬────────────────────┤
  │ GET    │ /.well-known/oauth-authorization-server    │ (none)             │
  │ POST   │ /oauth/register                            │ (none or reg token)│
  │ GET    │ /oauth/authorize                           │ (none — redirects) │
  │ POST   │ /oauth/token                               │ (none)             │
  │ GET    │ /oauth/jwks                                │ (none)             │
  │ POST   │ /oauth/revoke                              │ (none)             │
  ├────────┴───────────────────────────────────────────┴────────────────────┤
  │  A2A ENDPOINTS (inter-agent communication)                              │
  ├────────┬───────────────────────────────────────────┬────────────────────┤
  │ GET    │ /.well-known/agent.json                    │ (none)             │
  │ POST   │ /a2a/tasks/send                            │ Bearer / X-API-Key │
  │ GET    │ /a2a/tasks/{id}                            │ Bearer / X-API-Key │
  │ POST   │ /a2a/tasks/{id}/cancel                     │ Bearer / X-API-Key │
  ├────────┴───────────────────────────────────────────┴────────────────────┤
  │  ADMIN ENDPOINTS (break-glass)                                          │
  ├────────┬───────────────────────────────────────────┬────────────────────┤
  │ POST   │ /v1/shield/auth/agent-token                │ X-Admin-Key        │
  │ POST   │ /v1/shield/auth/revoke                     │ X-Admin-Key        │
  └────────┴───────────────────────────────────────────┴────────────────────┘
```
