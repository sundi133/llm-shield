# Votal Shield — Agent IDP architecture

This doc shows how Shield acts as an Agent Identity Provider: the
components, the data flow for a typical delegated tool call, the
network topology, and the wire-level payloads at each hop.

---

## 1. Component map

Shield sits between your existing human IdP and the resources your
agents need to touch. Humans keep authenticating to Okta / Entra / Ping;
Shield takes that human identity, binds it to an agent identity through
a delegation chain, and brokers every downstream tool call.

```mermaid
flowchart TB
    subgraph Humans["Humans"]
        H[Human user]
        IdP["Human IdP<br/>(Okta / Entra / Ping)"]
    end
    H -->|browser SSO| IdP

    subgraph Agents["AI workloads"]
        A1[AI agent<br/>user-delegated]
        A2[AI agent<br/>autonomous / M2M]
    end

    subgraph Shield["Votal Shield — Agent IDP"]
        direction TB

        subgraph IdReg["Identity & registration"]
            REG[Agent registry<br/>owner_email required]
            BP[Blueprints<br/>template → instances]
            SHADOW[Shadow agent<br/>discovery]
            CARD[A2A Agent Card<br/>/.well-known/agent.json]
        end

        subgraph AuthN["Authentication"]
            OAUTH["OAuth 2.1 AS<br/>auth_code · client_credentials<br/>refresh · token-exchange (RFC 8693)"]
            OIDC[OIDC client to<br/>external IdPs]
            AGT[Agent-token signer<br/>Ed25519 · RFC 8693 act chain]
            MTLS[mTLS / SPIFFE<br/>workload identity]
        end

        subgraph AuthZ["Authorization (runtime PDP)"]
            CAP[Capability mint/verify<br/>JIT · exp ≤ 60s · nonce-burn]
            RBAC[RBAC + delegation<br/>intersection]
            APPR[Step-up / HITL<br/>approvals]
        end

        subgraph Gov["Governance & audit"]
            KILL[Kill switch<br/>instance · jti · user]
            AUDIT[Signed audit log<br/>principal.type tagging]
            TEL[Telemetry pipeline<br/>OTLP / ES / HEC]
        end
    end

    subgraph Resources["Downstream"]
        APIS[APIs & tools]
        MCP[MCP servers]
        DATA[Data sources]
        OTHER[Other agents]
    end

    SIEM[(SIEM<br/>Splunk / ES / Datadog)]

    IdP -->|id_token| OIDC
    A1 -.->|register| REG
    A1 -->|X-API-Key| OAUTH
    A2 -->|client_credentials| OAUTH
    A1 -.->|mTLS cert| MTLS

    OIDC --> AGT
    OAUTH --> AGT
    AGT --> CAP
    RBAC --> CAP
    APPR --> CAP
    KILL --> CAP
    BP --> REG
    SHADOW -.->|discover| REG

    CAP -->|capability token| APIS
    CAP -->|capability token| MCP
    CAP -->|capability token| DATA
    CARD -.->|discovery| OTHER

    AGT --> AUDIT
    CAP --> AUDIT
    APIS -.->|verify result| AUDIT
    AUDIT --> TEL --> SIEM
```

Two enforcement zones to keep clear in your head:

| Zone     | What it proves       | Lifetime | Format                           |
|----------|----------------------|----------|----------------------------------|
| **AuthN** | who is calling      | ≤ 15 min | Agent token (JWT, EdDSA, `act` chain) |
| **AuthZ** | what may be done    | ≤ 60 s   | Capability token (single tool call, nonce-burned) |

---

## 2. End-to-end data flow — delegated tool call

A user clicks "summarize my invoices and email accounting." The agent
must hit two tools (`list_invoices`, `send_email`) on her behalf. Every
arrow is a real HTTP call.

```mermaid
sequenceDiagram
    autonumber
    participant U as Human user
    participant IDP as Okta / Entra
    participant APP as Agent runtime
    participant SHL as Shield (Agent IDP)
    participant T1 as Tool: list_invoices
    participant T2 as Tool: send_email
    participant SIEM as SIEM

    U->>IDP: 1. Browser SSO
    IDP-->>U: id_token (OIDC)
    U->>APP: 2. "Summarize my invoices and email accounting"
    APP->>SHL: 3. POST /oauth/token<br/>grant_type=urn:ietf:params:oauth:grant-type:token-exchange<br/>subject_token=<id_token>
    SHL->>IDP: 4. Validate id_token via JWKS
    IDP-->>SHL: signature + claims OK
    SHL-->>APP: access_token (Shield OAuth, 10m)

    APP->>SHL: 5. POST /v1/tenant/me/agent-auth/agent-token<br/>X-API-Key: <tenant key><br/>{ user_sub, agent_id, instance_id, ... }
    SHL-->>APP: signed agent_token (JWT, 10m, carries `act` chain)

    Note over APP,SHL: Tool call #1 — list_invoices
    APP->>SHL: 6. POST /v1/shield/cap/mint<br/>X-Agent-Token<br/>{ tool: "list_invoices", resource: "user:alice/invoices" }
    SHL->>SHL: PDP: RBAC ∩ delegation ∩ taint ∩ kill-switch
    SHL-->>APP: cap_token (≤60s, single-shot)
    APP->>T1: GET /invoices  X-Cap-Token: <cap>
    T1->>SHL: 7. POST /v1/shield/cap/verify
    SHL-->>T1: valid=true, claims
    T1-->>APP: invoice list

    Note over APP,SHL: Tool call #2 — send_email (sensitive, triggers HITL)
    APP->>SHL: 8. POST /v1/shield/cap/mint<br/>{ tool: "send_email", to: "ap@acme.com", body_hash }
    SHL-->>APP: 202 pending_confirmation,<br/>approval_request_id
    SHL-)U: 9. step-up prompt (mobile push / web)
    U-->>SHL: approve
    APP->>SHL: 10. POST /v1/shield/cap/mint<br/>{ ..., approval_request_id }
    SHL-->>APP: cap_token
    APP->>T2: POST /email   X-Cap-Token: <cap>
    T2->>SHL: cap/verify → valid=true
    T2-->>APP: 200 sent

    SHL-)SIEM: 11. signed audit rows<br/>principal.type=agent<br/>act chain attached
```

### What changes on each step

| Step | Carries WHO  | Carries WHAT permission | Lifetime |
|------|--------------|-------------------------|----------|
| 1–2  | human only   | (none yet)              | session  |
| 3–4  | human only   | scope=shield            | 10 min   |
| 5    | human + agent (`act` chain) | (none — AuthN) | 10 min   |
| 6, 10 | human + agent + tool + resource | one tool call | ≤ 60 s |
| 7    | verifier-side decision | nonce burned         | one-shot |

---

## 3. Network flow & ports

```
                 ┌─────────────────────────────────────────────┐
                 │             Customer VPC / cluster          │
                 │                                             │
   Browser ──TLS 443──▶  Okta / Entra (cloud)                 │
                 │      │                                       │
                 │      └──id_token──▶                          │
                 │                                              │
   Agent host ──TLS 8080──▶ ┌─────────────────────┐            │
   (or mTLS via             │  Shield gateway     │            │
    SPIFFE SVID)            │  (FastAPI worker)   │            │
                 │          │                     │            │
                 │          │  /oauth/* (AuthN)   │            │
                 │          │  /v1/shield/cap/*   │            │
                 │          │  /v1/agents/*       │            │
                 │          │  /v1/agents/        │            │
                 │          │     blueprints/*    │            │
                 │          │  /.well-known/      │            │
                 │          │     agent.json (A2A)│            │
                 │          └────┬─────────┬──────┘            │
                 │               │         │                    │
                 │               │ TCP 6379 (Redis, TLS opt.)   │
                 │               ▼                              │
                 │      ┌─────────────────┐                     │
                 │      │  Redis / Upstash │                    │
                 │      │  tenants, keys,  │                    │
                 │      │  agents, caps,   │                    │
                 │      │  revocation      │                    │
                 │      └─────────────────┘                     │
                 │                                              │
                 │   Outbound HTTPS:                            │
                 │   - JWKS to external IdP                     │
                 │   - OTLP/HEC/ES → SIEM (port per backend)    │
                 │                                              │
   Tool servers ──TLS 443──▶ Shield  /v1/shield/cap/verify     │
   (out-of-cluster)                                             │
                 └─────────────────────────────────────────────┘
```

### Auth method per network hop

| Source → destination               | Wire auth              | What's bound to the call |
|------------------------------------|------------------------|--------------------------|
| Browser → Okta                     | OIDC (TLS)             | human session             |
| Agent host → Shield `/oauth/*`     | API key OR mTLS        | tenant ID                 |
| Agent host → Shield `/cap/mint`    | `X-Agent-Token` (JWT)  | human + agent + parent    |
| Agent host → Tool                  | `X-Cap-Token` (JWT)    | one-shot capability       |
| Tool → Shield `/cap/verify`        | none (cap is bearer)   | the cap itself            |
| Shield → external OIDC JWKS        | TLS                    | issuer's public keys      |
| Shield → SIEM                      | OTLP / HEC / ES (TLS)  | signed batch              |

---

## 4. Payloads at each hop

### 4.1 Token-exchange (human id_token → Shield access token)

```http
POST /oauth/token  HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange
&subject_token=eyJhbGciOiJSUzI1NiIsImtpZCI6Im9rdGEta2lkLTAxIn0...
&subject_token_type=urn:ietf:params:oauth:token-type:id_token
&audience=shield
```

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImVudiJ9...",
  "token_type": "Bearer",
  "expires_in": 600,
  "scope": "shield"
}
```

### 4.2 Autonomous M2M — `client_credentials`

```http
POST /oauth/token  HTTP/1.1
Authorization: Basic c2hpZWxkLWFiYzpzM2NyZXQ=

grant_type=client_credentials&scope=guardrails
```

```json
{
  "access_token": "eyJhbGciOiJFZERTQSI...",
  "token_type": "Bearer",
  "expires_in": 600,
  "scope": "guardrails"
}
```

Decoded JWT payload — note `sub=client:<id>` so audit can tell the
caller apart from a human:

```json
{
  "iss": "shield",
  "aud": "shield-oauth",
  "sub": "client:shield-abc",
  "client_id": "shield-abc",
  "tenant_id": "acme",
  "scope": "guardrails",
  "iat": 1748259600,
  "exp": 1748260200,
  "jti": "0f4c…",
  "token_type": "access_token"
}
```

### 4.3 Agent token — RFC 8693 `act` chain

Mint:

```http
POST /v1/tenant/me/agent-auth/agent-token  HTTP/1.1
X-API-Key: tk_live_acme_…
Content-Type: application/json

{
  "agent_id": "billing-bot",
  "agent_instance_id": "inst-7af",
  "parent_agent_id": "router-bot",
  "session_id": "sess-123",
  "build_hash": "sha256:9cf…",
  "model_version": "claude-opus-4.7"
}
```

Decoded JWT (`X-Agent-Token` value on subsequent calls):

```json
{
  "iss": "shield",
  "aud": "shield-agent-tokens",
  "sub": "alice@acme.com",
  "act": {
    "sub": "billing-bot",
    "agent_instance_id": "inst-7af",
    "act": { "sub": "router-bot" }
  },
  "user_sub": "alice@acme.com",
  "agent_id": "billing-bot",
  "agent_instance_id": "inst-7af",
  "parent_agent_id": "router-bot",
  "tenant_id": "acme",
  "build_hash": "sha256:9cf…",
  "model_version": "claude-opus-4.7",
  "session_id": "sess-123",
  "iat": 1748259600,
  "exp": 1748260200,
  "jti": "a31d…",
  "kid": "env"
}
```

### 4.4 Capability mint (PDP decision)

```http
POST /v1/shield/cap/mint  HTTP/1.1
X-Agent-Token: <agent JWT>
Content-Type: application/json

{
  "tool": "send_email",
  "resource": "mailbox:alice@acme.com",
  "scope": ["to:ap@acme.com", "subject_hash:5fa…"],
  "ttl_seconds": 30
}
```

Approved:

```json
{
  "cap_token": "eyJhbGciOiJFZERTQSI…",
  "expires_in": 30,
  "cap_id": "cap-7c9…",
  "decision": "allow"
}
```

Sensitive — requires step-up:

```json
{
  "decision": "pending_confirmation",
  "approval_request_id": "appr-d12…",
  "reason": "send_email to external domain requires owner approval",
  "expires_in": 300
}
```

After the human approves, the client retries `/cap/mint` with
`approval_request_id` and gets a real cap.

### 4.5 Capability verify (tool side)

```http
POST /v1/shield/cap/verify  HTTP/1.1
Content-Type: application/json

{ "cap_token": "eyJhbGciOiJFZERTQSI…", "tool": "send_email" }
```

```json
{
  "valid": true,
  "claims": {
    "sub": "alice@acme.com",
    "act": { "sub": "billing-bot" },
    "tool": "send_email",
    "resource": "mailbox:alice@acme.com",
    "scope": ["to:ap@acme.com", "subject_hash:5fa…"],
    "cap_id": "cap-7c9…",
    "exp": 1748259630
  }
}
```

Re-presenting the same `cap_token` returns `valid:false, reason:"nonce
already burned"` — single-shot.

### 4.6 Blueprint → instance

```http
POST /v1/agents/blueprints  HTTP/1.1
X-API-Key: tk_live_acme_…

{
  "blueprint_id": "support-tier1",
  "name": "Tier-1 Support Agent",
  "tools": ["lookup_order", "issue_refund_small"],
  "role_permissions": { "support": ["lookup_order", "issue_refund_small"] },
  "owner_email": "ops-lead@acme.com"
}
```

```http
POST /v1/agents/blueprints/support-tier1/instantiate
{ "agent_id": "support-tier1-eu-01" }
```

```json
{
  "success": true,
  "agent": {
    "agent_id": "support-tier1-eu-01",
    "tools": ["lookup_order", "issue_refund_small"],
    "owner_email": "ops-lead@acme.com",
    "blueprint_id": "support-tier1",
    "blueprint_version": 1,
    "status": "active",
    "created_at": 1748259600
  }
}
```

### 4.7 Audit event on the wire (one row, ES-shaped)

```json
{
  "@timestamp": "2026-05-26T17:00:30.142Z",
  "service.name": "votal-shield",
  "event.kind": "event",
  "event.action": "response",
  "event.category": "web",
  "event.outcome": "success",
  "trace.id": "9f3a2c1b8d4e",
  "url.path": "/v1/shield/cap/mint",
  "http.response.status_code": 200,
  "principal.type": "agent",
  "principal.id": "billing-bot",
  "agent.key": "billing-bot",
  "votal.tenant_id": "acme",
  "votal.session_id": "sess-123",
  "votal.action": "allow",
  "votal.latency_ms": 12.41,
  "votal.guardrail_count": 0
}
```

SIEM consumers split the human stream from the agent stream simply by
faceting on `principal.type`:

```kql
event.action: "response" AND principal.type: "agent"
| stats count by principal.id, votal.action
```

---

## 5. State that lives in Redis

| Key pattern                         | Purpose                                       |
|-------------------------------------|-----------------------------------------------|
| `agents:{tenant}`                   | Agent registry (now carries `owner_email`)    |
| `agent_blueprints:{tenant}`         | Blueprint templates                           |
| `unregistered:{tenant}`             | Shadow-agent sightings buffered by middleware |
| `shield:oauth:client:{client_id}`   | Registered OAuth clients (incl. m2m)          |
| `shield:oauth:authcode:{code}`      | Short-lived auth codes (PKCE)                 |
| `shield:oauth:refresh:{hash}`       | Refresh tokens (rotated on use)               |
| `shield:cap:burned:{cap_id}`        | Burned nonces (single-shot enforcement)       |
| `shield:revoke:instance:{id}`       | Instance kill-switch                          |
| `shield:revoke:jti:{jti}`           | Per-token revocation                          |
| `shield:revoke:user:{sub}`          | User-wide revocation                          |
| `policies:{tenant}`                 | Per-tool policy + data sanitization           |
| `approval:{request_id}`             | HITL approval state                           |

Everything is per-tenant scoped; no cross-tenant key reads.

---

## 6. Failure isolation

```
                          ┌────────────────────┐
   token mint fails  ───▶ │ AuthN denies       │ ───▶ 401, no audit gap
                          └────────────────────┘
                          ┌────────────────────┐
   policy denies     ───▶ │ AuthZ refuses cap  │ ───▶ 403 + audit row
                          └────────────────────┘
                          ┌────────────────────┐
   cap replayed      ───▶ │ Verify burns nonce │ ───▶ 401 + alert
                          └────────────────────┘
                          ┌────────────────────┐
   compromised agent ───▶ │ Kill switch on jti │ ───▶ all caps fail
                          │ / instance / user  │       within 1 verify
                          └────────────────────┘
```

---

## 7. Sovereign / on-prem mode (no cloud IdP)

When there is no Okta or Entra to lean on — air-gapped enterprise, gov,
defense — Shield's `/v1/shield/auth/agent-token` accepts three workload
auth methods in addition to the legacy admin key. They are all wired in
code today (`api/routes_agent_auth.py::_authenticate_caller`) and all
covered by tests.

| Mode | Caller proves identity by | What Shield checks | Trust source |
|---|---|---|---|
| **B — Federated OIDC** | sends `X-Id-Token` header carrying an id_token from your on-prem IdP (Keycloak / Dex / Authelia / ADFS / PingFederate) | issuer matches a tenant-registered provider, JWKS signature, `aud`, `exp`; maps claims via `provider.claim_mapping` | the IdP's local signing key (never leaves your VPC) |
| **C₁ — SPIFFE workload** | presents an X.509 SVID via reverse proxy (`X-Client-Cert`) or JWT SVID validated against your SPIRE trust bundle | SPIFFE ID, trust domain, trust bundle / SVID JWKS, optional `allowed_workloads` allowlist | SPIRE server, on-prem |
| **C₂ — Raw mTLS** | TLS handshake with a client cert chained to an internal CA (`SHIELD_TRUSTED_CA_BUNDLE`) | cert fingerprint resolves to an agent registered in the per-tenant cert registry | your PKI / internal CA |

All three are **outbound-network-free**. The minted agent token carries
an `identity_method` claim (`spiffe`, `mtls`, `oidc_id_token`, or
`admin_key`) so audit rows can be filtered by how the identity was
proven — useful when you want, e.g., "show every token minted with the
admin break-glass key in the last 7 days."

### Mode B — sequence (Keycloak federation, no cloud)

```
 User ──SSO──▶ Keycloak (on-prem)
                    │
                    └── id_token ──▶ Agent runtime
                                          │
                                          │ POST /v1/shield/auth/agent-token
                                          │ X-Id-Token: <id_token>
                                          │ body: { agent_instance_id,
                                          │         tenant_id, build_hash, … }
                                          ▼
                                  ┌────────────────────────┐
                                  │ Shield: AuthN          │
                                  │  • _authenticate_caller│
                                  │    looks up provider   │
                                  │    by `iss`            │
                                  │  • validate id_token   │
                                  │    via JWKS (in-VPC)   │
                                  │  • map_claims →        │
                                  │    user_sub, agent_id  │
                                  │  • mint agent token    │
                                  │    identity_method=    │
                                  │      oidc_id_token     │
                                  └────────────┬───────────┘
                                               │ X-Agent-Token
                                               ▼
                                       /v1/shield/cap/mint …  (unchanged)
```

Configure once per tenant:

```http
POST /v1/admin/oidc-providers/{tenant_id}
{
  "issuer":   "https://keycloak.corp.local/realms/main",
  "client_id": "shield",
  "audience":  "shield",
  "jwks_uri":  "https://keycloak.corp.local/realms/main/protocol/openid-connect/certs",
  "claim_mapping": {
    "sub":                 "user_sub",
    "preferred_username":  "agent_id"
  }
}
```

If the caller supplies `user_sub`/`agent_id` in the body that disagree
with the verified id_token claims, the mint is rejected with
`400 body.user_sub conflicts with verified identity (oidc_id_token)` —
no spoofing.

### Mode C — sequence (workload identity, no humans)

```
   SPIRE server (on-prem)
        │
        │ attestation → SVID
        ▼
   Agent workload  spiffe://corp.local/billing-bot
        │
        │ mTLS handshake  (or X-Client-Cert via Envoy)
        ▼
   ┌──────────────────────────────────────────────┐
   │ Shield                                       │
   │   SPIFFEMiddleware    → state.spiffe_identity│
   │   MTLSMiddleware      → state.mtls_identity  │
   │                                              │
   │   POST /auth/agent-token                     │
   │     _authenticate_caller():                  │
   │       1) spiffe_identity?  → use it          │
   │       2) mtls_identity?    → use it          │
   │       3) X-Id-Token?       → Mode B          │
   │       4) X-Admin-Key?      → legacy          │
   │   mint agent_token with                      │
   │     user_sub = SPIFFE ID                     │
   │     agent_id = workload path                 │
   │     identity_method = "spiffe"               │
   └──────────────────────────────────────────────┘
        │
        ▼
   /v1/shield/cap/mint …  (unchanged)
```

Configure once at the process level:

```bash
SHIELD_SPIFFE_ENABLED=1
SHIELD_SPIFFE_TRUST_DOMAIN=corp.local
SHIELD_SPIFFE_TRUST_BUNDLE=/etc/shield/spire-ca.pem
SHIELD_SPIFFE_ALLOWED_WORKLOADS=spiffe://corp.local/billing-bot,spiffe://corp.local/support-bot

# or for raw mTLS without SPIRE:
SHIELD_MTLS_ENABLED=1
SHIELD_MTLS_CERT_HEADER=X-Forwarded-Client-Cert   # when behind Envoy/Istio
```

### What the minted token looks like in each mode

Same JWT shape across all modes — only `identity_method` and the
identity *source* differ. SIEM consumers can tell mints apart:

```json
{ "sub": "alice@corp",                  "identity_method": "oidc_id_token", … }
{ "sub": "spiffe://corp.local/billing", "identity_method": "spiffe",        … }
{ "sub": "billing-bot",                 "identity_method": "mtls",          … }
{ "sub": "ops@corp",                    "identity_method": "admin_key",     … }   # break-glass
```

### Sovereign-mode constraints — none of these need outside network

| Concern                | How it's satisfied on-prem                                  |
|------------------------|-------------------------------------------------------------|
| Token signing keys     | Ed25519 in fs or PKCS#11 (`SHIELD_SIGNER_BACKEND=hsm`)       |
| External JWKS fetch    | only internal IdP URLs; cached locally                       |
| Workload attestation   | SPIRE / internal CA — no cloud IID                           |
| State                  | self-hosted Redis / KeyDB / Sentinel                         |
| SIEM                   | on-prem Splunk, ES, Loki — same OTLP/HEC/ES export           |
| Outbound network       | **none required** in Mode C; only internal JWKS in Mode B    |
