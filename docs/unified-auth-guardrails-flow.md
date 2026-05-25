# How AuthN, AuthZ, and Guardrails Work Together

This document shows the unified flow — how authentication, authorization,
and content guardrails form a single coordinated defense.

---

## The Big Picture

```
  ┌──────────────────────────────────────────────────────────────────────────────┐
  │                                                                              │
  │   WHAT PROBLEM DOES EACH LAYER SOLVE?                                        │
  │                                                                              │
  │   ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐ │
  │   │  AUTH        │  │  IDENTITY &  │  │  CONTENT     │  │  TOOL            │ │
  │   │  MIDDLEWARE  │  │  AUTHZ       │  │  GUARDRAILS  │  │  ENFORCEMENT     │ │
  │   │             │  │              │  │              │  │                  │ │
  │   │ "Is this    │  │ "WHO is this │  │ "Is what     │  │ "May this agent  │ │
  │   │  request    │  │  agent and   │  │  they said   │  │  call this tool  │ │
  │   │  from a     │  │  WHAT may    │  │  safe to     │  │  with these      │ │
  │   │  real       │  │  they do?"   │  │  process?"   │  │  arguments?"     │ │
  │   │  tenant?"   │  │              │  │              │  │                  │ │
  │   └──────┬──────┘  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘ │
  │          │                │                  │                   │           │
  │     API key          Agent token        Adversarial         Kill switch     │
  │     validation       verification       detection           Allowlist       │
  │     Tenant ID        RBAC role          PII scanning        RBAC            │
  │     Rate limit       Cap token          Toxicity check      Approval flow   │
  │     Quota            Clearance          Custom policies     Cap token       │
  │                                                                              │
  └──────────────────────────────────────────────────────────────────────────────┘
```

---

## Middleware Stack (Execution Order)

Starlette runs middleware bottom-to-top. The app registers them in this
order (see `core/app.py`), so execution flows top-to-bottom:

```
  HTTP Request arrives
       │
       ▼
  ┌────────────────────────────────────────────────────────────────────────────┐
  │  LAYER 1: AuthMiddleware (core/auth.py)                    RUNS FIRST     │
  │  ─────────────────────────────────────                                    │
  │                                                                           │
  │  ● /v1/admin/* routes → require X-Admin-Key (HMAC compare)               │
  │  ● Public paths (/health, /docs, /oauth/*, /.well-known/*) → skip        │
  │  ● All other paths → require API key:                                     │
  │    1. Extract from X-API-Key / X-Tenant-Key / Authorization: Bearer       │
  │    2. Check against global keys (config)                                  │
  │    3. If no match → resolve_tenant_by_api_key() from Redis               │
  │    4. Set request.state.tenant_id                                        │
  │                                                                           │
  │  FAIL → 401/403 (request never reaches guardrails)                        │
  └────────────────────────────────────────────────────────────────────────────┘
       │ request.state.tenant_id = "acme-corp"
       ▼
  ┌────────────────────────────────────────────────────────────────────────────┐
  │  LAYER 2: MTLSMiddleware (core/mtls_middleware.py)                         │
  │  ────────────────────────────────────────────────                          │
  │                                                                           │
  │  ● If SHIELD_MTLS_ENABLED=true:                                           │
  │    Extract client cert from X-Forwarded-Client-Cert or X-Client-Cert      │
  │    Compute fingerprint → resolve agent via cert_registry                  │
  │    Set request.state.mtls_identity                                       │
  │                                                                           │
  │  ● If disabled or no cert → pass through unchanged                        │
  └────────────────────────────────────────────────────────────────────────────┘
       │ request.state.mtls_identity = {agent_key, fingerprint, ...}
       ▼
  ┌────────────────────────────────────────────────────────────────────────────┐
  │  LAYER 3: SPIFFEMiddleware (core/oauth/spiffe_middleware.py)               │
  │  ──────────────────────────────────────────────────────                    │
  │                                                                           │
  │  ● If SHIELD_SPIFFE_ENABLED=true:                                         │
  │    Validate SPIFFE X.509 SVID from client cert header                     │
  │    Set request.state.spiffe_identity                                     │
  │                                                                           │
  │  ● Used by _require_admin() as alternative to X-Admin-Key                 │
  └────────────────────────────────────────────────────────────────────────────┘
       │ request.state.spiffe_identity = {user_sub, agent_id, ...}
       ▼
  ┌────────────────────────────────────────────────────────────────────────────┐
  │  LAYER 4: AgentIdentityMiddleware (core/agent_identity_middleware.py)      │
  │  ───────────────────────────────────────────────────────────────           │
  │                                                                           │
  │  ● If X-Agent-Token header present:                                       │
  │    verify_agent_token(token) → IdentityTuple                              │
  │    Set request.state.identity                                            │
  │    FAIL → 401 {"error": "invalid_agent_token"}                            │
  │                                                                           │
  │  ● If no X-Agent-Token but mTLS identity exists:                          │
  │    Synthesize IdentityTuple from mTLS (trust_level="high")                │
  │                                                                           │
  │  ● If neither → pass through (guardrails still run, authz deferred)       │
  └────────────────────────────────────────────────────────────────────────────┘
       │ request.state.identity = IdentityTuple(user_sub, agent_id, ...)
       ▼
  ┌────────────────────────────────────────────────────────────────────────────┐
  │  LAYER 5: ShieldMiddleware (core/middleware.py)                            │
  │  ──────────────────────────────────────────────                            │
  │                                                                           │
  │  For /v1/shield/*, /v1/tenant/*, /guardrails/* paths:                     │
  │                                                                           │
  │  ● Resolve agent identity from X-Agent-Key header or cert fingerprint     │
  │  ● Resolve RBAC role: enforcer.resolve_role(agent_key)                    │
  │  ● Load tenant config from Redis (cached 60s):                           │
  │    get_tenant(tenant_id) → {input_guardrails, output_guardrails, ...}    │
  │  ● Shadow agent discovery (detect unregistered agents)                    │
  │  ● Per-tenant rate limit / quota enforcement                             │
  │                                                                           │
  │  Set on request.state:                                                   │
  │    .agent_key, .role, .role_name, .tenant_config,                        │
  │    .trust_level, .identity_method, .shadow_agent                         │
  │                                                                           │
  │  FAIL → 429 (quota exceeded)                                              │
  └────────────────────────────────────────────────────────────────────────────┘
       │ Full context: tenant_id + tenant_config + agent_key + role + identity
       ▼
  ┌────────────────────────────────────────────────────────────────────────────┐
  │  LAYER 6: TelemetryMiddleware (core/telemetry_middleware.py)               │
  │  ──────────────────────────────────────────────────────                    │
  │                                                                           │
  │  ● Captures request/response timing                                       │
  │  ● Tags with trace_id, tenant_id, agent_key, user_sub                    │
  │  ● Exports to Elasticsearch / Splunk / OTLP / file                       │
  │                                                                           │
  │  RUNS LAST — wraps the entire response lifecycle                          │
  └────────────────────────────────────────────────────────────────────────────┘
       │
       ▼
  Route handler receives request with FULL CONTEXT
```

---

## Unified Flow: Agent Sends a Message

This is the complete flow when an agent sends a user message through
the gateway (`POST /v1/shield/chat/completions`):

```
  CUSTOMER AGENT                                        LLM SHIELD
  ══════════════                                        ══════════

  POST /v1/shield/chat/completions
  Headers:
    X-API-Key: sk-tenant-xxx
    X-Agent-Token: eyJ... (JWT)
    X-Agent-Key: billing-bot
  Body:
    {"messages": [{"role":"user","content":"Send invoice to john@acme.com"}]}
  │
  │
  ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  MIDDLEWARE CHAIN (6 layers, ~2ms total)                                │
  │                                                                         │
  │  AuthMiddleware ──► validate sk-tenant-xxx                              │
  │    │                  resolve tenant_id = "acme-corp"                   │
  │    ▼                                                                    │
  │  MTLSMiddleware ──► (no cert header, skip)                              │
  │    │                                                                    │
  │    ▼                                                                    │
  │  SPIFFEMiddleware ──► (not enabled, skip)                               │
  │    │                                                                    │
  │    ▼                                                                    │
  │  AgentIdentityMiddleware ──► verify_agent_token(eyJ...)                 │
  │    │                           ├── Ed25519 signature ✓                  │
  │    │                           ├── exp not passed ✓                     │
  │    │                           ├── iss/aud binding ✓                    │
  │    │                           ├── not revoked ✓                        │
  │    │                           └── IdentityTuple:                       │
  │    │                                user_sub = "user-42"               │
  │    │                                agent_id = "billing-bot"            │
  │    │                                tenant_id = "acme-corp"             │
  │    ▼                                                                    │
  │  ShieldMiddleware ──► resolve RBAC role for "billing-bot"               │
  │    │                    role = "invoicing" (from tenant RBAC config)     │
  │    │                  load tenant config:                               │
  │    │                    input_guardrails: {adversarial, pii, keyword}   │
  │    │                    output_guardrails: {pii_leakage, bias}          │
  │    │                  per-tenant rate limit check ✓                     │
  │    │                  shadow agent check: billing-bot registered ✓      │
  │    ▼                                                                    │
  │  TelemetryMiddleware ──► start timer, assign trace_id                   │
  │                                                                         │
  └─────────────────────────────────────────────────────────────────────────┘
       │
       │  request.state now carries:
       │    .tenant_id = "acme-corp"
       │    .tenant_config = {input_guardrails: {...}, output_guardrails: {...}}
       │    .identity = IdentityTuple(user_sub="user-42", agent_id="billing-bot", ...)
       │    .agent_key = "billing-bot"
       │    .role = RBACRole(name="invoicing", allowed_tools=[...], ...)
       │    .role_name = "invoicing"
       │    .trust_level = "high" (from agent token)
       │
       ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │  ROUTE HANDLER: shield_chat_completions()                               │
  │  (api/routes_gateway.py:302)                                            │
  │                                                                         │
  │  ┌──────────────────────────────────────────────────────────────────┐   │
  │  │  PHASE 1: INPUT GUARDRAILS                                       │   │
  │  │                                                                  │   │
  │  │  Config source: request.state.tenant_config["input_guardrails"]  │   │
  │  │  Context: {agent_key, role, tenant_id, conversation_history}     │   │
  │  │                                                                  │   │
  │  │  Message: "Send invoice to john@acme.com"                        │   │
  │  │                                                                  │   │
  │  │  Tier 1 (fast, <1ms, parallel):                                  │   │
  │  │    keyword_blocklist ─── PASS (no blocked keywords)              │   │
  │  │    regex_pattern ─────── PASS (no regex violations)              │   │
  │  │    system_prompt_leak ── PASS (no "ignore" patterns)             │   │
  │  │                                                                  │   │
  │  │  Tier 2 (medium, ~150ms, parallel):                              │   │
  │  │    sentiment ─────────── PASS (neutral)                          │   │
  │  │    topic_restriction ─── PASS (invoicing is allowed topic)       │   │
  │  │                                                                  │   │
  │  │  Tier 3 (slow, ~500ms, parallel):                                │   │
  │  │    adversarial_detect ── PASS (score: 0.03, no injection)        │   │
  │  │    pii_detection ─────── WARN (email detected, action: log)      │   │
  │  │    toxicity ──────────── PASS (score: 0.01)                      │   │
  │  │                                                                  │   │
  │  │  Result: allowed=true (no blocks, PII logged only)               │   │
  │  └──────────────────────────────────────────────────────────────────┘   │
  │       │                                                                 │
  │       ▼ ALLOWED                                                         │
  │  ┌──────────────────────────────────────────────────────────────────┐   │
  │  │  PHASE 2: LLM CALL                                               │   │
  │  │                                                                  │   │
  │  │  Proxy to vLLM / LiteLLM / upstream:                            │   │
  │  │  POST http://127.0.0.1:8000/v1/chat/completions                 │   │
  │  │  {"messages": [...], "max_tokens": 512}                          │   │
  │  │                                                                  │   │
  │  │  LLM Response:                                                   │   │
  │  │  "I'll prepare the Q4 invoice for John Smith at john@acme.com.   │   │
  │  │   Total amount: $15,230.00. Shall I send it?"                    │   │
  │  └──────────────────────────────────────────────────────────────────┘   │
  │       │                                                                 │
  │       ▼                                                                 │
  │  ┌──────────────────────────────────────────────────────────────────┐   │
  │  │  PHASE 3: OUTPUT GUARDRAILS                                      │   │
  │  │                                                                  │   │
  │  │  Config source: request.state.tenant_config["output_guardrails"] │   │
  │  │                                                                  │   │
  │  │  Fast:                                                           │   │
  │  │    pii_leakage ──── WARN (email john@acme.com detected)          │   │
  │  │    competitor_mention ── PASS                                     │   │
  │  │                                                                  │   │
  │  │  Slow:                                                           │   │
  │  │    bias_detection ── PASS                                        │   │
  │  │                                                                  │   │
  │  │  Result: allowed=true (PII logged but not blocked — email is     │   │
  │  │  relevant to the invoice context)                                │   │
  │  └──────────────────────────────────────────────────────────────────┘   │
  │       │                                                                 │
  │       ▼                                                                 │
  │  ┌──────────────────────────────────────────────────────────────────┐   │
  │  │  PHASE 4: AUDIT LOG                                              │   │
  │  │                                                                  │   │
  │  │  One signed row per decision:                                    │   │
  │  │  {                                                               │   │
  │  │    agent_key: "billing-bot",                                     │   │
  │  │    tenant_id: "acme-corp",                                       │   │
  │  │    user_role: "invoicing",                                       │   │
  │  │    stage: "complete",                                            │   │
  │  │    blocked: false,                                               │   │
  │  │    input_guardrails: [{adversarial: pass}, {pii: warn}, ...],    │   │
  │  │    output_guardrails: [{pii_leakage: warn}, {bias: pass}],       │   │
  │  │    latency_ms: 680                                               │   │
  │  │  }                                                               │   │
  │  │  → Elasticsearch / Splunk / OTLP / file                         │   │
  │  └──────────────────────────────────────────────────────────────────┘   │
  │                                                                         │
  └─────────────────────────────────────────────────────────────────────────┘
       │
       ▼
  Response to agent:
  {
    "text": "I'll prepare the Q4 invoice for John Smith...",
    "blocked": false,
    "guardrail_results": {...}
  }
```

---

## Unified Flow: Agent Makes a Tool Call

This is the complete flow when an agent wants to execute a tool.
All layers coordinate: AuthN proves identity, guardrails check safety,
AuthZ grants per-action permission, the tool verifies the cap.

```
  CUSTOMER AGENT                   LLM SHIELD                   TOOL SERVER
  ══════════════                   ══════════                   ═══════════

  Agent decides to call send_email(to: "john@acme.com", body: "Invoice...")
       │
       │
  ═════╪═══════════════════════════════════════════════════════════════════════
  STEP 1: CHECK TOOL (optional — pre-flight check)
  ═════╪═══════════════════════════════════════════════════════════════════════
       │
       │  POST /v1/shield/tool/check
       │  X-API-Key: sk-xxx
       │  X-Agent-Key: billing-bot
       │  {tool_name: "send_email", user_role: "invoicing",
       │   arguments: {to: "john@acme.com"}}
       │ ──────────────────────────────────►
       │                                    │
       │                               ┌────┴────────────────────────┐
       │                               │ Middleware authenticates:   │
       │                               │   tenant_id, agent_key,    │
       │                               │   role from API key        │
       │                               │                            │
       │                               │ Agentic guardrail chain:   │
       │                               │  1. Kill switch: OFF  ✓    │
       │                               │  2. Circuit breaker: OK ✓  │
       │                               │  3. Allowlist:             │
       │                               │     billing-bot allows     │
       │                               │     send_email? ✓          │
       │                               │     invoicing role allows  │
       │                               │     send_email? ✓          │
       │                               │  4. Rate limit: OK ✓       │
       │                               │  5. Arg validation: OK ✓   │
       │                               │  6. Param policy: OK ✓     │
       │                               │  7. Workflow: OK ✓         │
       │                               │  8. Approval: not needed ✓ │
       │                               └────┬────────────────────────┘
       │                                    │
       │  {allowed: true, action: "pass",   │
       │   guardrail_results: [...]}        │
       │ ◄──────────────────────────────────│
       │
       │
  ═════╪═══════════════════════════════════════════════════════════════════════
  STEP 2: MINT CAPABILITY (AuthZ — freeze the decision into a signed token)
  ═════╪═══════════════════════════════════════════════════════════════════════
       │
       │  POST /v1/shield/cap/mint
       │  X-Agent-Token: eyJ... (JWT proving WHO)
       │  X-API-Key: sk-xxx
       │  {tool: "send_email",
       │   resource: "john@acme.com",
       │   clearance_max: "internal",
       │   scope_constraints: ["to:john@acme.com"],
       │   ttl_seconds: 30}
       │ ──────────────────────────────────►
       │                                    │
       │                               ┌────┴────────────────────────┐
       │                               │ AgentIdentityMiddleware:    │
       │                               │   verify_agent_token()      │
       │                               │   → IdentityTuple           │
       │                               │   (user_sub, agent_id,      │
       │                               │    tenant_id, build_hash)   │
       │                               │                             │
       │                               │ Rate limit: cap mint ✓      │
       │                               │                             │
       │                               │ _decide_authz():            │
       │                               │   RBAC role "invoicing"     │
       │                               │   → send_email allowed ✓    │
       │                               │   clearance "internal"      │
       │                               │   ≤ role ceiling ✓          │
       │                               │                             │
       │                               │ mint_cap():                 │
       │                               │   JWT with SEPARATE key     │
       │                               │   tool="send_email" (exact) │
       │                               │   nonce=one-shot            │
       │                               │   exp=30s from now          │
       │                               └────┬────────────────────────┘
       │                                    │
       │  {cap_token: "eyJ...",             │
       │   expires_in: 30,                  │
       │   decision: {allowed: true}}       │
       │ ◄──────────────────────────────────│
       │
       │
  ═════╪═══════════════════════════════════════════════════════════════════════
  STEP 3: EXECUTE TOOL (send cap to tool server as bearer credential)
  ═════╪═══════════════════════════════════════════════════════════════════════
       │
       │  send_email(
       │    to: "john@acme.com",
       │    body: "Invoice...",
       │    _cap_token: "eyJ..."     ← bearer credential
       │  )
       │ ──────────────────────────────────────────────────────►
       │                                                        │
       │                                                   ┌────┴──────────┐
       │                                                   │ Tool receives │
       │                                                   │ cap_token     │
       │                                                   │               │
       │                                                   │ BEFORE doing  │
       │                                                   │ anything:     │
       │                                                   │ verify cap    │
       │                                                   └────┬──────────┘
       │                                                        │
       │                                    POST /v1/shield/cap/verify
       │                                    {cap_token: "eyJ...",
       │                                     expected_tool: "send_email",
       │                                     expected_resource: "john@acme.com"}
       │                                   ◄────────────────────│
       │                                    │                   │
       │                               ┌────┴──────────────┐   │
       │                               │ Verify checks:    │   │
       │                               │ 1. Ed25519 sig ✓  │   │
       │                               │ 2. Not expired ✓  │   │
       │                               │ 3. Tool match ✓   │   │
       │                               │ 4. Resource match✓│   │
       │                               │ 5. Not revoked ✓  │   │
       │                               │ 6. Nonce burn ✓   │   │
       │                               │    (one-shot,     │   │
       │                               │     atomic Redis  │   │
       │                               │     SETNX)        │   │
       │                               └────┬──────────────┘   │
       │                                    │                   │
       │                                    │ {valid: true,     │
       │                                    │  claims: {        │
       │                                    │   user_sub,       │
       │                                    │   agent_id,       │
       │                                    │   tool, resource, │
       │                                    │   clearance_max}} │
       │                                    │──────────────────►│
       │                                                        │
       │                                                   ┌────┴──────────┐
       │                                                   │ valid=true    │
       │                                                   │ → Execute     │
       │                                                   │   send_email  │
       │                                                   └────┬──────────┘
       │                                                        │
       │  Result: email sent                                    │
       │ ◄─────────────────────────────────────────────────────│
       │
       │
  ═════╪═══════════════════════════════════════════════════════════════════════
  STEP 4: SANITIZE TOOL OUTPUT (data policy enforcement)
  ═════╪═══════════════════════════════════════════════════════════════════════
       │
       │  Tool returned data that needs sanitization before the agent uses it.
       │  Example: patient_lookup returned raw medical records.
       │
       │  POST /guardrails/output
       │  X-API-Key: sk-xxx
       │  {output: "Patient: John Smith, SSN: 123-45-6789, Diagnosis: ...",
       │   tool_name: "patient_lookup"}
       │ ──────────────────────────────────►
       │                                    │
       │                               ┌────┴────────────────────────┐
       │                               │ Stage 1: Tool Authorization │
       │                               │   agent + role + tool check │
       │                               │                             │
       │                               │ Stage 2: Data Sanitization  │
       │                               │   Load policy from Redis:   │
       │                               │   data_policies:acme-corp   │
       │                               │   → patient_lookup rules    │
       │                               │                             │
       │                               │   Regex pass:               │
       │                               │   \d{3}-\d{2}-\d{4}        │
       │                               │   → [SSN REDACTED]          │
       │                               │                             │
       │                               │   AI pass (if configured):  │
       │                               │   "Never expose SSNs even   │
       │                               │    if paraphrased"          │
       │                               │   → catches evasion         │
       │                               │                             │
       │                               │ Stage 3: Output Guardrails  │
       │                               │   pii_leakage → redact      │
       │                               │   bias_detection → pass     │
       │                               └────┬────────────────────────┘
       │                                    │
       │  {safe: true,                      │
       │   sanitized_output: "Patient:      │
       │     John Smith, SSN: [SSN REDACTED],│
       │     Diagnosis: ..."}               │
       │ ◄──────────────────────────────────│
       │
       ▼
  Agent uses sanitized output (never sees raw SSN)
```

---

## How Each Layer Feeds the Next

```
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                                                                         │
  │  AuthMiddleware                                                         │
  │  ├─ Sets: tenant_id ──────────────────────────────────────────┐         │
  │  │                                                            │         │
  │  ▼                                                            │         │
  │  ShieldMiddleware                                             │         │
  │  ├─ Uses: tenant_id to load tenant_config from Redis          │         │
  │  ├─ Sets: tenant_config ─────────────────────────────┐        │         │
  │  ├─ Sets: agent_key, role, role_name                 │        │         │
  │  │                                                   │        │         │
  │  ▼                                                   │        │         │
  │  AgentIdentityMiddleware                             │        │         │
  │  ├─ Sets: identity (IdentityTuple from JWT) ────┐   │        │         │
  │  │                                              │   │        │         │
  │  ▼                                              │   │        │         │
  │  Route Handler                                  │   │        │         │
  │  │                                              │   │        │         │
  │  ├─ INPUT GUARDRAILS                            │   │        │         │
  │  │  Uses: tenant_config ◄───────────────────────│───┘        │         │
  │  │    to know WHICH guardrails to run           │            │         │
  │  │  Uses: agent_key, role ◄─────────────────────│            │         │
  │  │    for role_based_input_policy guardrail      │            │         │
  │  │  Uses: tenant_id ◄──────────────────────────────────────┘         │
  │  │    for per-tenant keyword lists, custom policies                   │
  │  │                                                                     │
  │  ├─ TOOL CHECK (agentic guardrails)                                    │
  │  │  Uses: agent_key, role                                             │
  │  │    for allowlist intersection check                                │
  │  │  Uses: tenant_id                                                   │
  │  │    for kill switch lookup, rate limits                             │
  │  │                                                                     │
  │  ├─ CAP MINT (AuthZ)                                                   │
  │  │  Uses: identity (IdentityTuple) ◄────────────┘                     │
  │  │    bakes user_sub + agent_id + tenant_id into cap                  │
  │  │  Uses: role                                                        │
  │  │    for RBAC role→tool, role→data, clearance ceiling                │
  │  │                                                                     │
  │  ├─ OUTPUT GUARDRAILS                                                  │
  │  │  Uses: tenant_config                                               │
  │  │    to know WHICH output guardrails to run                          │
  │  │  Uses: tenant_id                                                   │
  │  │    for per-tool data policies (sanitization rules)                 │
  │  │  Uses: role                                                        │
  │  │    for role-based redaction                                        │
  │  │                                                                     │
  │  └─ AUDIT LOG                                                          │
  │     Uses: ALL of the above                                             │
  │     Every decision is one signed row with full context                 │
  │                                                                         │
  └─────────────────────────────────────────────────────────────────────────┘
```

---

## Failure Cascade: What Blocks What

```
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                                                                         │
  │  Each layer can independently reject. Later layers never run.           │
  │                                                                         │
  │  Request ──► AuthMiddleware ──► ShieldMiddleware ──► Identity ──► Route  │
  │                  │                   │                  │          │     │
  │              ┌───┴───┐          ┌────┴────┐       ┌────┴────┐     │     │
  │              │ 401   │          │ 429     │       │ 401     │     │     │
  │              │ 403   │          │ quota   │       │ invalid │     │     │
  │              │ no key│          │ exceeded│       │ agent   │     │     │
  │              │       │          │         │       │ token   │     │     │
  │              └───────┘          └─────────┘       └─────────┘     │     │
  │                                                                   │     │
  │  Inside the route handler, FIVE independent checkpoints:          │     │
  │                                                                   │     │
  │  ┌─────────────┐  ┌──────────────┐  ┌───────────┐  ┌───────────┐ │     │
  │  │ Input       │  │ Tool Check   │  │ Cap Mint  │  │ Output    │ │     │
  │  │ Guardrails  │  │ (agentic)    │  │ (AuthZ)   │  │ Guardrails│ │     │
  │  │             │  │              │  │           │  │           │ │     │
  │  │ 403: block  │  │ 403: denied  │  │ 403: RBAC │  │ 403: block│ │     │
  │  │ adversarial │  │ kill switch  │  │ denied    │  │ PII leak  │ │     │
  │  │ pii         │  │ allowlist    │  │ clearance │  │ toxicity  │ │     │
  │  │ toxicity    │  │ rate limit   │  │ exceeded  │  │ bias      │ │     │
  │  │ custom      │  │ approval     │  │           │  │ custom    │ │     │
  │  │ policy      │  │ needed       │  │           │  │ policy    │ │     │
  │  └─────────────┘  └──────────────┘  └───────────┘  └───────────┘ │     │
  │                                                                   │     │
  │  + at the tool server:                                            │     │
  │  ┌───────────────────┐                                            │     │
  │  │ Cap Verify         │                                           │     │
  │  │ valid=false:       │                                           │     │
  │  │ replay, tampered,  │                                           │     │
  │  │ expired, wrong tool│                                           │     │
  │  └───────────────────┘                                            │     │
  │                                                                         │
  │  EVERY rejection is logged to the audit trail with full context.        │
  │                                                                         │
  └─────────────────────────────────────────────────────────────────────────┘
```

---

## What Identity Information Each Layer Uses

```
  ┌────────────────────────────────────────────────────────────────────────┐
  │                                                                        │
  │  LAYER              IDENTITY SOURCE        WHAT IT USES IT FOR         │
  │  ─────              ───────────────        ──────────────────          │
  │                                                                        │
  │  AuthMiddleware     X-API-Key              tenant_id lookup            │
  │                     (long-lived,           per-tenant config           │
  │                      per-tenant)           rate limits                 │
  │                                                                        │
  │  ShieldMiddleware   X-Agent-Key            RBAC role resolution        │
  │                     (string, per-agent)    shadow agent detection      │
  │                     X-Client-Cert-FP       cert→agent resolution      │
  │                     (optional, mTLS)       trust_level="high"         │
  │                                                                        │
  │  AgentIdentity      X-Agent-Token          full identity:             │
  │  Middleware         (JWT, ≤15min)           user_sub (WHO the human)  │
  │                                             agent_id (WHO the agent)  │
  │                                             instance_id (WHICH pod)   │
  │                                             build_hash (WHAT code)    │
  │                                             tenant_id (scoped)        │
  │                                                                        │
  │  Input Guardrails   role (from RBAC)       role_based_input_policy    │
  │                     tenant_config          which guardrails to run    │
  │                     agent_key              per-agent custom rules     │
  │                                                                        │
  │  Tool Check         agent_key + role       allowlist intersection     │
  │                     tenant_id              kill switch, rate limit    │
  │                                                                        │
  │  Cap Mint (AuthZ)   IdentityTuple          bake into cap:            │
  │                     (from JWT)             user_sub, agent_id,       │
  │                     role (from RBAC)       tenant_id, tool, resource │
  │                                             RBAC checks              │
  │                                                                        │
  │  Output Guardrails  role                   role_based_redaction       │
  │                     tenant_id              per-tool data policies    │
  │                     tenant_config          which guardrails to run    │
  │                                                                        │
  │  Cap Verify         cap_token itself       tool + resource match     │
  │  (at tool server)   (self-contained JWT)   nonce (one-shot)          │
  │                                             no Shield round-trip     │
  │                                             needed after JWKS fetch  │
  │                                                                        │
  │  Audit Log          ALL of the above       full-context audit row     │
  │                                             per decision             │
  │                                                                        │
  └────────────────────────────────────────────────────────────────────────┘
```

---

## Summary: Defense-in-Depth Timeline

```
  TIME ──────────────────────────────────────────────────────────────────────►

       TRANSPORT    AUTH         CONTENT         AUTHZ           ENFORCEMENT
       ─────────    ────         ───────         ─────           ───────────

  ──►  mTLS /       API key      Input           Cap mint        Cap verify
       SPIFFE       validates    guardrails      (RBAC +         at tool
                    tenant       run on          clearance)      server
                                 user message    freezes
                    Agent token                  decision as     Nonce burn
                    validates                    signed JWT      (one-shot)
                    identity
                                                 Separate key    Tool+resource
                    RBAC role                    from AuthN      match
                    resolved
                                 Output                          Revocation
                    Tenant       guardrails                      check
                    config       run on LLM
                    loaded       response        Tool check      Data policy
                                                 (agentic        sanitization
                    Rate limit   Stream          guardrails)     on tool output
                    enforced     monitoring
                                 (real-time)     Kill switch
                                                 Allowlist
                                                 Approval flow

       ◄── Any layer can reject independently ──►
       ◄── Every decision is audited ──►
       ◄── Tenant-scoped throughout ──►
```
