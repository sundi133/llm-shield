# Spec: MCP gateway proxy (front unmodified third-party MCP servers)

Status: **DRAFT — for approval.** Spec-first per `CLAUDE.md`; no code until sign-off.

## 1. Problem & outcome

Customers with vendor-built, legacy, or change-averse MCP servers won't add Shield
calls inside their server (the embedded path, PR #242). They need to point their
agents at a **gateway** that fronts the **unmodified** upstream MCP server and
enforces Shield on every tool call — zero customer code change — where **one
deployment fronts many customers via config**.

Shield already has the enforcement middle: `core/mcp/proxy_server.py::MCPProxy`
runs `enforce_tool_call()` before forwarding and `sanitize_tool_result()` after
([proxy_server.py:72-94](../core/mcp/proxy_server.py)), RBAC-filters `list_tools()`,
and supports stdio/SSE/HTTP upstreams ([upstream.py:84](../core/mcp/upstream.py)).
What's missing is the **productization**: a deployable, multi-tenant *server* around
it.

**Outcome:** a running gateway service where a customer sets one config row
(`route → upstream`), points agents at `https://gateway/<route>/mcp`, and every
tool call is RBAC-checked, input-screened, forwarded, and output-sanitized — with
**no change** to the upstream. Success = the 20-tool financial MCP server the SE
built is fully governed behind the gateway with zero edits to it.

**Non-goals.** Not reinventing enforcement — reuse `MCPProxy` + `enforcement.py`.
Not the cooperative/embedded path (that stays for customers who want it). Not the
OpenAPI-codegen path (`/v1/openapi/*`). Not replacing Shield's own advisory MCP
server (`routes_mcp_server.py`).

## 2. Plane & latency contract

- **New deployable service** ("gateway plane"), its own process/image — **not** the
  admin (CPU portal) plane, and distinct from the GPU data plane.
- It **is** the hot path for *proxied* traffic — that's its job. Budget **per tool
  call**: 1 `enforce_tool_call` + 1 upstream forward + 1 `sanitize_tool_result`.
  - **In-process enforcer** (co-located with Shield): ~0 added network.
  - **HTTP enforcer** (thin edge → central Shield): + guard-endpoint round-trips
    (`/v1/shield/tool/check`, `/v1/shield/tool/output`). Documented trade.
- It must **not** add latency to Shield's own `/guardrails/*` / `cap/mint` /
  `tools/call` — in HTTP mode it is a *client* of those, never in-line with them.

## 3. Data model

- **Upstream config** (per tenant, per route):
  `mcp_gateway:upstream:{tenant_id}:{route}` → JSON:
  ```
  { route, transport: stdio|sse|http, command/args/env | url/headers,
    enforcement_backend: inprocess|http, policy_ref, scan_descriptions: bool,
    isolation_ack: bool, monitor_only: bool, created_at, updated_at }
  ```
  No TTL (config). Tenant-scoped by key prefix; a tenant key can only read/write
  its own routes (reuse the existing tenant-scoping guard).
- **Upstream credentials** stay in `headers`/`env` of the config; secret at rest
  (do not log). One tenant's creds never visible to another (key isolation).
- **Connection pool**: in-memory per gateway process (NOT Redis), keyed by
  `(tenant_id, route)` → live `MCPProxy` (lazy-init, health-checked, idle-TTL
  refresh). Process-local; no cross-tenant sharing.
- Tenant resolution reuses `storage.tenant_store.resolve_tenant_by_api_key`.

## 4. API / interface

**Gateway (MCP JSON-RPC over HTTP streamable + SSE)** — what agents point at:
- `POST /gateway/{route}/mcp` (+ SSE `GET /gateway/{route}/sse`). Methods:
  `initialize`, `tools/list`, `tools/call`, `resources/*`, `prompts/*`,
  notifications — forwarded to the routed upstream; `tools/list` and `tools/call`
  pass through `MCPProxy` (enforced), the rest pass through faithfully.
- **Identity** via the existing `_resolve_identity(request)`
  ([routes_mcp_server.py:169](../api/routes_mcp_server.py)) → `(tenant_id,
  agent_key, user_role)` from state / `X-Agent-Key` / `X-User-Role` / `X-API-Key`
  / OAuth Bearer. **Never** from tool arguments.

**Config (tenant self-service, tenant key):**
- `PUT/GET/DELETE /v1/tenant/me/mcp-gateway/upstreams/{route}` — manage upstream
  config; `GET` lists routes. Auth: tenant API key (mounted on whichever plane
  serves tenant self-service today).

**Enforcement seam (the unifying change):** `MCPProxy.__init__` gains an optional
`enforcer` (a `Protocol` with `enforce_tool_call` / `sanitize_tool_result` /
`filter_tools_for_role`). Default = the current in-process `core/mcp/enforcement`
module (behavior unchanged). Alternate = an **HTTP enforcer** that calls the guard
endpoints (reusing the `shield_guard.py` request shapes from PR #242). Both run the
*same* checks → the two existing enforcement paths converge, can't drift.

## 5. Security & backward compatibility

- **Additive & non-breaking.** New service + new config routes. `MCPProxy` gets an
  *optional* `enforcer` defaulting to today's in-process behavior — existing
  callers/tests unaffected.
- **Non-bypassability (hard requirement).** The gateway only enforces what flows
  through it. The upstream MUST accept connections **only** from the gateway
  (firewall / mTLS / localhost) — per [mcp-runtime-enforcement.md:74-86](mcp-runtime-enforcement.md).
  Enforce operationally: a route with `isolation_ack: false` starts in
  `monitor_only` mode and logs a loud warning, so an un-isolated upstream can't be
  silently mistaken for "protected."
- **Identity is connection-bound**, never tool-arg-derived; a caller can't claim a
  role via arguments.
- **Tenant isolation:** config + pool are per-tenant; tenant A cannot route to or
  read tenant B's upstream.
- **Fail policy:** default **fail-closed** on enforcement error (block the call);
  `SHIELD_GATEWAY_FAIL_OPEN=1` escape hatch. Upstream unreachable → MCP error.

## 6. Packaging & deploy

- **New service image** `Dockerfile.gateway` + entrypoint (`core/mcp/gateway.py`
  server). **Not** imported by `admin_app.py` ⇒ no `Dockerfile.admin` change
  (verify: gateway modules stay out of the admin import graph).
- **Dependencies:** `connect_upstream` needs the **`mcp` client SDK** — currently
  only in `requirements-test.txt`. Productionizing ⇒ add `mcp` to the gateway's
  runtime requirements (`requirements.txt` or a dedicated `requirements-gateway.txt`).
  `httpx` (HTTP enforcer) is already present. **Flag: declare the new runtime dep.**
- **Env flags:** `SHIELD_GATEWAY_ENFORCER=inprocess|http`, `SHIELD_URL` (http mode),
  `SHIELD_GATEWAY_FAIL_OPEN`, `PORT`. Rebuild: the gateway image only.

## 7. Failure modes & edge cases

- **Upstream down / slow:** health-check per route; fail-closed MCP error; optional
  per-route timeout.
- **Enforcer down (http mode):** fail policy per flag (default closed).
- **Redis down (config):** serve from the in-memory pool's last-known config;
  unknown route ⇒ 404/refuse.
- **Streaming / long tools:** MVP **buffers** the result then sanitizes (correctness
  over incrementality); flag incremental streaming sanitization as a follow-up.
- **Unknown/unregistered upstream tools:** `tools/list` annotates provenance +
  shadow-discovers (surfaces in the Agents tab); call-time RBAC is authoritative.
- **Concurrency / noisy tenant:** per-`(tenant,route)` pool + per-route rate limit
  so one tenant can't starve another's upstream.
- **Huge/empty args or results:** size caps before enforce/sanitize (as in
  `shield_guard`).

## 8. Test plan (Definition of Done)

- **Unit (fake `UpstreamClient`, like existing MCPProxy tests):**
  1. route→config resolution (tenant-scoped; A can't read B).
  2. **enforcer seam parity** — in-process enforcer and a stub HTTP enforcer both
     allow/block identically on the same inputs.
  3. blocked `call_tool` never forwards upstream (assert upstream not called).
  4. output sanitize path returns redacted / blocks.
  5. `tools/list` RBAC-filtered + shadow annotation.
  6. identity taken from the connection, not from a role planted in arguments.
  7. fail-closed default vs `SHIELD_GATEWAY_FAIL_OPEN`.
  8. `isolation_ack: false` ⇒ route forced to `monitor_only`.
- **Regression guard:** `MCPProxy` with **no** `enforcer` behaves byte-identically
  to today (pins the non-breaking default).
- **Live-upstream smoke (opt-in, not CI):** front the example financial MCP server;
  admin blocks a tool → agent gets an MCP error; PII in a result → redacted.
- Clean-venv green; full `pytest tests -q` green; CI `pytest` gate passes.

## Invariant risk flags
- ⚠️ **Hot path** — the gateway *is* the proxy path; budget stated (§2). In HTTP
  mode it only *calls* Shield's guard endpoints, never sits inline with them.
- ⚠️ **New runtime dep `mcp`** — must be declared in the gateway's requirements
  (validate in a clean venv).
- ✅ **Non-breaking** — `MCPProxy.enforcer` defaults to current in-process behavior.
- ✅ **No `admin_app` import** ⇒ no `Dockerfile.admin` change (verify).
- ⚠️ **Non-bypassability** is operational — enforced via `isolation_ack` + monitor
  fallback + docs.

## Task breakdown (one branch, ordered)
1. **Enforcement seam** — add optional `enforcer` Protocol to `MCPProxy` (default =
   in-process module) + an `HTTPEnforcer` backend (reuses `shield_guard` shapes).
   Parity tests. Non-breaking. *(No new service yet.)*
2. **Router + config** — `core/mcp/gateway.py`: per-tenant upstream config store,
   `(tenant,route)`→`MCPProxy` routing + connection pool; tenant self-service config
   API. Tests with fake upstream.
3. **Gateway server** — MCP JSON-RPC over HTTP/SSE bridging to the router; identity
   via `_resolve_identity`; `tools/list` + `tools/call` enforced, rest passthrough.
   Tests.
4. **Deploy + hardening** — `Dockerfile.gateway`, entrypoint, `requirements`,
   `isolation_ack` enforcement, docs, and an example fronting the sample upstream.

## Open questions (for approval)
1. **Primary enforcer topology** — ship in-process (co-located, fastest, parity) as
   the default and HTTP (thin edge, scalable) as opt-in? Or is the thin-edge HTTP
   deployment the main customer story (then default that)?
2. **Config plane** — tenant self-service (tenant key) as specced, or admin-only?
3. **Streaming** — is buffer-then-sanitize acceptable for v1, or is incremental
   sanitization required day one (long-running financial tools)?
4. **Image** — separate `Dockerfile.gateway`, or a gateway entrypoint bundled in the
   existing data-plane image?
