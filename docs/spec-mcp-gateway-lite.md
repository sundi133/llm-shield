# Spec: MCP gateway — small-team edition (`docker run`) (Phase 4)

Status: **DRAFT — for approval.** Spec-first per `CLAUDE.md`; no code until sign-off.
Reuses the **shipped** gateway internals (`core/mcp/proxy_server.py::MCPProxy`,
`core/mcp/enforcement.py`, `core/mcp/gateway.py::MCPGatewayRouter`,
`core/mcp/upstream.py::connect_upstream`) unchanged; this is a packaging + config
layer, not new enforcement. Composes with the scanner (PR #263) and its
distribution (PR #264). The two design forks are **decided** (§9): a slim CPU
image (allowlist + logging; model DLP opt-in) and a warn-and-front pre-flight.

## 1. Problem & outcome

The shipped MCP gateway is multi-tenant, Redis-backed, and configured through the
admin portal / tenant API keys — great for the platform, too much for the
thousands of small teams who just want to put *one or a few* MCP servers behind
something that logs every tool call and enforces an allowlist. They will not stand
up Redis, a portal, and tenant keys; they will run one container.

**Outcome.** A single `docker run` (or a 10-line `docker-compose.yml`) that:
- fronts one or more upstream MCP servers declared in **one config file** (no
  Redis, no portal, no tenant API keys),
- enforces a **role → tool allowlist** from that file on every `tools/call`,
- **logs every tool-call decision** as JSON lines to stdout/file,
- optionally **pre-flights each upstream with the scanner** (`shield-mcp scan`)
  before fronting it,
- and points agents at `http://localhost:PORT/gateway/<route>/mcp`.

Success = a team writes `gateway.yaml` (upstream + allowlist), runs the image,
points their agent at it, and a disallowed tool is blocked + logged with **zero**
Shield platform, Redis, or portal.

**Non-goals.**
- **Not** a second enforcement engine. It reuses `MCPProxy` + `enforcement.py`
  verbatim via their existing injection seams (`proxy_factory`, `enforcer`,
  `on_decision`); no fork.
- **Not** multi-tenant. One config file = one team (a single fixed `tenant_id`).
- **Not** the Redis config store, the admin portal, or tenant self-service config
  APIs. Those stay for the platform edition.
- **Not** a GPU/model deployment. The default image runs the **allowlist + logging**
  path on CPU; model-grade DLP/injection is opt-in via a Shield backend (§9 Q1).

## 2. Plane & latency contract

- **A new standalone service** ("gateway-lite"), its own image/process. **Not** the
  data (GPU/vLLM) plane and **not** the admin (CPU portal) plane.
- **It IS the proxy hot path** — that is its job. Budget **per `tools/call`**:
  1 `enforce_tool_call` + 1 upstream forward + 1 `sanitize_tool_result`, all
  **in-process** (no added network) in the default local mode. This is the same
  per-call budget the platform gateway already commits to.
- **It does not add latency to Shield's own `/guardrails/*` / `cap/mint` /
  `tools/call`.** In the optional HTTP-enforcer mode it is a *client* of the guard
  endpoints (`/v1/shield/tool/check`, `/v1/shield/tool/output`), never in-line with
  them.

## 3. Data model

**No Redis. No tenant scoping.** All state is one config file plus an in-process
connection pool.

- **Config file** (`gateway.yaml`, path via `--config` / `$GATEWAY_CONFIG`). Two
  sections:
  ```yaml
  team: "acme"                 # the single fixed tenant_id for this deployment
  log:
    format: json               # json | text
    path: "-"                  # "-" = stdout, or a file path
  preflight:
    scan: true                 # run `shield-mcp scan` on each upstream at boot
    on_finding: warn           # warn | refuse   (§9 Q2)
  routes:                      # one or more upstreams (schema = the shipped store)
    - route: files
      transport: stdio         # stdio | sse | http
      command: "npx"
      args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
      env: {}
      scan_descriptions: true
      isolation_ack: true      # I confirm this upstream only accepts the gateway
      enforcement_backend: inprocess   # inprocess | http
      # http backend only:
      # shield_url: "https://shield.example.com"
      # shield_tenant_key: "..."
  rbac:                        # populates config.schema.config.rbac (no Redis)
    roles:
      reader: { allowed_tools: ["read_file", "list_directory"], denied_tools: [] }
      admin:  { allowed_tools: [], denied_tools: [] }   # [] allowed = all
    agents:
      coding-agent: reader     # agent_key -> role
  ```
  The `routes[*]` schema is exactly the shipped upstream-config dict that
  `storage/mcp_gateway_store.get_upstream` returns (`transport`, `command/args/env`
  or `url/headers`, `enforcement_backend`, `scan_descriptions`, `isolation_ack`,
  `shield_url`, `shield_tenant_key`). `rbac` maps directly onto `config/schema.py`
  `RBACConfig` (`roles: {name: {allowed_tools, denied_tools, ...}}`, `agents:
  {agent_key: role}`).
- **Connection pool:** the existing in-process `MCPGatewayRouter._pool` keyed by
  `(team, route)`; stdio pooled + reconnect, http/sse per-call (unchanged).
- **Decision log:** append-only JSON lines (not Redis) — the decision dict
  `MCPProxy` already emits: `{phase, tool, agent_key, tenant_id, allowed, action,
  mode, would_block, risk, results, reason, ts}`.

## 4. API / interface

Reuses the shipped JSON-RPC surface; adds a file-config seam + an entrypoint.

- **Agent-facing (unchanged path):** `POST /gateway/{route}/mcp` — the existing
  `api/routes_mcp_gateway_server.py::_dispatch` handler (`initialize`, `tools/list`,
  `tools/call`, `resources/*`, `prompts/*`). Mounted in a **slim FastAPI app** (not
  the monolith, not the admin app).
- **Identity:** the existing `_resolve_identity` order, simplified for one team —
  `agent_key` from `X-Agent-Key` (default `mcp-agent`), `user_role` from
  `X-User-Role`, `tenant_id` = the fixed `team` from config. **Never** from tool
  arguments. No tenant API key required (single-team).
- **The file-config seam (the only new core code):** a `FileConfigRouter`
  subclass of `MCPGatewayRouter` overriding **`_load_cfg(team, route)`** to return
  the route dict from the loaded file instead of `get_upstream()` (Redis). Its
  `proxy_factory` wraps `_default_proxy_factory` to also pass
  `on_decision=<the log sink>` into `MCPProxy` (the seam the platform gateway
  leaves unused today).
- **RBAC without Redis:** at boot, translate the file's `rbac` into a
  `ShieldConfig` and load it via `config.schema.load_config` / set
  `config.rbac`, so `core.rbac.enforcer.resolve_role` works from static config
  (its documented first path, before any registry fallback).
- **Entrypoint CLI:** `mcp-gateway-lite --config gateway.yaml [--port 8080]`
  (also `$GATEWAY_CONFIG`, `$PORT`). Loads config → validates → populates rbac →
  builds the `FileConfigRouter` + sink → runs uvicorn.

## 5. Security & backward compatibility

- **Additive & non-breaking.** New entrypoint + new image + one new
  `FileConfigRouter` subclass. **No edits** to `MCPProxy`, `enforcement.py`,
  `MCPGatewayRouter`, or `_dispatch` — all reused through their existing seams
  (`proxy_factory`, `enforcer`, `on_decision`, subclass override). Existing
  callers/tests untouched.
- **Non-bypassability (hard requirement, operational).** The gateway only enforces
  what flows through it; the upstream MUST accept connections **only** from the
  gateway. Reuse the shipped `isolation_ack` warning: a route with
  `isolation_ack: false` boots with a **loud warning** (and, per §9 Q2 config, may
  refuse to start), so an un-isolated upstream isn't mistaken for protected.
- **Fail policy:** default **fail-closed** on an enforcement error (block the
  call); `SHIELD_GATEWAY_FAIL_OPEN=1` escape hatch (the existing flag). Upstream
  unreachable → MCP error.
- **Secrets** (`env`, `headers`, `shield_tenant_key`) live in the config file; the
  decision log and startup logs **must not** print them. Document file permissions.
- **Single-team isolation:** there is exactly one `tenant_id`; nothing to leak
  across tenants because there is only one.

## 6. Packaging & deploy

- **New slim image `Dockerfile.gateway`** (CPU, `python:3.12-slim`), a **curated
  per-file COPY allowlist** like `Dockerfile.admin`: the entrypoint +
  `core/mcp/*` + `core/rbac.py` + `config/*` + the lightweight
  `guardrails/agentic/*` guards used by the allowlist path + the scanner package
  (for pre-flight). **Deps:** `fastapi`, `uvicorn`, `httpx`, `mcp>=1.2`, `pyyaml`
  (all already in `requirements.txt`). **Not** `redis`/`upstash-redis` (file
  config), **not** `torch`/vLLM (model guards degrade; §7).
- **New entrypoint module** (e.g. `core/mcp/gateway_lite.py`) + console script
  `mcp-gateway-lite`. **Not imported by `admin_app.py`** ⇒ **no `Dockerfile.admin`
  change** (verify with the import-graph guard).
- **`docker-compose.gateway.yml`** example (gateway + a sample upstream) and a
  sample `gateway.yaml`.
- **No change** to the data-plane or admin images. New image builds independently.
- **Env flags:** `GATEWAY_CONFIG`, `PORT`, `SHIELD_GATEWAY_FAIL_OPEN`,
  `SHIELD_GATEWAY_RESOURCES` (existing), `SHIELD_URL` (http backend). No new
  *server* env on the platform side.

## 7. Failure modes & edge cases

- **Config file missing / invalid YAML / bad schema** → the entrypoint exits
  non-zero at boot with a clear message (never serves a half-configured gateway).
- **Unknown route** → the existing `GatewayError(404)` → JSON-RPC `-32004`.
- **Upstream down / slow** → fail-closed MCP error; stdio broken-session reconnect
  is the existing behavior.
- **Enforcement error** → fail-closed by default; `SHIELD_GATEWAY_FAIL_OPEN=1`
  opens. (Same contract as the platform gateway.)
- **Model guardrails unavailable (slim CPU image, no torch/models)** → the
  **allowlist path still enforces** (RBAC + `ToolAllowlistGuardrail` need no
  models); model-backed guards and `scan_descriptions` (`AdversarialGuardrail`)
  **degrade to a no-op** via the existing `try/except` pass-through, logged once at
  boot so the operator knows model DLP is off. Model-grade enforcement is opt-in
  via `enforcement_backend: http` (§9 Q1).
- **Pre-flight scan finds a high-risk upstream** → `warn` (log + front it) or
  `refuse` (don't front that route) per `preflight.on_finding` (§9 Q2).
- **Redis absent** → by design; the file-config path never touches Redis
  (`kill-switch` / metrics / registry are all no-ops without `tenant_id` in a
  registry, and the store is bypassed entirely).
- **Huge / empty args** → existing size caps in the guard chain.

## 8. Test plan (Definition of Done)

- **File-config core (fake upstream, like the existing MCPProxy tests):**
  1. `FileConfigRouter._load_cfg` returns the route dict from a loaded file; unknown
     route → `GatewayError(404)`; **no Redis touched** (assert `get_upstream` not
     called).
  2. `rbac` from the file → `resolve_role` resolves the agent's role with **no
     registry/Redis**; a disallowed tool is **blocked** and a blocked `call_tool`
     **never forwards upstream**.
  3. the `on_decision` sink writes exactly one JSON line per `tools/call` with the
     decision fields; secrets never appear in it.
  4. `isolation_ack: false` → loud warning (and refuse-to-boot when configured).
  5. enforcement-error path: fail-closed by default, opens under
     `SHIELD_GATEWAY_FAIL_OPEN=1`.
- **Entrypoint / server:**
  6. boot with a valid `gateway.yaml` serves `POST /gateway/{route}/mcp`; identity
     comes from `X-Agent-Key`/`X-User-Role`, **not** tool args.
  7. bad/missing config → non-zero exit with a clear message (no server).
- **Pre-flight:**
  8. `preflight.scan` runs the scanner per upstream; `on_finding: refuse` drops a
     high-risk route, `warn` keeps it — both logged.
- **Regression / reuse guard:** the shipped `MCPProxy` / `MCPGatewayRouter` /
  `enforcement` are **unmodified**; `FileConfigRouter` only overrides `_load_cfg`
  and the factory (a test pins that the platform path with Redis still works).
- **Packaging:** the gateway-lite entrypoint imports and boots with **no Redis and
  no torch** installed (slim-image smoke); assert it is **not** in the
  `admin_app` import graph. Clean-venv green; full `pytest tests -q` green; CI gate
  passes.

## Invariant risk flags
- ⚠️ **Hot path** — the gateway-lite *is* the proxy path; budget stated (§2). In
  http mode it only *calls* Shield's guard endpoints, never sits inline with them.
- ✅ **No `admin_app` import** ⇒ no `Dockerfile.admin` change (verify with the
  import-graph guard test).
- ✅ **Reuse, not reinvent** — `MCPProxy`/`enforcement`/`MCPGatewayRouter` unchanged;
  only a `FileConfigRouter` subclass + entrypoint are new.
- ⚠️ **New image `Dockerfile.gateway`** — curated COPY allowlist; deps already in
  `requirements.txt` (no new pip deps). Validate in a clean venv / slim image.
- ⚠️ **Non-bypassability** is operational — enforced via `isolation_ack` warning
  (+ optional refuse-to-boot) and docs.
- ✅ **Non-breaking** — additive; the platform gateway path is untouched.

## Task breakdown (one branch, ordered — committed per task, one PR)
1. **File-config core** — `FileConfigRouter(MCPGatewayRouter)` overriding
   `_load_cfg` from a loaded config object; a YAML loader that validates routes +
   populates `config.rbac`; a JSON/text `DecisionSink` (stdout/file); a
   `proxy_factory` wiring the sink. Tests 1-5 with a fake upstream.
2. **Lite server entrypoint** — `core/mcp/gateway_lite.py`: slim FastAPI app
   mounting `/gateway/{route}/mcp` via the reused `_dispatch`, fixed-team identity;
   `mcp-gateway-lite --config` CLI. Tests 6-7.
3. **Packaging** — `Dockerfile.gateway` (slim, curated COPY), a sample
   `gateway.yaml`, `docker-compose.gateway.yml`, README; boot smoke + admin
   import-graph guard.
4. **Scanner pre-flight** — optional `shield-mcp scan` of each upstream at boot;
   `warn` vs `refuse` per config (composes with PR #263/#264). Test 8.

## Resolved decisions (locked)
1. **Default image = slim CPU: allowlist + logging.** No torch/models in the
   image; RBAC allowlist + tool-call logging (+ best-effort heuristics) on CPU.
   Model-grade DLP/injection is opt-in via `enforcement_backend: http` pointing at
   a Shield backend. Small image, runs anywhere, matches the small-team story.
2. **Pre-flight = warn-and-front by default.** `preflight.on_finding: warn` logs a
   high-risk scan result loudly but still fronts the upstream; `refuse` (don't
   front a flagged route) is opt-in per config. Least surprising for an operator
   who may knowingly front a flagged server.
