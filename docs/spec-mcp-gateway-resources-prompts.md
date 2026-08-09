# Spec: MCP gateway — resources/* and prompts/* passthrough

Status: **DRAFT — for approval.** Spec-first per `CLAUDE.md`; no code until sign-off.

## 1. Problem & outcome

The gateway ([routes_mcp_gateway_server.py](../api/routes_mcp_gateway_server.py))
handles `initialize` / `tools/list` / `tools/call` and returns `-32601` for
everything else; `MCPProxy` ([proxy_server.py](../core/mcp/proxy_server.py)) only
exposes `list_tools`/`call_tool`. So a customer MCP server that also exposes **MCP
resources or prompts** can't be fully used through the gateway.

**Outcome:** the gateway also proxies `resources/list`, `resources/read`,
`resources/templates/list`, `prompts/list`, `prompts/get` — so a resource/prompt
server is usable end-to-end behind Shield, unmodified. The one method that returns
content that could carry sensitive data — **`resources/read`** — is run through the
**same output DLP** as tool results; the rest pass through faithfully (with room to
add resource/prompt policies later). The underlying `ClientSession` already
supports these calls; we only surface + guard them.

**Non-goals.** Not adding per-resource/per-prompt RBAC policy *authoring* now
(passthrough + optional future policy). Not `sampling` / `completion` / `roots`
(server→client and generative flows — separate, later). Not changing the tools
path. Not incremental streaming of large resources (buffer, like tool output).

## 2. Plane & latency contract

- Same **data-plane gateway** as the existing feature; it *is* the hot path for
  proxied traffic. Per method:
  - `resources/read` → 1 upstream fetch + **1 DLP call** (`sanitize_tool_result`,
    same cost as a tool result).
  - `resources/list` / `resources/templates/list` / `prompts/list` / `prompts/get`
    → **forward-only** (+ an optional in-memory filter), no guard round-trip.
- No added latency to Shield's own `/guardrails/*` / `cap/mint` / `tools/call`.
  In HTTP-enforcer mode, `resources/read` calls `/v1/shield/tool/output` (a client
  call), never inline with those endpoints.

## 3. Data model

- **No new Redis keys for v1.** Lists/prompts pass through; `resources/read` reuses
  the existing output-DLP path (no new storage). The upstream config
  (`mcp_gateway:upstream:{tenant}:{route}`) is unchanged.
- (Future, out of scope) an optional resource/prompt allowlist would live in that
  same per-route config — flagged, not built here.
- Tenant scoping unchanged (route is already tenant-scoped).

## 4. API / interface

**Gateway JSON-RPC** ([routes_mcp_gateway_server.py](../api/routes_mcp_gateway_server.py)) —
`_dispatch` gains cases (identity still from the connection, never args):

| Method | Gateway behavior |
|---|---|
| `resources/list` | forward → `{resources:[...]}` (optional RBAC-style filter if a policy exists, else passthrough) |
| `resources/templates/list` | forward → `{resourceTemplates:[...]}` (passthrough) |
| `resources/read` | forward → **DLP-sanitize each returned content block** via `sanitize_tool_result`; on block, return an MCP error |
| `prompts/list` | forward → `{prompts:[...]}` (passthrough / optional filter) |
| `prompts/get` | forward → `{messages:[...]}` (passthrough v1; injection screening is a flagged follow-up) |
| anything else | still `-32601` (unchanged) |

**`MCPProxy`** ([proxy_server.py](../core/mcp/proxy_server.py)) — new methods
mirroring the existing shape: `list_resources`, `read_resource(uri)`,
`list_resource_templates`, `list_prompts`, `get_prompt(name, arguments)`.
`read_resource` runs `self._enforcer.sanitize_tool_result(...)` on the content
(synthetic label = the resource URI) so both enforcement backends work unchanged.

**`MCPUpstream`** ([upstream.py](../core/mcp/upstream.py)) — add adapter methods
wrapping the SDK `ClientSession`: `list_resources()` → `session.list_resources()`,
`read_resource(uri)` → `session.read_resource(uri)`, `list_resource_templates()`,
`list_prompts()`, `get_prompt(name, args)` → `session.get_prompt(...)`, with the
same tolerant normalization the tool methods use (SDK result objects **or** fakes).

**`MCPGatewayRouter`** ([gateway.py](../core/mcp/gateway.py)) — thin delegators
(`list_resources`/`read_resource`/`list_prompts`/`get_prompt`) that resolve the
pooled proxy exactly like `call_tool` does.

**Enforcer seam:** no `Enforcer` protocol change — `resources/read` reuses
`sanitize_tool_result` (already on both backends); lists don't call the enforcer.

## 5. Security & backward compatibility

- **Additive & non-breaking.** These methods currently return `-32601`; supporting
  them is a pure capability gain. The **tools path is untouched** (regression-pinned).
- **`resources/read` is DLP-guarded by default** — resource content is treated like
  tool output, so PII/secrets are sanitized before reaching the agent. This is the
  safe default; a route can't accidentally leak resource content that tool output
  would have redacted.
- **Graceful degradation:** where no resource/prompt policy is configured (the v1
  norm), lists/prompts pass through unchanged — the gateway never *blocks* a method
  it has no policy for, it just relays it.
- **Non-bypassability unchanged** — same `isolation_ack` deployment requirement;
  identity still from the authenticated connection.
- **Escape hatch:** `SHIELD_GATEWAY_RESOURCES=0` disables the new methods (revert to
  `-32601`) if an operator wants tools-only. Default on (additive).

## 6. Packaging & deploy

- **No new dependency** — `mcp` already declared; `ClientSession` already supports
  these calls. **No `admin_app` import** (gateway is data-plane only) ⇒ no
  `Dockerfile.admin` change. Files touched already exist and are dir-copied by the
  data-plane image.
- **Env flag:** `SHIELD_GATEWAY_RESOURCES` (default on). Rebuild: data-plane image.

## 7. Failure modes & edge cases

- **Upstream doesn't implement resources/prompts:** the SDK call raises
  method-not-found → return a clean MCP error (`-32601` / relay the upstream error),
  never a 500.
- **Large / binary resource content:** buffer + size-cap before DLP (like tool
  output); binary blobs (base64) passed through with a documented size cap, DLP on
  text blocks only.
- **DLP block on `resources/read`:** return an MCP error (content withheld), same as
  a blocked tool output.
- **Enforcer down (HTTP mode) on read:** existing fail-open/closed policy applies.
- **Empty/absent lists:** return `{resources:[]}` / `{prompts:[]}` cleanly.
- **Unknown sub-method (e.g. `resources/subscribe`):** `-32601` (documented; can add
  later).
- **Concurrency:** stateless per call; pooled session reused (unchanged).

## 8. Test plan (Definition of Done)

- **Unit (fake `UpstreamClient` extended with resources/prompts, like the tool tests):**
  1. `resources/read` content runs through DLP (redaction visible; block path).
  2. `resources/list` / `resources/templates/list` / `prompts/list` / `prompts/get`
     forward faithfully (passthrough), including empty results.
  3. upstream that lacks a method → clean MCP error, not a crash.
  4. **regression:** `tools/list` / `tools/call` behave byte-identically to today;
     `MCPProxy` with no enforcer still defaults to in-process.
  5. dispatcher routes each new method to the right proxy call; unknown still `-32601`.
  6. `SHIELD_GATEWAY_RESOURCES=0` → new methods return `-32601` (flag honored).
  7. identity from the connection, not from params.
- **Clean venv:** full `pytest tests -q` green; CI gate passes.

## Invariant risk flags
- ⚠️ **Hot path** — `resources/read` adds one DLP call (equivalent to a tool result);
  lists are forward-only. Budget stated.
- ✅ No new dep · ✅ no `admin_app` import / `Dockerfile.admin` change · ✅ tools path
  unchanged (non-breaking) · ⚠️ new capability gated by `SHIELD_GATEWAY_RESOURCES`
  (default on) with an off switch.

## Task breakdown (one branch, ordered)
1. **Adapter + proxy** — `MCPUpstream` resources/prompts methods + `MCPProxy`
   `list_resources`/`read_resource`(DLP)/`list_resource_templates`/`list_prompts`/
   `get_prompt` + unit tests (fake upstream). No dispatcher yet.
2. **Router + dispatcher** — `MCPGatewayRouter` delegators + `_dispatch` cases +
   `SHIELD_GATEWAY_RESOURCES` flag + tests.
3. **Docs** — `docs/mcp-gateway.md`: supported methods matrix, what's enforced
   (`resources/read` = DLP), passthrough note, flag.

## Open questions (for approval)
1. **`resources/read` DLP default** — sanitize by default (recommended, safe), or
   passthrough unless a policy is set? Recommend **default-sanitize**.
2. **List filtering** — v1 passthrough for `resources/list`/`prompts/list`, or add a
   per-route allowlist policy now? Recommend **passthrough v1** (policy later).
3. **`prompts/get` screening** — passthrough v1, or screen the returned prompt for
   indirect injection now? Recommend **passthrough v1**, flag screening as follow-up.
4. **Flag** — ship `SHIELD_GATEWAY_RESOURCES` default-on with an off switch (as
   specced), or always-on with no flag?
