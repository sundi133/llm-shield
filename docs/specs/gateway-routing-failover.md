---
title: "Spec: model routing and failover in Shield's LLM proxy"
layout: default
nav_exclude: true
permalink: /specs/gateway-routing-failover/
description: Route each model call through Shield's OpenAI-compatible proxy to the right provider and model by policy, data sensitivity, latency and cost, and fail over when a provider errors or times out, with Shield's guardrails applied once to whichever model answers.
---

# Spec: model routing and failover in Shield's LLM proxy

> Status: **APPROVED and built** (tasks 1 to 5; task 6 not started). See "As built"
> at the end. Branch `spec/gateway-routing-failover`.
> Related: `docs/spec-openai-compat-chat-completions.md` (the proxy this
> extends), `docs/ai-gateway-interoperability.md` (Shield inside LiteLLM,
> Portkey, Kong), `core/secret_vault/` (provider keys), `docs/specs/ai-discovery.md`.
> Origin: the Quilr comparison gap list (gateway routing, failover, cost).

## 1. Problem & outcome

Shield already proxies model calls: `POST /v1/chat/completions` (OpenAI
compatible, `api/routes_openai_compat.py`) and `POST /v1/shield/chat/completions`
(`api/routes_gateway.py`). Both send every call to **one** place:

| Today (verified on main 33f82f8) | Consequence |
|---|---|
| One `llm_backend.upstream_url` from the process-wide config (`api/routes_gateway.py:_get_upstream_url`), else the built-in model | No per-tenant choice of provider or model; every tenant shares one upstream |
| `httpx.AsyncClient(timeout=300)`, one attempt, no retry (`routes_gateway.py:602`, `routes_openai_compat.py:270`, streaming at `:237`) | A provider outage or a hung call is the caller's outage, for up to 5 minutes |
| Only the JSON body is forwarded; no `Authorization` or provider key | The upstream must be keyless (vLLM, Ollama). OpenAI, Anthropic, Azure and similar cannot be reached through Shield at all |
| The request's `model` is passed through unchanged | No aliasing ("smart", "cheap", "private") and no way to move callers between models centrally |
| `budget_exceeded` is a declared webhook event (`api/routes_webhooks.py`) that nothing emits | No spend tracking or limits |
| Guard results are computed before the call and thrown away for routing | A prompt Shield has just flagged as containing PII (allowed in monitor or warn mode) still goes to whatever the default upstream is |

Customers who already run an AI gateway keep using it with Shield as the
guardrail (LiteLLM plugin, Portkey or Kong patterns). This spec is for the
customers who use **Shield's proxy as their gateway** and today get no routing,
no failover and no provider keys.

**Outcome.** A tenant defines **targets** (a provider endpoint, a model name, a
credential, optional prices) and **routes** (a name callers use as `model`, an
ordered list of targets, a strategy, and rules). For each call Shield:

1. runs the input guardrails once, as today;
2. picks the route by the request's `model`, applies its rules (data
   sensitivity from the guard results, agent, role, a data-class header, prompt
   size, budget) to choose the eligible targets;
3. calls the best healthy target and, on a timeout, connection error, 429 or
   5xx, the next one, within the route's limits;
4. runs the output guardrails and tool RBAC once, on the answer that came back;
5. records which target answered, the failovers, tokens and cost.

Observable success: with OpenAI's endpoint returning 503, a call to
`model: "smart"` is answered by the second target with
`X-Shield-Failovers: 1`; a prompt flagged by the PII guardrail goes only to the
on-prem target even when a cloud target is cheaper; a route over its monthly
budget follows its configured action and raises `budget_exceeded`.

**Non-goals.**
- Provider-native wire formats in v1: only the OpenAI Chat Completions format
  (OpenAI, Azure OpenAI, vLLM, Ollama, Groq, Together, Mistral, OpenRouter,
  Fireworks, and the OpenAI-compatible endpoints Anthropic and Google offer).
  Bedrock (SigV4) and native Anthropic Messages are a later adapter.
- Embeddings, images, audio, the Responses API. Chat Completions only.
- Semantic caching, prompt rewriting, load-testing, or matching LiteLLM's
  provider list. Customers who need that keep LiteLLM in front.
- A built-in price list. Prices change and differ by contract; the tenant
  enters them per target (section 3.1). Without prices, cost strategies and
  budgets are unavailable for that target and say so.
- Routing on `/guardrails/*`, `tool/check`, `cap/mint` or MCP `tools/call`.
  Those endpoints judge content; they never call a model on the caller's
  behalf.
- Classifying prompt complexity to pick a cheaper model. Optional task 6, kept
  separate because it needs a model artifact and torch (section 6).

## 2. Plane & latency contract

- **Data plane** (`core/app.py`): the two proxy endpoints gain routing and
  failover. This is the proxy path, not the guard path: `/guardrails/*`,
  `tool/check`, `cap/mint` and `tools/call` are **unchanged**.
- **Latency budget on the proxy:** route resolution and target choice add
  **at most 1 ms** (in-process, measured in task 1's benchmark test as overhead
  against today's code, not as an absolute figure). No Redis read on a request:
  the tenant's routing config is cached in-process for 10 s and refreshed in the
  background (stale-while-revalidate), the same lesson as the tool registry
  read that cost 26 ms per call at 1,000 tools. Usage and health go to an
  in-process buffer flushed every 30 s (pattern of
  `core/policy_learning/observe.py`).
- A failover adds the failed attempt's time. Each target has its own timeout
  (default 60 s, streaming first byte 20 s) and each route a total deadline
  (default 120 s), so the worst case is bounded and far below today's single
  300 s wait.
- **Admin plane** (`admin_app.py`): targets, routes, simulation, usage and
  health views, and the portal tab. Off the proxy path.
- A tenant with no routes, or a request whose `model` matches no route, takes
  exactly today's path. Nothing changes for them.

## 3. Data model

All keys are tenant-scoped by the tenant resolved from the caller's key
(`request.state.tenant_id`); a request with no tenant never uses routes.

### 3.1 Targets: `gw_targets:{tenant}`

JSON object `{target_id: target}`, at most 50 targets.

```json
{
  "id": "openai-4o",
  "name": "OpenAI GPT-4o",
  "base_url": "https://api.openai.com/v1",
  "flavor": "openai",                         // openai | azure
  "model": "gpt-4o",                          // sent upstream as "model"
  "azure": {"deployment": "", "api_version": ""},
  "auth": {"mode": "vault",                   // vault | passthrough | none
           "header": "Authorization", "scheme": "Bearer",
           "secret_ref": "shield://openai_prod"},
  "location": "cloud",                        // cloud | on_prem (rules match on it)
  "allow_private": false,                     // an RFC 1918 base_url needs this
  "timeout_s": 60, "first_byte_timeout_s": 20,
  "price": {"input_per_mtok": 2.50, "output_per_mtok": 10.00, "currency": "USD"},
  "enabled": true, "updated_at": 0, "updated_by": ""
}
```

- `auth.mode: vault` stores only the reference. The key is materialized on the
  outbound request by `core.secret_vault.materialize.materialize_headers`, and
  only when the secret's bindings include the target's host; the target write
  is refused when they do not. The key never appears in config, logs, audit or
  responses.
- `auth.mode: passthrough` forwards the caller's `X-Shield-Upstream-Key`
  header (bring your own key) to this target only. A failover to a target in
  another mode does not receive it.
- `auth.mode: none` for keyless on-prem servers (vLLM, Ollama).

### 3.2 Routes: `gw_routes:{tenant}`

JSON object `{route_name: route}`, at most 100 routes. `route_name` is what
callers send as `model` (letters, digits, `.`, `_`, `-`, `/`; e.g. `smart`,
`private`, `shield/cheap`).

```json
{
  "name": "smart",
  "targets": ["openai-4o", "azure-4o", "onprem-qwen"],   // the eligible set, in priority order
  "strategy": "priority",            // priority | lowest_latency | lowest_cost | weighted
  "weights": {"openai-4o": 70, "azure-4o": 30},          // weighted only
  "failover": {"max_attempts": 3, "deadline_s": 120,
               "on": ["timeout", "connect", "429", "5xx"]},
  "rules": [
    {"when": {"flagged": ["pii_detection", "secrets_detection"]},
     "use": ["onprem-qwen"]},
    {"when": {"data_class": ["restricted"]}, "use": ["onprem-qwen"]},
    {"when": {"role": ["contractor"]}, "deny": "Contractors cannot use this model"},
    {"when": {"prompt_tokens_over": 60000}, "use": ["azure-4o"]}
  ],
  "budget": {"monthly": 500.0, "currency": "USD",
             "at_limit": "fallback",           // warn | fallback | block
             "fallback_targets": ["onprem-qwen"]},
  "enabled": true, "updated_at": 0, "updated_by": ""
}
```

**Rules** are evaluated in order; the first that matches decides. `use`
**narrows** the eligible set to the listed targets (they must be in
`targets`); `deny` refuses the call. Conditions in one `when` must all hold:

| Condition | Matches when |
|---|---|
| `flagged` | One of these guardrails did not pass on this request's input but the request was allowed (monitor mode, or action warn or log). This is the data-sensitivity signal Shield already computed |
| `data_class` | The caller's `X-Shield-Data-Class` header is one of these values |
| `agent` / `role` | The resolved agent key or role name is one of these (from the auth middleware, never a raw header) |
| `location_required` | Shorthand: keep only targets with this `location` |
| `prompt_tokens_over` | An estimate of the prompt's tokens (characters / 4) exceeds the value |

**The invariant that makes rules safe:** failover and every strategy act only
inside the eligible set a rule produced. A prompt routed to on-prem because it
carries PII is never sent to a cloud target because the on-prem one failed;
if every eligible target fails, the call fails (section 7).

### 3.3 Usage, spend and health

| Key | Shape | Notes |
|---|---|---|
| `gw_usage:{tenant}:{yyyymmdd}` | HASH `"{route}|{target}"` → JSON `{calls, ok, errors, failovers_from, input_tokens, output_tokens, cost, latency_ms_sum}` | Written by the flush (30 s); TTL 95 days |
| `gw_spend:{tenant}:{yyyymm}` | HASH `{route}` → cost as a decimal string | Incremented by the flush; read by the config refresh; TTL 400 days |
| `gw_health:{tenant}` | HASH `{target_id}` → JSON `{state, failures, last_error, last_ok_at, at, process}` | Each data-plane process writes its own view at flush; TTL 1 h; for the portal only |

Circuit state used for decisions lives **in each process** (no shared state on
the request path). A target opens after 5 failures within 60 s, stays open for
30 s, then lets one probe call through (half-open). Latency for
`lowest_latency` is an exponentially weighted average per process.

Spend used for budget decisions is the stored month total plus this process's
unflushed spend, refreshed with the config every 10 s. It can therefore exceed
the limit by up to one flush interval of traffic across processes; the spec
accepts that and the portal says so.

## 4. API / interface

### 4.1 Callers (data plane, unchanged endpoints)

Callers keep using `POST /v1/chat/completions` or
`POST /v1/shield/chat/completions` with their tenant key, and put a route name
in `model`. Optional request headers:

| Header | Meaning |
|---|---|
| `X-Shield-Data-Class` | A label the route's rules can match (`public`, `internal`, `restricted`, ...). It can only narrow where a call goes, never widen it past the route's `targets` |
| `X-Shield-Upstream-Key` | The caller's own provider key, for targets in `passthrough` mode. Stripped before logging |

Response additions, when a route was used:

| Where | Field |
|---|---|
| Headers (both endpoints) | `X-Shield-Route`, `X-Shield-Target`, `X-Shield-Failovers` (count), `X-Shield-Budget` (`ok`, `warn`, `fallback`) |
| `/v1/chat/completions` body | `x_shield.routing: {route, target, attempts: [{target, outcome, ms}], rule, cost}`; `model` is the target's model name, as OpenAI clients expect |
| `/v1/shield/chat/completions` body | `routing` with the same object, next to `guardrail_results` |

A `deny` rule, an exhausted route, or a `block` budget answers like a guardrail
block on each endpoint (200 with `finish_reason: "content_filter"` on the
OpenAI-compatible one; 403 on the legacy one), with `x_shield.routing.reason`.

### 4.2 Configuration (admin plane), `/v1/tenant/me/gateway`

| Route | Does | Gate |
|---|---|---|
| `GET /targets`, `GET /targets/{id}` | List, read (credentials shown as the reference only) | tenant |
| `PUT /targets/{id}`, `DELETE /targets/{id}` | Create or replace, delete (refused while a route uses it, 409) | config write; `allow_private: true` also needs the registry write gate, as for MCP servers |
| `GET /routes`, `GET /routes/{name}` | List, read | tenant |
| `PUT /routes/{name}`, `DELETE /routes/{name}` | Create or replace, delete | config write |
| `POST /routes/{name}/simulate` `{messages, headers, agent, role}` | Runs the input guardrails and the rules and returns the eligible set, the order the strategy would try, and the budget state; calls no model | config write (it runs guardrails) |
| `GET /usage?from=&to=&route=` | Daily calls, tokens, cost, failovers, errors per route and target | tenant |
| `GET /health` | The last flushed circuit state per target and process | tenant |

All writes are audited (`gateway_target_set`, `gateway_target_deleted`,
`gateway_route_set`, `gateway_route_deleted`). Webhook `budget_exceeded` (the
event that already exists) fires once per route per month when spend crosses
`budget.monthly`, and `gateway_target_down` (new) when a target's circuit opens,
at most once per target per 10 minutes per process.

### 4.3 Portal

A **Model routing** tab: targets (health dot, location, price), routes (targets
in order, strategy, rules in plain words, budget bar), a simulator ("which
model would this prompt use, and why"), and a usage table by day.

## 5. Security & backward compatibility

- **Default:** no behavior change. Routing applies only when the tenant has a
  route whose name equals the request's `model`. `SHIELD_LLM_ROUTING=0`
  disables it process-wide (escape hatch: every call takes today's path).
- **Guardrails are not bypassable by routing.** Input guardrails run once
  before routing, exactly as today; output guardrails and tool RBAC run once
  on the answer that is returned, whichever target produced it. A failed
  attempt's partial output is discarded, never returned. Both endpoints keep
  their fail-closed behavior.
- **Rules only narrow.** `use` must be a subset of the route's `targets`;
  `X-Shield-Data-Class` can only select a narrower rule; failover never leaves
  the eligible set. A caller cannot name a target directly.
- **Credentials.** Vault references only, bound to the target's host by the
  vault's own binding check (`_binding_matches`); `is_self_host` refuses
  binding to a Shield plane. Passthrough keys go to that one target and are
  never logged. Target reads never return a secret.
- **Egress (SSRF).** `base_url` is checked with
  `core.url_safety.validate_outbound_url(purpose="llm-target")` at write and
  again at call time (DNS rebinding), private addresses only with
  `allow_private`, and redirects are not followed (`follow_redirects=False`).
- **Body hygiene.** Shield sets `model` to the target's model and drops fields
  the target flavor does not accept (`x_shield`, Shield-only fields); the rest
  of the client body passes through as today.
- **Cross-tenant.** Config, usage, spend and health are keyed by the caller's
  tenant; the in-process cache is keyed by tenant.
- **Existing tests stay green.** `docs/spec-openai-compat-chat-completions.md`
  requires the legacy endpoint to stay byte-for-byte unchanged; that holds for
  every call that matches no route.

## 6. Packaging & deploy

- New package `core/llm_gateway/`: `config.py` (store, validation, cache),
  `select.py` (rules, strategies, budget), `health.py` (circuit, latency),
  `dispatch.py` (call with failover, streaming), `usage.py` (buffer, flush).
- Data plane: `api/routes_gateway.py` and `api/routes_openai_compat.py` call
  `core.llm_gateway.dispatch` at their existing "proxy to the LLM" points and in
  `_build_stream_payload` / `_stream_chat_completion`.
- Admin plane: `api/routes_llm_gateway_admin.py`, mounted in `admin_app.py`.
  **`Dockerfile.admin` gets `COPY core/llm_gateway/` and the route module**
  (guarded by `tests/test_admin_dockerfile_imports.py`).
- **No new dependencies** for tasks 1 to 5 (httpx is already used).
- Env: `SHIELD_LLM_ROUTING` (default on; `0` ignores routes),
  `SHIELD_LLM_ROUTING_CACHE_S` (10), `SHIELD_LLM_ROUTING_FLUSH_S` (30).
- Rebuild the data-plane image and the admin image.
- **Task 6 only:** the complexity router (ModernBERT, `predict_router.py` and
  `router-complexity/` in a local checkout, not in the repo) needs `torch` and
  `transformers` and a published model artifact. It would add a `complexity`
  condition (`low`, `medium`, `high`) to rules. Not started without its own
  approval and a latency measurement on the data plane.

## 7. Failure modes & edge cases

| Case | Behavior |
|---|---|
| `model` matches no route, or no tenant | Today's path, unchanged |
| A target times out, refuses the connection, answers 429 or 5xx | Next eligible target, within `max_attempts` and `deadline_s`; recorded in `attempts` |
| A target answers 400, 401, 403, 404, 422 | No failover (the request or the credential is wrong, and another target would likely fail the same way, or leak a bad request further); the error is returned in the endpoint's error shape, naming the target |
| Every eligible target failed | 502 on the legacy endpoint; on the OpenAI-compatible one an OpenAI-shaped error (`type: "upstream_error"`) listing the attempts. Never a fallback outside the eligible set |
| A rule narrows to targets that are all disabled or open | Same as every target failed; the simulator shows it before it happens |
| Streaming, target fails before the first byte | Failover as above |
| Streaming, target fails after bytes were sent | No failover (the client already has part of an answer); the stream ends with the existing content-filter or error chunk |
| Vault disabled, or the reference is missing or not bound to the host | That target is skipped as `credential_unavailable` and counted as a failure; the target write is refused up front when detectable |
| Price missing on a target | `lowest_cost` orders it last; budgets count it as 0 and the portal flags the route as "spend incomplete" |
| Redis down | Cached config keeps serving; if the cache is cold, routes are unavailable and calls take today's path, logged once per minute. Usage stays in the buffer (capped at 10,000 rows per process, then oldest dropped and counted) |
| Config changed | Seen by every process within the cache interval (10 s) |
| Budget crossed during a burst | Over by at most one flush interval across processes (section 3.3); `at_limit` then applies |
| `block` budget on a route an agent depends on | The refusal says the route's budget is spent; `warn` is the default `at_limit` |
| Huge request body | Same limits as today; `prompt_tokens_over` uses a character estimate, no tokenizer |
| Output guardrail blocks the answer | Blocked as today; no failover to "try another model until one passes" (that would turn routing into a guardrail bypass) |
| Tool calls in the answer | RBAC and kill switch on the returned answer, as today |

Fail-closed where it protects data (rules, eligible sets, credentials,
guardrails); fail-open to today's path only when routing itself is unavailable
(no config), which is the behavior every tenant has now.

## 8. Test plan (Definition of Done)

1. Config validation: every field, limits (50 targets, 100 routes), rule
   targets must be a subset, bad URLs, private URL without `allow_private`,
   vault reference not bound to the host, passthrough header name.
2. Selection: each strategy; each rule condition; first match wins; `use`
   narrows; `deny`; budget states `warn`, `fallback`, `block`; disabled and
   open targets skipped.
3. The narrowing invariant: a property-style test over random routes and
   failures that no attempt ever goes outside the eligible set.
4. Dispatch with a fake upstream: timeout, connect error, 429, 5xx fail over;
   4xx does not; deadline and `max_attempts`; attempts recorded; the answer
   from the second target goes through the output guardrails; a failed
   attempt's body is never returned.
5. Streaming: failover before the first byte; none after.
6. Credentials: vault materialization only for the bound host; passthrough key
   only to passthrough targets; keys absent from logs, audit and responses.
7. Circuit breaker: opens, half-opens, closes; per process; health flush.
8. Usage and spend: buffer, flush, cost from prices and usage, monthly spend,
   `budget_exceeded` once per route per month, `gateway_target_down` throttled.
9. Backward compatibility: with no routes (and with `SHIELD_LLM_ROUTING=0`)
   both endpoints behave exactly as before, using the existing
   `tests/test_openai_compat*.py` and gateway tests unchanged; an overhead
   benchmark for resolution (at most 1 ms added).
10. Admin routes: gates (route classification test covers the new writes),
    audit, simulate calls no model, credentials never returned;
    `Dockerfile.admin` import guard; portal escaping and empty state.
11. Full suite green in a clean venv; CI `pytest` passes.

## Tasks (one branch, one PR, one commit per task)

1. **Targets, routes and priority failover (non-streaming).** `core/llm_gateway/`
   config, select (priority only, no rules yet), dispatch, credentials (vault,
   passthrough, none), SSRF checks; both endpoints; response headers and
   `routing` fields; audit metadata; admin CRUD and simulate; `Dockerfile.admin`.
   Tests 1, 2 (priority), 4, 6, 9, 10.
2. **Streaming, health and strategies.** Failover before the first byte, the
   circuit breaker, `lowest_latency` and `weighted`, the health flush and
   `GET /health`, `gateway_target_down`. Tests 5, 7.
3. **Rules.** `flagged`, `data_class`, `agent`, `role`, `location_required`,
   `prompt_tokens_over`, `deny`; the narrowing invariant. Tests 2 (rules), 3.
4. **Cost and budgets.** Prices, usage buffer and flush, `lowest_cost`, monthly
   spend, `at_limit`, `budget_exceeded`, `GET /usage`. Test 8.
5. **Portal tab.** Targets, routes, simulator, usage. Test 10 (portal).
6. **Optional, separate approval: complexity condition** from the ModernBERT
   router, after the model is published and its data-plane latency measured.

## As built (tasks 1 to 5)

- **Simulator.** The admin image carries no input guardrail pipeline (it runs
  on the data plane), so `POST /routes/{name}/simulate` does not run
  guardrails: the request names the guardrails that would flag the prompt
  (`flagged`), with the data class, role, agent and a sample for its length.
- **A matched route never falls back.** If the route matches but cannot be
  evaluated (a bug), the call is refused like a block, not sent to the
  default upstream. Only a missing routing config (cold cache with the store
  down) takes the default path.
- **Rules.** `location_required` is not a test: it narrows the targets of a
  rule that matched, and on its own it always applies. All other conditions
  present must hold. The first matching rule decides.
- **Budgets** apply after the rules: `fallback` narrows the rule's eligible
  targets to `fallback_targets`; if that leaves none, the call is refused.
  Spend used for decisions is the stored month total from the cached
  snapshot plus this process's unflushed spend, so it can trail by one flush.
- **Streaming.** Failover stops once a target answers with a status line;
  the first-byte timeout bounds the wait for it. A routed stream that breaks
  after starting ends with an `upstream_error` event and `[DONE]`, and is
  counted as `stream_broken`. A stream without reported usage is costed from
  characters (4 per token) and counted in `estimated`. The existing SSE
  proxy, with its mid-stream output guardrails, is reused for routed streams.
- **Health** outcomes that count as failures: timeout, connect, 429, 5xx,
  bad response, credential unavailable, unsafe URL. A 4xx does not.
- **Webhooks.** `gateway_target_down` is a new event; `budget_exceeded` (declared
  before, never sent) now fires once per route per month across processes
  via `HSETNX gw_budget_alerted:{tenant}:{yyyymm}`.
- **Body.** Shield drops `prompt`, `system`, `x_shield` and `run_id`, sets
  `model` to the target's, and sends the client's own `messages` (not the
  default system message the legacy path adds).
- **Portal.** Targets are edited in a form, routes as JSON. Checked in a
  browser against the admin app with seeded targets, routes, usage and health.
- **Not done:** task 6 (complexity condition) needs its own approval.
