# Spec: OpenAI-compatible Chat Completions (guarded proxy)

Status: **DRAFT — awaiting approval.** No code has been written.

## 1. Problem & outcome

Today Shield's proxy `POST /v1/shield/chat/completions`
([routes_gateway.py:388](../api/routes_gateway.py)) **consumes** OpenAI-shaped
`messages` but **returns** a custom `ShieldResponse`
(`{text, usage, inference_time_ms, guardrail_results, blocked, block_reason, tool_calls}`).
That is not a valid `chat.completion` object, so an off-the-shelf OpenAI SDK
(`openai`, LangChain `ChatOpenAI`, LlamaIndex, etc.) pointed at Shield fails to
parse the response.

**Outcome:** a customer sets their OpenAI client's `base_url` to Shield and gets
guardrails transparently, with **zero client code change**:

```python
client = OpenAI(base_url="https://api.guardrails.votal.ai/v1", api_key="<tenant-key>")
client.chat.completions.create(model="...", messages=[...])          # non-stream
client.chat.completions.create(model="...", messages=[...], stream=True)  # stream
```

Success condition: the `openai` Python SDK parses both non-stream and stream
responses without error; input/output guardrails still run; a blocked prompt
comes back as a **200 `chat.completion` whose assistant message is a refusal**
(`finish_reason: "content_filter"`), with guardrail detail under a namespaced
`x_shield` extension field.

**Consumer (confirmed):** guarded LLM proxy — apps use Shield as an OpenAI
`base_url` drop-in.

**Block contract (confirmed):** refusal-as-content (200), not an error object or
a 403.

### Non-goals
- `/v1/moderations`, `/v1/embeddings`, `/v1/completions`, `/v1/responses` — separate specs if wanted.
- OpenAI-shaping the IDP (`agent-token`, `cap/mint`, `cap/verify`), tool RBAC
  (`tool/check`), or MCP gateway — those have **no OpenAI analog** and stay as-is.
- **No change to any existing endpoint.** `/v1/shield/chat/completions`,
  `/guardrails/*`, `cap/mint`, `tools/call` keep their exact current behavior and
  response shapes. This spec is purely additive.

## 2. Plane & latency contract

- **Plane:** data (GPU/vLLM) — mounted in `core/app.py` alongside the existing
  `gateway_router`. Admin plane untouched → **no `Dockerfile.admin` impact.**
- **Guard path:** this is a proxy that *runs* guardrails, but it does **not**
  add latency to the guard primitives (`/guardrails/*`, `cap/mint`,
  `tools/call`) — those code paths are not modified. The new endpoint reuses the
  same `run_input_pipeline` / `run_output_pipeline` the current proxy already
  calls; the only added work per request is response-shape marshalling
  (dict construction), which is negligible (<1 ms, no I/O). Justification: the
  new route is a thin adapter around already-optimized pipeline calls.

## 3. Data model

No new Redis keys, no new persisted state, no new TTLs. Tenant resolution reuses
the existing path: `_extract_api_key(request)` →
`resolve_tenant_by_api_key(api_key)` → `request.state.tenant_id`
([core/middleware.py:396](../core/middleware.py),
[storage/tenant_store.py](../storage/tenant_store.py)). Cross-tenant isolation is
identical to the current proxy — the tenant is bound to the API key, never taken
from the request body.

## 4. API / interface

### New endpoint(s)
`POST /v1/chat/completions` — unprefixed, so the customer's `base_url` is
`https://<host>/v1` (the OpenAI default layout). Served on the **data plane**
via a new `openai_compat_router` (`APIRouter()` with no prefix) included in
`core/app.py`.

> Alternative considered: mounting at `/v1/shield/chat/completions/openai`. Rejected —
> it is not a base_url drop-in, which is the whole point (§1).

### Request
Standard OpenAI Chat Completions body. Parsed fields:
`model` (required by clients, echoed back), `messages` (required),
`stream` (bool), `max_tokens`, `temperature`, `response_format`, `tools`,
`tool_choice`. Unknown fields are ignored (forwarded to upstream where relevant).
Auth: `Authorization: Bearer <tenant-key>` (already supported by
`_extract_api_key`) **or** `X-API-Key`.

### Response — non-stream (200), success
```json
{
  "id": "chatcmpl-<uuid>",
  "object": "chat.completion",
  "created": 1690000000,
  "model": "<echoed model>",
  "choices": [{
    "index": 0,
    "message": {"role": "assistant", "content": "<sanitized_output or raw>",
                "tool_calls": [ ... allowed only ... ]},
    "finish_reason": "stop" | "tool_calls"
  }],
  "usage": {"prompt_tokens": N, "completion_tokens": N, "total_tokens": N},
  "x_shield": {"input_guardrails": [...], "output_guardrails": [...],
               "sanitized": true|false, "blocked_tool_calls": [...]}
}
```
- If the output pipeline rewrote the text, `content` is the **sanitized** text
  (proxy mode makes this clean — the client only ever sees safe text).
- Tool calls: allowed calls are emitted as standard `message.tool_calls`; blocked
  ones are omitted and listed in `x_shield.blocked_tool_calls`.

### Response — non-stream (200), blocked (input or output)
```json
{
  "id": "chatcmpl-<uuid>", "object": "chat.completion", "created": ...,
  "model": "<echoed>",
  "choices": [{
    "index": 0,
    "message": {"role": "assistant",
                "content": "<refusal message, e.g. block_reason>"},
    "finish_reason": "content_filter"
  }],
  "usage": {"prompt_tokens": N, "completion_tokens": 0, "total_tokens": N},
  "x_shield": {"blocked": true, "block_reason": "...",
               "guardrail_results": [ ... ]}
}
```
HTTP status **200** (refusal-as-content). No upstream call is made when input is
blocked.

### Response — stream (`stream: true`)
`text/event-stream` of OpenAI `chat.completion.chunk` frames terminated by
`data: [DONE]`. The existing `_stream_chat_completion` generator already does
exactly this — it forwards upstream chunks verbatim, runs tiered output
guardrails on the accumulated text, and on a block emits a terminal
`finish_reason: "content_filter"` chunk (`_build_content_filter_chunk`) plus
`[DONE]` ([routes_gateway.py:207–385](../api/routes_gateway.py)). **Reuse it
unchanged.** Input-blocked streams emit a single `content_filter` chunk + `[DONE]`
without contacting upstream.

### Reuse (no reimplementation)
`run_input_pipeline`, `run_output_pipeline`, `async_llm_call` / upstream proxy,
`_get_upstream_url`, `_build_payload`, `_build_stream_payload`,
`_stream_chat_completion`, `_extract_tool_calls`, `_check_tool_call_rbac` — all
already in `api/routes_gateway.py`. The new handler is orchestration + OpenAI
marshalling only.

### Middleware enrolment (the one required additive touch)
`ShieldMiddleware` enriches only `_GUARDED_PREFIXES`
(`/v1/shield`, `/v1/tenant`, `/v1/agents`, `/v1/data-policies`) and
`_GUARDED_EXACT` ([core/middleware.py:236–242](../core/middleware.py)). An
unprefixed `/v1/chat/completions` matches none, so tenant/agent context would not
be attached. **Add `"/v1/chat/completions"` to `_GUARDED_EXACT`.** This is
additive — it enrolls the *new* path into existing enrichment and changes no
existing route's behavior.

## 5. Security & backward compatibility

- **Additive & opt-in by construction.** New path; existing endpoints byte-for-byte
  unchanged. Nothing to migrate. No behavior-changing default.
- **Optional kill flag:** `SHIELD_OPENAI_COMPAT_ENABLED` (default **on**). When
  `0`, the router is not mounted (or 404s) — escape hatch if a host must not
  expose the unprefixed path.
- **Authz:** identical to the current proxy — tenant bound to API key, never to
  body; a malicious caller cannot select another tenant or skip guardrails (the
  pipeline runs server-side regardless of request fields).
- **Refusal leakage:** the refusal `content` uses the existing `block_reason`
  string already returned by the current proxy — no new information disclosure.

## 6. Packaging & deploy

- **No new pip deps** — `httpx`, `fastapi`, `pydantic` already present. Nothing
  added to `requirements.txt` / `requirements-test.txt` / `requirements-admin.txt`.
- **No `admin_app.py` import** → no `Dockerfile.admin` COPY change.
- New file `api/routes_openai_compat.py` + one `include_router` line in
  `core/app.py` + one line in `core/middleware.py`. Rebuild the **data-plane
  image** only (`scripts/start_vllm.sh` target). Env: optional
  `SHIELD_OPENAI_COMPAT_ENABLED`.

## 7. Failure modes & edge cases

- **Empty/missing `messages` and no `prompt`** → 400 with an OpenAI-shaped
  `{"error": {...}}` body (parity with SDK expectations).
- **Upstream/backend error (5xx, timeout)** → propagate as OpenAI-shaped error
  JSON with the upstream status (mirror existing `_stream_chat_completion`
  error handling). Fail-**closed** for guardrails: if the input pipeline itself
  errors, treat as block (never proxy an unguarded request).
- **Output pipeline error** on non-stream → fail-closed: return a
  `content_filter` refusal rather than leaking unguarded text.
- **Huge input** → same limits as the current pipeline (no new limit introduced).
- **`stream: true` + output guardrail** → tokens already partially sent; handled
  by the existing tiered stream checker (fast/slow tiers) which cuts the stream
  with a `content_filter` terminal chunk. Documented limitation: content emitted
  before the check boundary has already reached the client (unchanged from
  today's streaming behavior).
- **Redis down (tenant unresolved)** → same degradation as current proxy; guard
  config falls back to server defaults, request is still guarded.
- **`model` absent** → echo `"unknown"` (SDKs tolerate; matches current stream
  default).

## 8. Test plan (Definition of Done)

New `tests/test_openai_compat_chat_completions.py`:
1. **Happy non-stream:** valid body → `object=="chat.completion"`, one choice,
   `message.role=="assistant"`, `finish_reason=="stop"`, `usage` present,
   parses via `openai` types (or a schema assert).
2. **Input blocked:** adversarial prompt → 200, `finish_reason=="content_filter"`,
   `x_shield.blocked is True`, **no upstream call** (mock asserts not called).
3. **Output sanitized:** output pipeline rewrites → `content` equals sanitized
   text, `x_shield.sanitized is True`.
4. **Tool calls:** upstream returns tool_calls, one blocked by RBAC → allowed
   call in `message.tool_calls`, blocked one in `x_shield.blocked_tool_calls`,
   `finish_reason=="tool_calls"`.
5. **Streaming happy:** `stream=True` → SSE frames are `chat.completion.chunk`,
   terminated by `[DONE]`.
6. **Streaming blocked:** output-guard trips mid-stream → terminal
   `content_filter` chunk + `[DONE]`.
7. **Bad request:** no messages/prompt → 400 OpenAI-shaped error.
8. **Bearer auth:** `Authorization: Bearer <key>` resolves the tenant (regression
   for the middleware enrolment).
9. **Existing-endpoint regression:** `/v1/shield/chat/completions` still returns
   the legacy `ShieldResponse` unchanged (guards against accidental coupling).

Green in a **clean venv** (`python -m venv /tmp/x && /tmp/x/bin/pip install -r
requirements-test.txt && /tmp/x/bin/python -m pytest tests -q`); CI `pytest` gate
passes.

## Invariant risk flags
- ✅ Off the hot path — no change to guard primitives; adapter overhead is dict marshalling.
- ✅ No admin import → no `Dockerfile.admin` drift.
- ✅ No new deps.
- ⚠️ **One additive middleware line** (`_GUARDED_EXACT`) is required for the
  drop-in path to receive tenant context — called out here so review expects it;
  it enrols the new path only and does not alter existing routes. Covered by test #8.
- ✅ Non-breaking / secure-by-default — additive endpoint, optional kill flag.

## Proposed task breakdown (PRs)
- **PR 1 (this spec):** `api/routes_openai_compat.py` with the **non-stream**
  `POST /v1/chat/completions` (success + input-block refusal + output sanitize),
  middleware enrolment, `core/app.py` wiring, tests #1–3, #7–9. One reviewable unit.
- **PR 2:** wire `stream: true` through the existing `_stream_chat_completion`,
  tests #5–6.
- **PR 3:** tool-call mapping into `message.tool_calls` + `x_shield.blocked_tool_calls`,
  test #4.

(If preferred, PR 1+2 can merge since streaming reuses existing code with no new
logic — call it in approval.)

## Open decisions for approver
1. **Path:** confirm unprefixed `/v1/chat/completions` (drop-in) vs. a
   `/v1/shield/...` variant. Recommended: unprefixed.
2. **`x_shield` field name:** OpenAI clients ignore unknown top-level fields, but
   some strict proxies validate. Confirm `x_shield` (vs. `metadata` / a response
   header). Recommended: `x_shield` top-level + also mirror block state in an
   `X-Shield-Blocked` header for header-only consumers.
3. **PR split:** 3 PRs as above, or fold streaming into PR 1?
