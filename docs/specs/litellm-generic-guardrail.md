---
title: "Spec: LiteLLM Generic Guardrail API"
layout: default
nav_exclude: true
permalink: /specs/litellm-generic-guardrail/
description: One endpoint on Shield that speaks LiteLLM's Generic Guardrail API, so a LiteLLM proxy uses Shield with a few lines of config and no plugin code.
---

# Spec: LiteLLM Generic Guardrail API

> Status: **APPROVED 2026-10-01** (user: "approved"). Task 1 built; tasks 2 and 3 open.
> Branch: `litellm_integration` (from main at 43058d3).
> Contract source: LiteLLM `main` on 2026-10-01,
> `litellm/proxy/guardrails/guardrail_hooks/generic_guardrail_api/generic_guardrail_api.py`
> and its types file, read in full. The docs page is a summary of these.

## Short answers

- **How do I support it?** Add one route to the data plane,
  `POST /beta/litellm_basic_guardrail_api`. It translates LiteLLM's request
  into the calls `/guardrails/input` and `/guardrails/output` already make, and
  translates Shield's verdict back into LiteLLM's three actions.
- **Is it a lot of changes?** No. One new file of about 250 lines, two
  one-line additions to the middleware path sets, tests, a docs page and an
  example config. No new dependency, no data model, no change to any existing
  endpoint, no admin image change.
- **Is it a new layer on top of the current guardrails API?** Yes, a thin
  adapter. It runs in the same process and calls the existing handlers as
  functions, so tenant policy, monitor mode, metrics, audit and auto-revoke
  behave exactly as they do for a direct call. It does not copy or fork the
  pipeline.

## 1. Problem & outcome

Today a LiteLLM user gets Shield through `votal_guardrail.py`, a Python plugin
that must be copied into their LiteLLM image and referenced by module path.
That rules out hosted LiteLLM, the LiteLLM UI's "add guardrail" form, and any
team that will not ship custom code in their proxy.

LiteLLM's Generic Guardrail API removes that step: LiteLLM itself calls
`{api_base}/beta/litellm_basic_guardrail_api` on any guardrail provider that
implements the contract.

**Outcome.** A LiteLLM operator adds this and nothing else:

```yaml
litellm_settings:
  guardrails:
    - guardrail_name: votal-shield
      litellm_params:
        guardrail: generic_guardrail_api
        mode: [pre_call, post_call]
        api_base: https://api.guardrails.votal.ai
        api_key: os.environ/VOTAL_API_KEY
        default_on: true
```

Success is observable three ways:

1. A prompt the tenant's input policy blocks returns a LiteLLM guardrail error
   carrying Shield's reason; the model is never called.
2. A model response containing data the tenant's output policy redacts reaches
   the client redacted.
3. Both decisions appear in the tenant's portal telemetry, attributed to the
   LiteLLM user and call id.

**Non-goals (v1).**

- Images (`images`). Ignored and passed through.
- Tool definitions (`tools`). Not scanned. A later task can route them to the
  MCP poisoning scan.
- Per-request tenant selection. One guardrail entry in LiteLLM maps to one
  Shield tenant key. Several tenants means several guardrail entries.
- `stream_holdback_chars` and LiteLLM's `incremental_diff` streaming rewrite.
- Replacing `votal_guardrail.py`. It stays, unchanged (see §5, "Which to use").

## 2. Plane & latency contract

- **Plane: data only.** Mounted in `core/app.py`. `admin_app.py` does not
  import it.
- **This endpoint is itself a guard path.** It sits inline in the customer's
  LLM call exactly as `/guardrails/input` does.
  - Budget: the adapter adds **under 2 ms p95** over the equivalent direct
    `/guardrails/*` call. It does JSON reshaping only: no Redis read, no model
    call and no network call of its own.
  - It runs **one pipeline pass per screened text**, concurrently. In the
    normal chat case that is one pass per LiteLLM call (see §4.3), the same
    cost as a direct call.
- **Existing guard paths are not touched.** `/guardrails/input`,
  `/guardrails/output`, `cap/mint` and `tools/call` keep their code and
  latency. The only shared edit is two set members in `ShieldMiddleware`
  (a set lookup that already runs on every request).

## 3. Data model

None. No Redis keys, no stored state. The adapter is stateless per call.

Telemetry: each screened text writes the handler's usual audit row. The adapter
adds one summary row per LiteLLM call (`endpoint` = the route, `metadata.kind`
= `litellm_guardrail`) with the LiteLLM call id, trace id, model, version and
the caller fields from `request_data`. It has its own kind so decision counts
are not doubled. The trace id is the `session_id` on both rows.

Tenant scoping: the tenant comes from the API key LiteLLM presents, resolved by
the existing `ShieldMiddleware` path. Nothing in the request body can select or
change the tenant, so a caller cannot reach another tenant's policy by editing
`request_data`, `request_headers` or `additional_provider_specific_params`.

## 4. API / interface

### 4.1 Endpoint

`POST /beta/litellm_basic_guardrail_api` (data plane). The path is fixed by
LiteLLM, which appends it to `api_base`.

**Auth.** LiteLLM sends its configured `api_key` as the `x-api-key` header.
That is already the first header `_extract_api_key` reads, so a Shield tenant
key works with no mapping. Deployments behind RunPod add the RunPod bearer with
LiteLLM's static `headers:` block; `x-api-key` still wins for tenant lookup.

**Request** (LiteLLM's `GenericGuardrailAPIRequest`; unknown fields ignored):

| Field | Use in v1 |
|---|---|
| `input_type` | `request` runs the input pipeline, `response` the output pipeline |
| `texts` | the content to screen |
| `structured_messages` | role information: picks which texts to screen, and supplies conversation history |
| `tool_calls` | task 2: tool authorization and data policy |
| `request_data` | attribution: `user_api_key_user_id`, `_end_user_id`, `_team_id`, `_org_id`, `_alias`, `_hash` |
| `request_headers` | agent and role, when the operator forwards them (§5) |
| `litellm_call_id`, `litellm_trace_id` | telemetry correlation; the trace id becomes Shield's `session_id` and `run_id` |
| `additional_provider_specific_params` | optional `agent_key`, `user_role` |
| `model`, `litellm_version` | recorded in telemetry |
| `images`, `tools` | ignored in v1 |

**Response** (always HTTP 200 for a decision):

```json
{"action": "NONE"}
{"action": "BLOCKED", "blocked_reason": "Blocked by Votal Shield: <guardrail>: <message>"}
{"action": "GUARDRAIL_INTERVENED", "texts": ["...same length as the request's texts..."]}
```

**Status codes.** 200 for every decision. 401 when no tenant key resolves and
`SHIELD_GUARD_REQUIRE_KEY` is enforcing. 400 for a body that is not the
contract (missing or invalid `input_type`). 500 on an internal failure. LiteLLM
treats any non-200 according to its own `fail_on_error` and
`unreachable_fallback` settings (default: block the request).

### 4.2 Verdict mapping

| Shield root action | LiteLLM action |
|---|---|
| `pass`, `log`, `warn` | `NONE` |
| `block` | `BLOCKED`, with the failed guardrails' names and messages as `blocked_reason` |
| `redact`, and a guardrail returned modified text | `GUARDRAIL_INTERVENED`, with the full `texts` list and only the redacted entries changed |
| `redact`, but no modified text was produced | `BLOCKED` (see §5) |

Monitor mode needs no handling here: `apply_policy_mode` already turns a
tenant in monitor mode into a non-blocking result before the adapter sees it.

Modified text comes from `core.text_utils.modified_text`, the one place the
redaction key is read, the same helper the gateway and chat routes use.

### 4.3 Which texts are screened

LiteLLM sends **every** in-scope message of the conversation in `texts`, on
every turn: earlier user turns, assistant turns, tool results, and the system
prompt unless the operator excludes it. Screening all of them would re-run the
model guardrails over the whole history each turn and would judge the
operator's own system prompt as if a user had typed it.

- **`input_type: request`.** Screen the texts of the **latest user message**
  only (normally one text). Earlier user and assistant messages go to the
  pipeline as `conversation_history`, which is what `/guardrails/input` is
  already shaped for. The latest user message is found by walking
  `structured_messages` with the same flattening LiteLLM uses (a string
  content is one text; a list content is one text per non-empty text part).
  - If `structured_messages` is absent or does not line up with `texts`
    (completions, rerank, audio and other non-chat endpoints), screen the last
    `last_k` texts (default 3, capped at 8). `last_k` is set by
    `SHIELD_LITELLM_LAST_K` only. It is not read from the request, because
    LiteLLM merges per-request client parameters into
    `additional_provider_specific_params` and a caller could use it to narrow
    what is screened.
- **`input_type: response`.** Screen every text (one per choice, normally
  one). During streaming LiteLLM sends the text accumulated so far; each call
  is screened on its own.
- A request with nothing to screen answers `NONE` without running a pipeline.

Each screened text is one in-process call to the existing handler function
(`classify` or `classify_output`), run concurrently, so each gets the tenant
config, policy mode, metrics, audit row and auto-revoke it would get over HTTP.
The worst action across the screened texts decides the response.

### 4.4 Tool calls (task 2)

For `input_type: response` with `tool_calls`, each call goes through the
existing tool path of `/guardrails/output` (`context.tool_name`, `tool_input`,
`stage: "input"`): role-based tool authorization, the tool's data policy, then
the output guardrails on the arguments. This is what `votal_guardrail.py` does
today. A denied tool call answers `BLOCKED`.

For `input_type: request`, texts from `tool` role messages (tool results going
into the model) are screened through the same path with `stage: "output"`, so
indirect injection and data policies apply to them.

## 5. Security & backward compatibility

- **Opt-in by construction.** A new route. Nothing changes for anyone who does
  not point a LiteLLM proxy at it. No existing default changes.
- **Requires a tenant key** like the other guard paths: the route is added to
  `_GUARDED_EXACT` and `_REQUIRE_TENANT_KEY`. Device keys (`vdk_`) are refused
  by the existing device-key path limit.
- **Identity is asserted by the proxy, and treated that way.** Agent and role
  arrive inside the JSON body (forwarded headers or provider params), not as
  real headers. The adapter hands them to `resolve_identity` as body values, so
  the existing rules apply unchanged: under `strict` and `strict_proxy`
  identity modes a self-asserted role is accepted only when the proxy also
  proves the hop (LiteLLM sends `X-Shield-Proxy-Token` through its static
  `headers:` block). The adapter adds no new trust path.
- **LiteLLM hides most inbound headers.** Only an allowlist is forwarded with
  values; the rest arrive as `"[present]"`. The adapter ignores that
  placeholder. To forward `x-agent-key` or `x-user-role`, the operator lists
  them under LiteLLM's `extra_headers`.
- **A redaction that cannot be applied blocks.** If policy says redact and no
  guardrail produced the redacted text, passing the original through would
  leak what the policy meant to remove. Escape hatch:
  `SHIELD_LITELLM_UNREDACTABLE=pass` returns `NONE` instead.
- **Block reasons** contain guardrail names and messages, as the plugin's do
  today. They are shown to the LiteLLM caller.
- **What a malicious caller can do.** With a valid tenant key: only what
  `/guardrails/input` already allows. Without one: nothing (401).

**Which to use**

| | Generic Guardrail API (this spec) | `votal_guardrail.py` plugin |
|---|---|---|
| Setup | config only | plugin file in the LiteLLM image |
| Hosted LiteLLM / UI | yes | no |
| Tenant | one key per guardrail entry | per request, from metadata |
| Verified agent token, delegated user token | not in v1 | yes |
| Redaction of prompts and responses | yes | no (block only) |

## 6. Packaging & deploy

- New module `api/routes_litellm_guardrail.py`, mounted in `core/app.py`. The
  data plane image copies `api/` whole, so no Dockerfile change.
- **Not imported by `admin_app.py`,** so `Dockerfile.admin` is untouched.
- **No new pip dependency.** The adapter does not import `litellm`; it accepts
  plain JSON. Tests build request bodies from the documented field list.
- Env flags: `SHIELD_LITELLM_UNREDACTABLE` (`block` default, `pass`),
  `SHIELD_LITELLM_LAST_K` (default 3).
- Rollout: rebuild and deploy the data plane image only. Applies to both
  topologies (cloud model and on-prem RunPod).
- New files for customers: `config/litellm_generic_guardrail.example.yaml` and
  `docs/litellm-generic-guardrail.md`.

## 7. Failure modes & edge cases

| Case | Behaviour |
|---|---|
| `texts` empty or missing, no `tool_calls` | `NONE`, no pipeline run |
| Empty or whitespace-only text among others | skipped, not sent to the handler (which rejects empty input) |
| Very large text | same limits and behaviour as `/guardrails/input`; no new limit |
| Many texts without role information | last `last_k` screened, capped at 8 |
| `structured_messages` does not line up with `texts` | fallback above; never an error |
| Redaction returned for one of several texts | that entry replaced, others returned unchanged, list length preserved |
| Unknown `input_type` | 400 |
| Model slow or pipeline raises | 500; LiteLLM applies `fail_on_error` (default: block). Shield does not decide fail-open here: the operator's LiteLLM setting does, and the docs page says so |
| Redis down | as `/guardrails/input`: tenant lookup behaviour is unchanged |
| Streaming | LiteLLM calls every 5th chunk by default with the text so far; each call is a full output pass and an audit row. The docs recommend `streaming_end_of_stream_only: true` or a higher `streaming_sampling_rate`. Redaction of streamed text is not delivered in LiteLLM's default `block_only` mode: only a block stops a stream |
| Tenant in monitor mode | `NONE`, decision still recorded |
| LiteLLM adds request fields later (beta API) | ignored; the contract test pins the fields we read |

**Fail-open or fail-closed:** fail-closed. An internal error is a non-200,
never a silent `NONE`.

## 8. Test plan (Definition of Done)

`tests/test_litellm_generic_guardrail.py`, using the existing app test client
and guardrail stubs, no network and no `litellm` install:

- Request pass, block, and redact, each mapped to the right action; a blocked
  reason names the guardrail.
- Response pass, block, and redact, with the `texts` length preserved.
- Only the latest user message is screened; system and earlier turns are not,
  and earlier turns arrive as conversation history.
- List-content messages (several text parts) map to the right `texts` indexes.
- Fallback when `structured_messages` is missing or misaligned.
- Empty `texts`, whitespace texts, unknown `input_type`, missing key (401 when
  enforcing), a device key (403).
- Redact with no modified text blocks; `SHIELD_LITELLM_UNREDACTABLE=pass`
  returns `NONE`.
- Monitor mode returns `NONE` and still records the decision.
- Tenant comes from the key only: tenant-looking values in the body are
  ignored.
- `request_headers` values of `"[present]"` are ignored; forwarded role and
  agent reach `resolve_identity` as body values.
- Telemetry row carries the LiteLLM call id, trace id and user id.
- A pipeline exception is a 500, not `NONE`.
- Contract test: a body with every field of LiteLLM's request model, plus an
  unknown field, is accepted.
- Task 2: allowed and denied tool calls; tool-result text screened.
- `/guardrails/input` and `/guardrails/output` tests unchanged and green.
- Full suite green in a clean venv; the CI `pytest` gate passes.

Manual, task 3: a real LiteLLM proxy pointed at a local Shield, one blocked
prompt, one redacted response, one streamed response.

## Tasks

All on branch `litellm_integration`, one PR.

1. **Adapter for text.** The route, text selection, verdict mapping and
   redaction for request and response, middleware path sets, attribution, the
   tests above.
2. **Tool calls.** `tool_calls` in responses and tool-result messages in
   requests through the existing tool path, with tests.
3. **Docs and example.** Customer page, example config, streaming guidance,
   and the end-to-end check against a real LiteLLM proxy (needs `litellm`
   installed in a scratch venv, which I will ask about first).
