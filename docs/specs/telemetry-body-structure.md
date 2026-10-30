# Spec: keep request and response bodies structured in telemetry

Status: **approved 2026-10-29; implemented** on branch `fix/telemetry-body-structure`.

## 1. Problem & outcome

`core/telemetry.py` logs each request's JSON body as `request.body` and each
response's as `response.body`, through `_truncate(obj, 2000)`. When the
JSON-encoded body is longer than 2,000 characters, `_truncate` returns a
**string** (`first 2000 chars + "...[truncated]"`) instead of the object.

Three consequences, seen by a customer in Kibana on 2026-10-29:

1. **Fields disappear on long requests.** Any request with a long prompt loses
   every `request.body.*` field, including `request.body.request_headers.*`
   and `request.body.request_data.*` that LiteLLM-style gateways send
   (`x-tf-api-key-id`, `x-tf-organization-id`, `user_api_key_org_id`). An
   operator can't tell "the gateway didn't send the org id" from "Shield's
   logging dropped it".
2. **Whole events can be lost.** The same field is an object on short
   requests and a string on long ones. Elasticsearch maps `request.body` from
   whichever arrives first; once it is an object, a string value is a mapping
   conflict and the document is rejected, so long requests may never reach the
   index at all.
3. **Credentials can be logged.** Short bodies are logged verbatim. Bodies and
   responses that carry credentials (a key in a create-tenant request, a new
   key in an API-key response, `authorization` inside LiteLLM's forwarded
   `request_headers`) go to the SIEM as written. Keeping more of each body
   (this change) would widen that, so redaction is part of the fix.

**Outcome:** `request.body` and `response.body` are always a JSON object (or
absent), never a string. Small metadata survives any body size: a 50 KB
LiteLLM request still produces `request.body.request_headers.x-tf-api-key-id`.
Only long text is shortened. Credential-named fields are `[REDACTED]` at any
depth. A separate boolean says when anything was shortened.

**Non-goals:** changing what is logged for other fields
(`votal.input_text`, `votal.conversation.history`, `votal.prompt_chain` keep
their own limits); the ASIM-only output (it does not include bodies, checked
in `core/asim.py`); log shipping, retention or index templates.

## 2. Plane & latency contract

- **Data plane** (`core/telemetry.py`, used by `core/telemetry_middleware.py`
  in `core/app.py`). The admin plane does not run `TelemetryMiddleware`.
- **Off the guard decision path.** Events are built inside
  `asyncio.create_task(_record_request_async(...))` and the response
  equivalent, after the body is already parsed for other reasons. The new
  function runs on the event loop, so its cost still matters: budget **under
  0.5 ms p99 for a 100 KB body**. No I/O.
- **Measured** (`_bounded_body`, 2,000 runs; 300 at 1 MB):

  | Body | Median | p99 | Old `_truncate` (median / p99) |
  |---|---|---|---|
  | 4 KB LiteLLM | 13 µs | 15 µs | |
  | 100 KB LiteLLM | 144 µs | 178 µs | 148 µs / 850 µs |
  | 100 KB chat, 50 messages | 199 µs | 492 µs | |
  | 1 MB LiteLLM | 1.4 ms | 2.1 ms | 1.8 ms / 4.1 ms |

  The cost is dominated by encoding the whole body once to measure it, which
  the old code also did, so it is no slower than before.

## 3. Data model

Event fields (dotted names, expanded to objects by Elasticsearch):

| Field | Before | After |
|---|---|---|
| `request.body` | object if ≤ 2,000 chars encoded, else string | same JSON type as the body at any size: an object for every JSON-object request (absent when the body wasn't JSON) |
| `response.body` | same | same as `request.body` |
| `request.body_truncated` | none | `true` when anything in the body was shortened or dropped; absent otherwise |
| `response.body_truncated` | none | same |

No Redis keys, no tenant data.

## 4. Interface

Replace `_truncate(body)` for the two body fields with
`_bounded_body(body) -> (dict | None, truncated: bool)`:

1. **Redact first**, at any depth, any key whose lowercased name is one of
   `authorization`, `proxy-authorization`, `cookie`, `set-cookie`,
   `x-api-key`, `x-admin-key`, `x-tenant-key`, `x-agent-token`,
   `x-shield-proxy-token`, `api_key`, `api_keys`, `password`, `secret`,
   `client_secret`, `private_key`, `access_token`, `refresh_token`. The value
   becomes the string `"[REDACTED]"` (a list becomes `["[REDACTED]"]`, so a
   field's type does not change).
2. **If the encoded result is at most 4,000 characters, keep it whole.**
3. **Otherwise shorten in place, keeping every key and every type:**
   - strings longer than 500 characters: first 500 + `...[truncated]`;
   - lists longer than 10 items: keep the **last** 10 (the newest messages
     are the ones guardrails acted on);
   - nesting deeper than 6 levels: the deeper value becomes `null`;
   - if still over 4,000 characters, repeat with 200 characters and 3 items,
     then 50 and 1;
   - if still over, keep only scalar top-level fields and the top-level
     objects named `request_headers`, `request_data`, `metadata`, each
     bounded the same way, and drop the rest.
4. Non-dict bodies (a JSON array or scalar) keep today's behaviour of being
   logged as `{}` by the middleware (it already does that).

Raising the whole-body limit from 2,000 to 4,000 is deliberate: LiteLLM's
`request_headers` plus `request_data` alone are about 1.5 KB.

**Escape hatch:** `SHIELD_TELEMETRY_BODY_MODE=legacy` restores the old
behaviour exactly (whole body or a 2,000-character string, no redaction),
read per event. For a pipeline that parses the string form.

## 5. Security & backward compatibility

- **Less sensitive data than today:** credentials are redacted in bodies of
  any size, where today short bodies log them verbatim. This is the one
  behaviour change a consumer could notice on short bodies.
- **Schema change for long bodies:** a consumer that matched
  `request.body : "*...[truncated]"` as a string must switch to
  `request.body_truncated : true`. Migration note in
  `docs/sigma-policies.md` (telemetry section) and the escape hatch above.
- **Elasticsearch:** indexes where `request.body` was first mapped as a
  string (text) will now get objects and reject them. The migration note says
  to roll over to a new index (or delete the `request.body` mapping) when
  upgrading. Indexes mapped as an object, the common case, start accepting
  the long-body events they used to reject.
- Tenant isolation unchanged: events carry the same `votal.tenant_id`.

## 6. Packaging & deploy

No new module (the function lives in `core/telemetry.py`), no dependency, no
Dockerfile change. New env var documented with the other telemetry settings.

## 7. Failure modes & edge cases

| Case | Result |
|---|---|
| Body with a 1 MB prompt in `texts` | `texts` kept as a list of shortened strings; headers and ids whole; `body_truncated: true` |
| Chat body with 300 messages | last 10 (then 3, then 1) messages, each `content` shortened |
| Key named `API_Key` or `Authorization` in any nested object | `[REDACTED]` |
| Value is `"[present]"` (LiteLLM placeholder) | kept as is; it is not a credential |
| Body not JSON / multipart | unchanged: no body logged |
| Exception inside `_bounded_body` | the event is still recorded, with the body omitted and `body_truncated: true` (telemetry must never fail a request, and must never fall back to logging the raw body) |
| `SHIELD_TELEMETRY_BODY_MODE=legacy` | today's output byte for byte |

## 8. Test plan (Definition of Done)

New `tests/test_telemetry_body.py`:
1. A small body is returned unchanged (same object, no `body_truncated`).
2. A LiteLLM body with a 50 KB text keeps
   `request_headers.x-tf-api-key-id`, `request_headers.x-tf-organization-id`
   and `request_data.user_api_key_org_id` whole, `texts` is still a list of
   strings, and the encoded body is at most 4,000 characters.
3. Type stability: for every key in the input, the output value has the same
   JSON type (object, list, string, number, bool, null-only-past-depth),
   over a set of generated bodies of growing size.
4. A 300-message chat body keeps the last messages, in order.
5. Redaction at depth, case-insensitive, list-valued keys stay lists, and
   applies to small bodies too; `[present]` untouched.
6. `build_request_event` / `build_response_event` set `body_truncated` only
   when something was shortened, and never emit a string body.
7. Legacy mode reproduces the old output exactly.
8. A body that makes `_bounded_body` raise produces an event with no body.
9. End to end through `TestClient`: a long LiteLLM call's recorded request
   event carries `request.body.request_headers.x-tf-api-key-id`.
10. Check tests 2, 3 and 9 fail against the current `_truncate`.

Latency: p50/p99 for 4 KB, 100 KB and 1 MB bodies, recorded in section 2.
Full suite green in a clean venv.

Manual: send a long LiteLLM-shaped request to a Shield with telemetry going
to Elasticsearch; in Kibana the event has
`request.body.request_headers.x-tf-api-key-id` and
`request.body_truncated: true`.

## 9. Tasks

1. **One PR:** `_bounded_body`, redaction, the two event builders, the
   `body_truncated` fields, the escape hatch, the tests above, and the
   migration note in `docs/sigma-policies.md`.
