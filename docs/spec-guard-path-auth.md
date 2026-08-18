# Spec: require a tenant key on the guard path

Status: **DRAFT - approved to implement.**

## 1. Problem & outcome

The content guard endpoints accept unauthenticated traffic and serve a verdict
under a default policy. Reproduced against production:

```
POST /guardrails/input   no key      -> 200  {"safe":true,"action":"pass",...}
POST /guardrails/input   bogus key   -> 200  (identical)
GET  /v1/tenant/me       no key      -> 401
```

810 ms of adversarial detection ran for an anonymous caller. Tenant routes
enforce authentication in their handlers; the guard path never does.

Two consequences, and the second is worse than the first:

- **Unmetered anonymous compute.** Anyone who learns the hostname gets GPU
  inference.
- **Silent misconfiguration.** An integrator who ships a broken or absent key
  sees `200 {"safe": true}` and concludes they are protected. A guardrail that
  fails open while reporting success is worse than no guardrail, because it is
  trusted. This is the finding a partner security review will lead with.

`AuthMiddleware` is misnamed: it *enriches* (resolves tenant, agent, role, rate
limits onto `request.state`) and never rejects. `/guardrails/input` is already
in its `_GUARDED_EXACT` set, so it runs, resolves nothing, sets
`identity_method = "anonymous"`, and calls through.

**Outcome.** A guard call with no key or an unrecognised key is refused with
401 in one documented shape, and the operator can see who that would break
before it breaks them.

### Non-goals
- No change to what any guardrail decides. Authentication only.
- No change to `/v1/tenant/*`, which already enforces in `_require_tenant`.
- Not a rate-limiting or quota change.
- Does not address the `safe` vs `allowed` field inconsistency (separate).

## 2. Plane & latency contract

**Plane:** both. The middleware is shared, and the guard path lives on the data
plane, so this is the one control in recent memory that *is* on the hot path.

**Latency budget:** the rejection happens on data already resolved. Tenant
lookup runs today for every guarded request - this adds a null check and, in the
refusal case, returns before the guardrail pipeline. **The enforce path is
strictly cheaper than the status quo**: a refused request stops before 810 ms of
inference instead of after it. No new store read, no new import.

## 3. Data model

**None.** No new Redis keys, no writes, no TTLs. The decision is made from
`request.state.tenant_id`, which the middleware already populates.

Warn mode records to the existing telemetry/log path rather than a new store  -
this must not add a write to the guard path.

## 4. API / interface

### Environment flag

```
SHIELD_GUARD_REQUIRE_KEY = off | warn | enforce      (default: off)
```

Same ladder as `SHIELD_REGISTRY_WRITE_SCOPE`, deliberately: operators already
know the shape, and the rung that matters is `warn`.

| Mode | Behaviour |
|---|---|
| `off` | Today's behaviour exactly. Anonymous guard calls succeed. |
| `warn` | Anonymous calls succeed **and are recorded** with path and client, so an operator can see who would break. |
| `enforce` | Anonymous or unresolvable key returns 401. |

### Refusal shape

Matches the shape this middleware already returns for `agent_blocked` and
`agent_disabled`, so a client handles one shape rather than a new one:

```json
{
  "error": "missing_tenant_key",
  "detail": "This endpoint requires a tenant API key in X-API-Key."
}
```

`invalid_tenant_key` when a key was presented but resolved to no tenant. The
two are distinguished because "you sent nothing" and "you sent something wrong"
lead to different fixes, and an integrator debugging a 401 needs to know which.

### Paths enforced

Explicit allow-list of *enforced* paths, not a blanket rule over the guarded
prefixes. Two exemptions are load-bearing:

| Path | Enforced | Why |
|---|---|---|
| `/guardrails/input`, `/output`, `/file` | **yes** | the finding |
| `/classify`, `/classify_output` | **yes** | same handlers, older aliases |
| `/v1/shield/tool/check`, `/tool/output` | **yes** | the finding |
| `/v1/chat/completions` | **yes** | OpenAI-compatible shim |
| `/v1/shield/cap/verify` | **no** | **unauthenticated by design** - tool servers verify caps on behalf of agents and the cap *is* the bearer credential. Requiring a tenant key breaks every tool-side verification. |
| `/v1/shield/ssf/events` | **no** | has its own auth (`SHIELD_SSF_RECEIVER_TOKEN`, closed by default, constant-time compare) |
| `/v1/shield/cap/mint` | **no** | already requires a verified agent token (`get_identity_from_request` raises 401) |
| `/v1/tenant/*` | **no** | already enforced in `_require_tenant` |
| `/v1/admin/*` | **no** | admin key, separate surface |
| `/health`, `/ping`, `/docs` | **no** | already skipped |

## 5. Security & backward compatibility

**Default `off`, so merging changes nothing.** This is a behaviour-changing
control on the hot path, and the repo invariant is secure-by-default but
non-breaking.

**The migration is the point of `warn`.** Anonymous guard traffic may exist
today - demos, the LangChain examples, a POC, an internal script. Going
straight to `enforce` would break them silently and blame the wrong thing. Run
`warn`, read what it records, fix those callers, then `enforce`.

**What an attacker can no longer do under `enforce`:** obtain free GPU
inference, or probe guardrail behaviour to learn a tenant's policy shape,
without a credential.

**What this does not fix:** a valid tenant key remains a tenant *admin*
credential until `SHIELD_REGISTRY_WRITE_SCOPE` is enforced. This spec closes
"no key at all"; it does not close "runtime key has admin power". They are
independent and both must land before a partner key is issued.

## 6. Packaging & deploy

- `core/middleware.py` only - already in the `Dockerfile.admin` COPY list.
- **No new module, no new dependency, no new import.**
- Rebuild: both images (shared middleware).
- Rollout: set `SHIELD_GUARD_REQUIRE_KEY=warn` on both planes, read the audit,
  then `enforce`.

## 7. Failure modes & edge cases

| Case | Behaviour |
|---|---|
| No key, `enforce` | 401 `missing_tenant_key`, before the pipeline |
| Bogus key, `enforce` | 401 `invalid_tenant_key` |
| Valid key | unchanged |
| **Redis down, key presented** | tenant resolution fails through no fault of the caller. **Fail open with a warning** - the store being down must not convert every guarded request into a 401. Stated explicitly because the opposite choice is defensible and this one is deliberate: a guardrail outage should degrade to *unauthenticated screening*, not to a total outage of the customer's application. |
| Redis down, no key | 401 under `enforce` - nothing to resolve either way |
| Unknown flag value | normalises to `off`, same convention as `registry_write_mode()` |
| Bearer instead of `X-API-Key` | accepted, because `_extract_api_key` already accepts it. Undocumented today; the spec change is to *document* it, not to remove it |

## 8. Test plan (Definition of Done)

`tests/test_guard_path_auth.py`

- `off`: no key -> 200 (today's behaviour preserved exactly)
- `warn`: no key -> 200, and the anonymous call is recorded
- `enforce`: no key -> 401 `missing_tenant_key`
- `enforce`: unresolvable key -> 401 `invalid_tenant_key`
- `enforce`: valid key -> 200, unchanged
- **exemptions under `enforce`**: `/cap/verify` still reachable with no tenant
  key; `/v1/shield/ssf/events` still governed by its own token; `/health` open
- Redis down + key presented -> fail open, warning logged
- unknown flag value -> treated as `off`
- refusal body matches the documented shape and carries no tenant identifiers

Regression guards:

- a source-level assertion that `/cap/verify` is in the exemption set, with the
  reason, so a later tightening does not silently break tool verification
- existing guard-path read-count spies still pass: no new store read

Full suite green in a clean venv; CI `pytest` passes.

## 9. Task breakdown

One PR. The flag, the check, the tests, and a line in the partner spec
description stating that the guard endpoints require a key.
