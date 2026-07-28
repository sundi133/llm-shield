---
title: "Spec: Guard-path scale (fail-closed, non-blocking, cached)"
layout: default
nav_order: 37
permalink: /spec-guard-path-scale/
description: "Three defects that surface only under enterprise load: the payload judge fails open on error, a synchronous Redis call blocks the async guard path, and tenant policies are refetched per request. Fail-open becomes opt-in, policy loading moves off the event loop and behind a TTL cache."
---

# Spec: Guard-path scale

Status: DRAFT, awaiting approval. No code written.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. Problem & outcome

Three defects in `guardrails/agentic/tool/payload_risk.py` do not show up at demo
volume and get worse together under load.

**1. The payload judge fails open on any exception.** Every tool call carrying a
policy is judged by an LLM. `payload_risk.py:106` and `:166`:

```python
except Exception as e:
    logger.error(f"LLM payload risk evaluation error for {tool_name}: {e}")
    return None  # Fail open
```

Timeout, rate limit, OOM, connection reset, malformed JSON: all return "no
violation" and the tool call proceeds. The LLM backend is the first thing to
saturate under load, so the control does not degrade gracefully, it degrades
permissively, precisely when traffic is heaviest.

Worse, the caller is told the opposite of the truth.
`tool_call_validation.py:47` returns:

```python
GuardrailResult(passed=True, action="pass",
                message=f"Tool '{tool_name}' parameters valid")
```

"Parameters valid" is a positive claim about parameters that were never
evaluated. The audit record does not merely omit the degradation, it asserts a
check that did not happen. An auditor reading that log cannot distinguish a
clean run from a total outage of policy enforcement.

**2. A synchronous Redis call blocks the async guard path.**
`evaluate_payload_policy_llm` is `async`, and at line 53 it calls
`_format_data_policies` -> `_load_data_policies`, which does a **synchronous**
`r.get()`. When `UPSTASH_REDIS_REST_URL` is configured, which
`storage/tenant_store.py:35` documents as preferred for serverless and RunPod,
that `.get()` is a synchronous HTTPS round trip executed on the event loop.

Concurrent requests serialise behind it. Adding workers or GPU does not help,
because the bottleneck is the loop being blocked, not compute. This is the
ceiling identified in the deferred performance work.

**3. Tenant policies are refetched on every call.** Policies change on the order
of weekly. They are read from Redis per guarded request.

### Outcome

- A failed judge results in a decision the operator chose, and the audit record
  always states which of the two happened.
- No blocking I/O on the guard path.
- Policy reads collapse from one per request to one per tenant per TTL.

Observable success: under a load test where the LLM backend is forced to time
out, tool calls are refused (in the default posture) and every resulting
`GuardrailResult` carries `degraded: true`. Guard-path p99 with a warm policy
cache shows no Redis round trip in the request span.

### Non-goals

- Caching LLM **verdicts**. Keyed on normalised arguments it is worth doing, but
  correctness risk is much higher than a policy cache and it deserves its own
  spec.
- Latency of the LLM judge itself, and of `/guardrails/input|output`. Real
  problems (0.7s to 16.6s measured), separate work.
- Reconciling the registry and data-policy layers in the admin console.
- Any change to which tools a role may call.

---

## 2. Plane & latency contract

**Plane:** data plane (`core/app.py`). No admin-plane change, no new route.

**Touches the guard path:** yes, deliberately. This is guard-path work, so the
budget is the justification.

| | now | after |
|---|---|---|
| Redis round trips per guarded call | 1, blocking, on the event loop | 0 on a cache hit; on a miss, off-loop |
| Added CPU per call | n/a | one dict lookup and a timestamp compare |
| Judge latency | unchanged | unchanged |

The change is strictly subtractive on the hot path: it removes blocking I/O and
adds an in-process lookup. No new network call is introduced. The fail-closed
branch runs only on the error path, which today does no work at all.

---

## 3. Data model

No new Redis keys. Existing key, unchanged shape:

```
data_policies:{tenant_id}   ->  JSON  {tool_name: {sanitization_rules, role_policies, compliance_framework}}
```

New in-process cache, following the precedent already set by
`core/identity_resolution.py:120`:

```python
_POLICY_CACHE: dict[str, tuple[list[dict], float]] = {}   # tenant_id -> (policies, fetched_at)
_POLICY_CACHE_TTL_S = 30                                   # SHIELD_POLICY_CACHE_TTL_S
```

**Tenant scoping.** The cache is keyed by `tenant_id`, which is resolved exactly
as today and never taken from the cache itself. A miss for tenant A cannot
return tenant B's entry: the key is the whole identity of the row. `tenant_id`
empty returns `[]` before any lookup, as it does now.

Bounded growth: entries are per tenant, small, and expire. A tenant count high
enough to matter would need eviction, noted in §7.

---

## 4. API / interface

No endpoint added, removed, or changed. No new auth header.

One response-shape addition. `GuardrailResult.details` gains two fields on the
degraded path only:

```json
{
  "degraded": true,
  "degraded_reason": "payload_judge_unavailable"
}
```

Absent on every normal decision, so existing consumers see no change.

Message text changes on the degraded path only, because the current text is
false:

| | message |
|---|---|
| now (any failure) | `Tool 'x' parameters valid` |
| after, fail-closed | `Tool 'x' refused: payload policy could not be evaluated` |
| after, fail-open | `Tool 'x' allowed WITHOUT payload policy evaluation (judge unavailable)` |

---

## 5. Security & backward compatibility

This changes a default, so it needs an escape hatch and a migration note.

```
SHIELD_PAYLOAD_JUDGE_ON_ERROR = closed | open      # default: closed
SHIELD_POLICY_CACHE_TTL_S     = <int seconds>      # default: 30, 0 disables
```

**Why `closed` is the right default.** The current default is a security control
that switches itself off under load and reports success. No operator would
choose that knowingly. Existing deployments that need the old behaviour set
`open` and get it exactly, including the allow, but with `degraded: true`
recorded rather than a false "valid".

**Migration note.** A deployment whose LLM backend is unhealthy will begin
refusing tool calls that previously passed. That is the point, but it must be a
decision. Recommended rollout in §8: ship with the flag set to `open` first,
watch `degraded` in the audit log, then flip to `closed` once the rate is near
zero.

**Authorization.** Unchanged. No new caller, no new privilege. A malicious caller
cannot reach the degraded path (it needs a backend failure, which they do not
control) and cannot poison the cache (keyed on server-resolved `tenant_id`, and
nothing caller-supplied is stored).

**Cache staleness is a real exposure.** A policy tightened in the console takes
up to `SHIELD_POLICY_CACHE_TTL_S` to take effect. 30s is proposed as the same
value already accepted for role binding. Set `0` to disable if an operator wants
immediate propagation, at the cost of the round trip.

---

## 6. Packaging & deploy

- **No new module imported by `admin_app.py`.** `Dockerfile.admin` unchanged.
  The transitive-import guard covers this either way.
- **No new pip dependency.** `redis` is already in `requirements.txt:13`, and
  `redis.asyncio` ships with it (verified: redis 8.0.1).
- **`upstash-redis` has no async client.** This is the one real constraint. On
  the Upstash path the sync call must be moved off the loop with
  `asyncio.to_thread` rather than swapped for an async client. Both paths are
  covered in §7.
- **Rebuild:** data-plane image only.
- **Rollout:** deploy with `SHIELD_PAYLOAD_JUDGE_ON_ERROR=open`, observe, then
  flip. The cache needs no rollout step.

---

## 7. Failure modes & edge cases

| Case | Behaviour |
|---|---|
| LLM times out / errors | `closed`: refuse, `degraded: true`. `open`: allow, `degraded: true`. Never a silent pass. |
| LLM returns malformed JSON | Same as above. Today this is swallowed by the same bare `except`. |
| Redis down, cache cold | Policy load fails. Treated as a judge failure and follows the flag, rather than silently evaluating against an empty policy set (which is today's behaviour and is a quiet downgrade). |
| Redis down, cache warm | Served from cache until TTL, then as above. Improves availability. |
| No policies configured for a tenant | Unchanged: allow. Not a degradation, an empty policy set is a valid configuration. Must not be conflated with a failed load, and a test pins that distinction. |
| `tenant_id` empty | Returns `[]` before any lookup, as today. |
| Upstash (sync client) | `asyncio.to_thread`, so the loop is not blocked. |
| Standard Redis TCP | `redis.asyncio` client. |
| Concurrent misses, same tenant | Both fetch and both write. Benign: same value, last write wins. A lock is not worth the contention. |
| Very many tenants | Unbounded dict. Add a simple size cap with oldest-first eviction; noted so it is a decision, not an oversight. |
| Cache disabled (`0`) | Fetch every call, still off-loop. Preserves today's freshness without today's blocking. |

**Fail-open vs fail-closed, stated explicitly.** Default **fail-closed** for the
payload judge. Fail-open remains available and supported, but must be chosen,
and is always recorded.

---

## 8. Test plan (Definition of Done)

Unit:

1. Judge raises -> `closed` refuses, `passed is False`, `degraded is True`.
2. Judge raises -> `open` allows, `passed is True`, `degraded is True`.
3. Judge raises -> message never says "parameters valid". Regression pin on the
   false assertion.
4. Judge returns a violation -> refused, `degraded` absent. Flag makes no
   difference on a real verdict.
5. Judge returns no violation -> allowed, `degraded` absent.
6. Empty policy set -> allowed, `degraded` absent. Distinguished from a failed
   load.
7. Redis raises on load -> follows the flag, `degraded is True`.
8. Cache: two calls, same tenant, one backend fetch.
9. Cache: TTL elapsed -> refetched.
10. Cache: tenant A never returns tenant B's policies.
11. Cache TTL `0` -> fetch every call.
12. Invalid flag value -> falls back to `closed`, mirroring how
    `_env_mode()` treats an unknown mode.

Structural / regression:

13. No synchronous Redis call reachable from the guard path. An AST or source
    assertion in the spirit of `tests/test_identity_seam_is_used.py`, because a
    behavioural test cannot catch a *new* blocking call added tomorrow.

Load (manual, recorded in the PR, not in CI):

14. Force the backend to time out under concurrency; confirm refusals rather
    than passes, and that `degraded` appears on every one.
15. Guard-path p99 with a warm cache shows no Redis span.

Full suite green in a **clean venv**; CI `pytest` gate passes.

---

## 9. Scope boundary

In: `guardrails/agentic/tool/payload_risk.py`,
`guardrails/agentic/tool/tool_call_validation.py`, the policy loader, tests.

Out: the LLM judge's own latency, `/guardrails/input|output`, verdict caching,
registry and data-policy reconciliation in the console, rate limiting.

Two PRs, in order, because they fail differently and should be revertible
independently:

1. Fail-closed with the flag and the `degraded` signal (behaviour change, needs
   the rollout).
2. Non-blocking policy load with the TTL cache (performance, no behaviour
   change).
