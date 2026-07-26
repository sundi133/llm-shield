# Spec: apply tenant custom policies on the guarded chat proxies

Status: implemented. Shared helper `core/tenant_pipeline.py`; both proxies wired;
regression + parity tests in `tests/test_tenant_policy_on_chat_proxies.py`.

**Scope grew by one endpoint during implementation.** `POST /v1/shield/chat/agent`
(`api/routes_agent_chat.py`) turned out to have the *identical* gap — it resolved
`tenant_config` for tool RBAC, then ran the input/output pipelines without it.
It is fixed here with the same helper rather than left as a known-identical hole
in a separate PR. Three guarded chat paths are now covered, not two.

## 0. Migration note (read before deploying)

**Behavior change on the guard path.** Tenants with configured
`input_guardrails` / `output_guardrails` now have those policies enforced on
`/v1/chat/completions` and `/v1/shield/chat/completions`. Requests that these
proxies previously let through will start being blocked — that is the fix, but
it is a live traffic change.

Before deploying:

1. Review which tenants have custom policies configured. Their proxy traffic is
   what changes.
2. For a policy that has never been enforced in production, set the tenant's
   `policy_mode` to `monitor` first. Guardrails still evaluate and findings are
   still recorded, but nothing is blocked — review the would-be blocks, then
   flip to `enforce`.
3. If a tenant's legitimate traffic breaks after rollout, set
   `SHIELD_DISABLE_TENANT_POLICY_ON_PROXY=1` to restore the previous
   defaults-only proxy behavior while you investigate. Prefer moving that tenant
   to `monitor` mode over leaving the flag on — the flag disables tenant policy
   enforcement on the proxies for **every** tenant, not just the affected one.

| Env flag | Default | Effect |
|---|---|---|
| `SHIELD_DISABLE_TENANT_POLICY_ON_PROXY` | _(unset — enforcing)_ | `1`/`true`/`yes`/`on` reverts both chat proxies to default guardrails only. Read live, so no restart is needed. |

## 1. Problem & outcome

A tenant's configured custom policies are enforced on `/guardrails/input` and
`/guardrails/output`, but **not** on the guarded chat proxies. Customers who
route traffic through the proxy get only the default/global guardrail set, so
policies they configured in the portal are silently unenforced.

Reproduced on live tenant `bank-co`, which has an input-stage "pricing
confidential data" policy:

| Call | Result | Correct? |
|---|---|---|
| `POST /guardrails/input` — "our margin is 62% and supplier cost is 400 AED" | blocked (`custom_policy_input`) | yes |
| `POST /v1/chat/completions` — same message | not blocked, model replies | **no** |

**Root cause (verified in code).** `custom_policy_input` / `custom_policy_output`
read their policy list out of the `_request_configs` contextvar
(`guardrails/base.py:56`). `_classify_tenant` populates that contextvar from
`tenant_config` before running the pipeline
(`api/routes_classify.py:651`, `api/routes_classify_output.py:654`). The proxies
call bare `run_input_pipeline` / `run_output_pipeline`, which do
`get_by_stage(...)` with **no contextvar set** — so the custom-policy guardrails
execute against an empty policy list and no-op.

Affected call sites:
- `api/routes_gateway.py:454` (input), `:334` (streaming output)
- `api/routes_openai_compat.py:180` (input), `:311` (output)

`request.state.tenant_config` **is** already populated on these paths —
`core/middleware.py:305-311` sets it for any API-keyed request regardless of
route. The proxies simply ignore it. The gateway proves the pattern is known: it
already sets `_request_configs` at `api/routes_gateway.py:93`, but only for
`tool_allowlist`.

**Outcome.** A tenant policy blocks identically whether the caller uses
`/guardrails/*`, `/v1/chat/completions`, or `/v1/shield/chat/completions`.
Observable success: the `bank-co` repro blocks on all three.

**Non-goals.** No new policy types, no policy-authoring/portal changes, no
change to how policies are stored or evaluated, no change to tool-call RBAC
(already tenant-aware), no per-endpoint policy targeting.

## 2. Plane & latency contract

**Plane:** data plane only (GPU/vLLM, `core/app.py`). `admin_app.py` mounts none
of these routers — no admin import, so **no `Dockerfile.admin` change**.

**Touches the guard path: YES.** This is squarely on the hot path
(`/guardrails/*` and the chat proxies), so the latency argument is required:

- The shared helper does dict-walking and one `contextvars.set/reset` per
  request — microseconds, no I/O. `tenant_config` is already resolved and cached
  by middleware (`_get_cached_tenant`); we add **zero** Redis reads.
- Real cost is the **union** semantics (§5): a tenant-configured guardrail that
  was not previously running on the proxy now runs. For a fast-tier guard
  (`custom_policy_input` is regex/keyword-driven) this is sub-millisecond; a
  tenant that configures a slow-tier LLM guard pays that tier's cost. That is
  the cost of actually enforcing what the customer configured — the current
  "fast" behavior is fast because it is wrong.
- `/guardrails/*` latency is **unchanged**: the refactor is a pure extraction,
  same operations in the same order.

## 3. Data model

**No new state. No new Redis keys. No TTLs. Nothing written.** This is a
read-only wiring fix over data that already exists.

Read: `request.state.tenant_config` — the same dict `/guardrails/input` reads,
shaped `{"input_guardrails": {<name>: {enabled, action, settings}}, "output_guardrails": {...}, "policy_mode": "enforce"|"monitor"}`.

**Tenant scoping / isolation.** `tenant_id` and `tenant_config` are resolved
from the request's own API key in middleware and read per-request from
`request.state`. The helper never takes a tenant id from the body or a header.
Config is pushed through a `contextvars.ContextVar`, which is per-task in
asyncio — so concurrent requests from different tenants cannot observe each
other's config, and the existing `try/finally` reset (which the helper
preserves) prevents leakage into a later request on the same worker.

## 4. API / interface

**No new endpoints. No request/response shape changes. No new auth headers.**
Behavior-only change on existing routes.

New internal helper, `core/tenant_pipeline.py`:

```python
async def run_tenant_input_pipeline(content, context, tenant_config) -> PipelineResult
async def run_tenant_output_pipeline(content, context, tenant_config) -> PipelineResult
```

Each resolves the guardrail set + config dict from `tenant_config`, sets
`_request_configs`, runs `run_pipeline`, and resets in `finally`. With
`tenant_config=None` the behavior is byte-identical to today's
`run_input_pipeline` / `run_output_pipeline` (defaults, no contextvar).

Callers after the change:
- `api/routes_gateway.py` — input + streaming output
- `api/routes_openai_compat.py` — input + output (its streaming path reuses the
  gateway generator, so that is covered by the same fix)
- `api/routes_classify.py` / `routes_classify_output.py` — `_classify_tenant`
  reduced to a thin wrapper over the helper, so the three paths cannot drift

## 5. Security & backward compatibility

**This changes existing behavior: traffic that passed the proxy yesterday may
block today.** That is the point of the fix, but it is exactly the kind of
default change the repo invariant governs.

**Guardrail set = union (decided).** When `tenant_config` is present, the proxy
runs the default stage guardrails **plus** the tenant's configured ones; tenant
settings override any guardrail the tenant names. Rationale: the alternative
("replace", mirroring `/guardrails/input` exactly) would mean a tenant whose
config lists only a custom policy silently *loses* the default guards on the
proxy path — closing one hole while opening another. Union is strictly additive,
so no tenant ends up with fewer guards than today.

> Consequence to keep honest: proxy semantics are a deliberate **superset** of
> `/guardrails/input`, not a byte-identical copy. The helper takes an explicit
> mode (`replace` for `/guardrails/*`, `union` for the proxies) and both modes
> are tested, so the difference is intentional and pinned rather than drift.

**Monitor mode must be honored.** `/guardrails/input` applies
`apply_policy_mode(resolve_mode(tenant_config))` (`routes_classify.py:250`); the
proxies do not. Without this, a tenant running a policy in `monitor` (dry-run)
mode would start getting hard 403s/refusals on chat traffic the moment this
ships — the precise failure `core/policy_mode.py` exists to prevent. The proxies
must resolve the mode and suppress would-be blocks in `monitor`, while still
recording the finding in the audit log. Administrative blocks (kill switch,
disabled agent) continue to enforce in monitor mode, per `is_administrative`.

**Rollout: on by default + kill switch (decided).** Enforcement is on by
default, because a dormant security guard is a known failure mode in this repo.
Escape hatch: `SHIELD_DISABLE_TENANT_POLICY_ON_PROXY=1` restores the old
(default-guardrails-only) proxy behavior for an operator whose traffic breaks.
Migration note ships in the same PR.

**Authz.** No privilege change. Policies are read from the tenant resolved by
the caller's own API key; a caller cannot select, inject, or disable another
tenant's policy. Strictly more restrictive than today — a malicious caller gains
nothing, and loses a bypass.

## 6. Packaging & deploy

- **New deps:** none. `contextvars`, `os` are stdlib; everything else is already
  imported on these paths. No `requirements*.txt` change.
- **`Dockerfile.admin`:** no change — `admin_app.py` does not import any
  affected module. (`core/tenant_pipeline.py` is data-plane only. If a later
  change makes admin import it, it must be added to the COPY allowlist;
  `tests/test_admin_dockerfile_imports.py` enforces this.)
- **Env flags:** `SHIELD_DISABLE_TENANT_POLICY_ON_PROXY` (unset = enforce).
- **Rebuild:** data-plane image only.
- **Rollout:** deploy → verify the `bank-co` repro blocks on
  `/v1/chat/completions` → watch for a spike in proxy blocks; if a tenant's
  legitimate traffic breaks, set the kill switch and move that tenant's policy
  to `monitor` mode rather than leaving the flag on.

## 7. Failure modes & edge cases

| Case | Behavior |
|---|---|
| No API key / no tenant (`tenant_config is None`) | Defaults only — byte-identical to today |
| `tenant_config` present, no `input_guardrails` key | Defaults only |
| `input_guardrails` present but empty `{}` | Defaults only (union of nothing) |
| Guardrail named in config not in registry (`get_guardrail` → None) | Skipped, as `_classify_tenant` already does. Not fatal |
| Guardrail configured `enabled: false` | Skipped — an explicit tenant disable must not be resurrected by the union |
| Same guardrail in defaults *and* tenant config | Runs **once**, with tenant settings. Dedupe by guardrail name — must not double-run or double-charge latency |
| Empty / whitespace `last_user_msg` (no user turn) | Pipeline runs as today; guards handle empty content |
| Huge message | Unchanged — existing length guards apply |
| Redis down (tenant lookup fails) | Middleware yields `tenant_config = None` → defaults only. **Fail-open on tenant policy** |
| Guardrail raises | `_run_guardrail` already catches → `action: "log"`, request proceeds |
| Streaming | Input is checked pre-stream; output policy applies in the post-stream generator (`routes_gateway.py:334`) and the incremental in-stream check |
| Concurrency | contextvar is per-task; `try/finally` reset preserved |
| Kill switch set | Old behavior exactly |

**Fail-open vs fail-closed, stated explicitly:** *fail-open on tenant-policy
resolution* — if the tenant/config cannot be resolved, the request runs with
default guardrails rather than being rejected. This matches the existing
behavior of `/guardrails/input` and avoids a Redis outage becoming a full
traffic outage. It is a deliberate availability tradeoff: a tenant policy can go
unenforced during a Redis outage. Guardrail *execution* remains fail-closed on
the proxies, which already wrap the pipeline in try/except and refuse on error
(`routes_openai_compat.py:181`).

## 8. Test plan (Definition of Done)

Regression tests (the ones the bug report asks for):
1. Tenant with a custom **input** policy → blocked via `/v1/chat/completions`
2. Tenant with a custom **input** policy → blocked via `/v1/shield/chat/completions`
3. Tenant with a custom **output** policy → blocked via both proxies
4. Parity test: same message + same tenant config yields the same block decision
   from `/guardrails/input` and both proxies — the drift guard

Edge cases from §7, each its own test:
5. No tenant → defaults only, response unchanged (backward-compat pin)
6. Empty / missing `input_guardrails` → defaults only
7. `enabled: false` tenant guardrail is not resurrected by the union
8. Guardrail present in both defaults and tenant config runs exactly once
9. Unknown guardrail name in config → skipped, request still served
10. `policy_mode: "monitor"` → proxy does **not** block, finding still audit-logged
11. `SHIELD_DISABLE_TENANT_POLICY_ON_PROXY=1` → old behavior
12. Streaming request with a tenant output policy → blocked mid/post-stream

Refactor safety:
13. Existing `/guardrails/*` tests stay green unchanged — proves pure extraction
14. Unit tests on the helper directly for `replace` vs `union` mode

Gates: full suite `python -m pytest tests -q` green in a **clean venv**
(`python -m venv /tmp/x && /tmp/x/bin/pip install -r requirements-test.txt`);
CI `pytest` gate passes.

## 9. Task breakdown (PRs)

Per the repo's single-branch guidance, these land as ordered commits on one
branch / one PR — they are not independently shippable (Task 1 alone changes
nothing; Task 2 alone is the untested behavior change).

1. **Extract the helper.** Add `core/tenant_pipeline.py` with `replace` +
   `union` modes; reduce both `_classify_tenant` functions to wrappers. Pure
   refactor — existing tests must pass untouched. (+ tests 13, 14)
2. **Wire the proxies.** Use the helper in `routes_gateway.py` and
   `routes_openai_compat.py`, input + output + streaming; honor monitor mode;
   add the kill-switch flag. (+ tests 1–3, 10, 11, 12)
3. **Edge cases + parity guard + migration note.** (+ tests 4–9, docs)
