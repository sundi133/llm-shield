# Spec: capability/approval nonce replay protection fails closed

## 1. Problem & outcome

A capability token is single-use: the verifier burns its nonce, so a leaked cap
cannot be replayed inside its 30s window. An approval grant works the same way,
and there the nonce is what stops a human's "yes" being reused.

Both burn through `_burn_nonce_if_unused`, which swallows every Redis exception
and falls back to a **per-process dict**:

```python
    if r:
        try:
            return bool(r.set(key, "1", ex=ttl, nx=True))
        except Exception:
            pass          # <- silently degrades
    if key in _fallback_store: ...
```

With Redis configured and momentarily unreachable, each worker keeps its own
nonce set, so one cap burns once **per worker** — N replays on an N-worker
deployment — and every one of them reports first-use. The control does not
report that it stopped working. That is the worst property a replay defence can
have: an operator watching logs sees nothing, and the audit trail records N
legitimate-looking actions.

A second, smaller hole: `/cap/verify` takes `burn_nonce` as a **request field**
(`api/routes_agent_auth.py`), so the caller chooses whether single-use applies
to it. A tool server that sends `burn_nonce: false` gets unlimited replays for
the token's lifetime.

**Outcome.** A configured-but-failing nonce store rejects verification instead
of allowing it, and single-use is decided by the operator rather than by the
caller.

**Non-goals.**
- Exactly-once execution. Burning happens before the tool runs, so a crash in
  between loses the action, and an agent that retries after an ambiguous
  timeout can still execute twice with a fresh cap. Single-use bounds *one
  token*, not *one intent*; idempotency keys are the fix and are out of scope.
- Changing TTLs, the signing scheme, or the two-plane split.
- The single-process path where Redis was never configured (see §5).

## 2. Plane & latency contract

Data plane. `cap/mint` and `/cap/verify` are guard path.

No added latency: the Redis `SET NX` call is unchanged on the success path. The
new code runs only in the `except` branch, which today is already an error path.
No extra round-trips, no new I/O, no import cost at request time.

## 3. Data model

Unchanged. Same keys (`cap:nonce:*`, approval `_NONCE_PREFIX`), same TTLs, same
`SET NX` semantics. Nonces are random per token, so tenant scoping is unchanged.

## 4. API / interface

`POST /v1/shield/cap/verify` — `burn_nonce` in the request body is ignored
unless the operator opts in. Response shape unchanged. A verification that fails
because the store is unavailable returns the existing invalid-cap shape with a
distinct message, not a 500.

Internal: new `core/nonce_store.py` exposing `burn_nonce_if_unused(key, ttl)`
and `NonceStoreUnavailable`. `core/capabilities.py` and `core/approvals.py` both
delegate to it — they carry the same logic today, and a fix applied to one and
not the other is how this reappears.

## 5. Security & backward compatibility

The distinction that makes this non-breaking:

| `_get_redis()` | `WORKERS` | Behaviour |
|---|---|---|
| returns `None` | 1 or unset | in-process dict, **unchanged** |
| returns `None` | > 1 | **fail closed** (new) |
| returns a client, `.set()` raises | any | **fail closed** (new) |

The middle row was a correction, and worth recording because the first draft of
this spec got it wrong. It claimed no-Redis meant "dev, tests, a single
process — nothing to share". Running the flow against a real server disproved
that in one line of startup output: `handler.py` defaults to **`WORKERS=32`**,
so `python handler.py` with no Redis is not one process, it is 32 private
dicts, and a capability verifies once in each. The demo replayed a cap
successfully on the first run.

So the condition is not "was Redis configured" but "is there a shared store
when something needs sharing". `handler.py` now exports the resolved worker
count so child processes can see it; absent or unparseable reads as 1, the
conservative direction, which keeps every test and single-process dev server
working.

A deployment that configured Redis and lost it is the other case that silently
degrades today, and it fails closed regardless of worker count.

Escape hatch: `SHIELD_NONCE_LOCAL_FALLBACK=1` restores the old behaviour
(degrade to the local dict, log a warning). For an operator who would rather
keep serving than fail verification during a Redis incident, and who accepts
replay-per-worker as the price.

Second flag: `SHIELD_CAP_ALLOW_DRYRUN_VERIFY=1` re-permits caller-supplied
`burn_nonce` on the HTTP endpoint. Default off. The Python parameter stays —
`verify_cap(..., burn_nonce=False)` is legitimate for diagnostics and is used in
tests; only the *remote* control is withdrawn.

Migration note: an operator whose tool servers currently send
`burn_nonce: false` will see those caps become single-use. That is the intended
correction, and the flag exists for anyone who needs to stage it.

A malicious caller gains nothing: they cannot force the fallback (it depends on
server-side Redis health), and can no longer waive their own single-use.

## 6. Packaging & deploy

`core/nonce_store.py` is imported by `core/capabilities.py` and
`core/approvals.py`, both already in the `Dockerfile.admin` COPY allowlist, so
the new module **must** be added there too.

Both import it at **module level**, deliberately. The existing nonce code
imported `storage.tenant_store` lazily inside the function, and copying that
habit here would have put the dependency somewhere
`tests/test_admin_dockerfile_imports.py` cannot see: that guard only walks
module-load-time imports, by design, because those are what crash at boot. A
function-level import of a module missing from the image fails at *call* time
instead — a cap verification 500ing in production rather than a container that
refuses to start. Hoisting it puts the COPY line under test. `core/nonce_store.py`
imports nothing first-party at module scope, so there is no cycle to avoid.

No new pip dependencies. Rebuild both images. Both flags default off/unset, so
a deploy with no env change is a pure correctness improvement.

## 7. Failure modes & edge cases

- **Redis configured, down** → `NonceStoreUnavailable` → verification fails
  closed with a message naming the cause, distinct from "replay detected" so
  the two are not confused in triage.
- **Redis never configured, one worker** → local dict, unchanged.
- **Redis never configured, many workers** → refuse, naming the worker count
  and the three ways out (configure Redis / WORKERS=1 / accept the fallback).
- **`WORKERS` unset or unparseable** → treated as 1, so a library import or a
  non-uvicorn host does not start failing verification.
- **Fallback flag on, Redis down** → local dict + `WARNING` naming the
  degradation, so it appears in logs rather than nowhere.
- **`.set()` returns `False`** → genuine replay, unchanged.
- **Concurrent burns of one nonce** → `SET NX` is atomic; exactly one wins.
- **Redis recovers mid-flight** → next call uses it; no sticky state.
- **Approval grants** get identical treatment via the shared helper.

Fail-closed is the explicit decision for a configured store, on the grounds that
a rejected legitimate action is recoverable (re-mint) and a replayed capability
is not.

## 8. Test plan (Definition of Done)

- Redis absent → burns locally, second burn returns False (unchanged).
- Redis present and raising → raises `NonceStoreUnavailable`, does **not**
  silently allow.
- Same, with `SHIELD_NONCE_LOCAL_FALLBACK=1` → allowed, warning logged.
- `verify_cap` surfaces it as a `CapabilityError` whose message says the store
  is unavailable, not that a replay occurred.
- Approvals path covered identically.
- `/cap/verify` with `burn_nonce: false` burns anyway; a second call is
  rejected as a replay.
- Same request with `SHIELD_CAP_ALLOW_DRYRUN_VERIFY=1` → honoured.
- `verify_cap(..., burn_nonce=False)` in-process still does not burn.
- Regression: `tests/test_admin_dockerfile_imports.py` catches the new module.
- No Redis + `WORKERS=32` → refuses; message names the count.
- No Redis + `WORKERS=1`, unset, or garbage → still burns locally.
- Redis present + `WORKERS=32` → fine (the refusal is about the missing store,
  not the worker count).
- End-to-end: `examples/cap_flow_demo.py` against a running server, which is
  how the multi-worker case surfaced in the first place.
- Full suite green in a clean venv; CI `pytest` gate passes.
