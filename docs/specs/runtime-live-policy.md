---
title: "Spec: Live Runtime Policy, Advisor and Lock"
layout: default
nav_exclude: true
permalink: /specs/runtime-live-policy/
description: Apply runtime profile changes to running OpenShell sandboxes without a restart, turn sandbox denials into least-privilege suggestions an operator approves in the portal, and keep sandboxes from being loosened outside Shield.
---

# Spec: Live Runtime Policy, Advisor and Lock

> Status: **APPROVED 2026-09-28** (user: "approved"), with the decisions in §12.
> Builds on `docs/specs/infra-guardrails.md` (APPROVED, shipped in #444).
> Planes:
> - **Admin + data (tenant API, both planes like today):** advice, history, drift.
> - **Data plane:** event ingest (existing) gains the advisor aggregation and
>   applied-state records, in the background.
> - **Broker side (examples/, not a server plane):** the sync sidecar gains a
>   watch loop, live apply, reconcile and lock.

## 0. The gap in one paragraph

#444 made Shield the author of an agent's runtime boundary: one profile,
compiled to OpenShell, signed, fed back as events. It stops at sandbox
creation. A profile change today means recreating every sandbox. A denial lands
in the audit log and nobody is told what rule would fix it. Anyone with access to the
OpenShell gateway can run `openshell policy set` and loosen a sandbox without
Shield knowing. NVIDIA's OpenShell pitch has three parts: an immutable boundary,
policy advising and live policy changes. We cover the first only partly and
the other two not at all.

## 1. What OpenShell 0.0.80 actually does (verified live, 2026-09-28)

A probe sandbox on the local gateway, then deleted:

| Change on a running sandbox (`openshell policy set NAME --policy f --wait`) | Result |
|---|---|
| `network_policies`: method `GET` to `*` on an existing endpoint | Applied live: "Policy version 3 loaded" |
| `filesystem_policy.read_write`: add `/var/tmp` | Applied live: version 4 |
| `filesystem_policy.read_write`: remove `/tmp` | **Rejected**: "read_write path '/tmp' cannot be removed on a live sandbox" |
| `process.run_as_user` change | **Rejected**: "process policy cannot be changed on a live sandbox (applied at startup)" |

| Advisor and lock | Result |
|---|---|
| 6 x `curl https://pypi.org` denied (L4, `NET:OPEN`) | OpenShell created 1 pending draft chunk `allow_pypi_org_443`, binary `/usr/bin/curl`, hit_count 6, confidence 0.65, proposing **all methods** on the host |
| 6 x `POST api.github.com/zen` denied (L7, `HTTP:POST`) | **No** draft chunk |
| `openshell policy set --global` (gateway-wide lock) | Sandbox shows "Policy source: global" |
| Sandbox-level `policy set` while locked | Refused |
| `ApproveDraftChunk` (gRPC) while locked | Refused: `FAILED_PRECONDITION` "cannot approve rules while a global policy is active" |
| `openshell policy list NAME` | Revision history with a content hash per revision (same content gives the same hash) |

Consequences for the design:
1. Live apply is safe to **attempt**: OpenShell itself rejects what cannot be
   changed live, atomically. Shield does not need to predict it perfectly.
2. OpenShell's own advisor is too coarse for us (host-wide, all methods) and
   blind to L7 denials. Shield builds suggestions from the deny events it
   already ingests, which covers L7 and every runtime, not just OpenShell.
3. The global lock is **per gateway**, not per profile. It is only usable
   when a gateway runs sandboxes of one profile. Everywhere else, tamper
   detection has to come from reconciling.

## 2. Problem & outcome

**Outcome, observable:**

1. **Live apply.** An operator adds `pypi.org GET` to `coding-agent` in the
   portal. Within one watch interval (default 30 s) every running sandbox on
   that profile has loaded the new policy, with no restart. The drift view
   shows them all on the new hash.
2. **Restart only when needed.** A change OpenShell cannot apply live (a
   removed filesystem path, a process change) leaves those sandboxes on the old
   policy and marks them `restart_required` in the drift view, with OpenShell's
   reason. Attestation `enforce` then refuses them new capabilities, as today.
3. **Advisor.** After an agent is denied `pypi.org` a few times, the Runtime
   Profiles tab shows a suggestion: "allow GET pypi.org:443 /simple/** for
   /usr/bin/curl; 6 hits; 1 agent; last seen 2 min ago". Approve (optionally
   edited) writes the profile, and step 1 applies it live. Reject suppresses it.
   An L7 denial (`POST api.github.com`) produces a suggestion too, which
   OpenShell does not.
4. **Tamper.** Someone runs `openshell policy set` on a sandbox, or approves a
   rule in the OpenShell TUI, outside Shield. Within one watch interval
   Shield records a critical `runtime_boundary` event, and the sidecar
   restores Shield's policy (`--reconcile revert`, default) or only reports it
   (`--reconcile report`, for development). Rules added out of band show up as
   advisor suggestions, so an operator can approve them properly.
5. **Lock.** With `--lock global` on a gateway dedicated to one profile, the
   sandbox cannot be loosened at all. OpenShell refuses both `policy set` and
   draft approvals.

**Non-goals:**
- Shield never restarts or recreates sandboxes. `restart_required` is
  reported, and the broker decides.
- No automatic approval of any suggestion, ever.
- No suggestions that loosen **filesystem** or **process** rules. Those denials
  are shown as observed activity only. Loosening a file boundary from observed
  traffic is how a sandbox escape gets approved.
- No wildcard hosts in suggestions.
- No mirroring of OpenShell's own draft chunks in v1. The sidecar stays stdlib-only.
  A TUI approval is handled by reconcile (outcome 4).
- Kubernetes, Cilium and Squid live apply stays out of scope. They already
  reload from their own objects. The advisor itself works for their deny
  events.

## 3. Plane & latency contract

| Component | Plane | Guard path? | Budget |
|---|---|---|---|
| Advice list, approve, reject; profile history; extended drift | both (existing `/v1/tenant/me/runtime-profiles` router) | **No.** Off hot path, no guarded-traffic impact. | n/a |
| Advisor aggregation | data, inside the existing `rt_events.ingest` background task | **No.** Runs after the 202 is returned. | ≤ 3 Redis ops per deny event; bounded by the existing per-tenant ingest rate limit |
| Applied-state records (from the sidecar) | data, same background task | **No** | 1 HSET per report |
| `check_attestation` in `cap/mint` | data | **Yes** (existing check) | Unchanged when the token's hash matches (a comparison). On a mismatch only: **one extra HGET** to see whether the instance was live-updated. Microseconds; the mismatch path already writes a drift record. |
| Sidecar watch loop | broker host | n/a | 1 conditional GET (304 when unchanged) + 1 `openshell policy get` per sandbox per interval |

## 4. Data model

All keys are tenant-scoped. The tenant always comes from the authenticated
key, never from a body or an event.

### 4.1 Profile history
`rtprofile_hist:{tenant_id}:{name}`: LIST, newest first, `LTRIM` to 20. No TTL.
Deleted together with the profile.
```json
{"hash": "sha256:...", "profile": {...normalized...}, "at": 1790662000,
 "actor": "tenant:acme", "reason": "put | advice:adv_3f2a... | rollback"}
```
Written by every save path: PUT, advice approve. It gives the portal a diff
and a "this change needs a restart" preview (§5.1).

### 4.2 Advice
`rtadvice:{tenant_id}:{profile}`: HASH. `EXPIRE` refreshed on every write,
`SHIELD_RUNTIME_ADVICE_TTL_DAYS` (default 30).
- Field `{advice_id}`: JSON metadata.
- Field `{advice_id}:hits`: counter (`HINCRBY`), so concurrent ingests never lose counts.

`advice_id = "adv_" + sha256(kind|host|port|binary)[:16]`, deterministic, so
repeats aggregate.
```json
{"id": "adv_3f2a...", "kind": "network_allow | network_method | binary",
 "status": "pending | approved | rejected",
 "host": "pypi.org", "port": 443,
 "methods": ["GET"], "methods_observed": true,
 "paths": ["/simple/**"], "binary": "/usr/bin/curl",
 "agents": ["coding-bot"], "sources": ["openshell"],
 "first_seen": 1790662321.8, "last_seen": 1790662337.2,
 "sample_reason": "endpoint pypi.org:443 is not allowed by any policy",
 "flags": ["write_method"], "decided_by": "", "decided_at": 0,
 "reject_reason": "", "origin": "denial | out_of_band"}
```
Caps: at most `SHIELD_RUNTIME_ADVICE_MAX` (200) pending suggestions per profile.
Past the cap, new keys are dropped and counted in a `_dropped` field. Up to 20
agents and 10 paths are kept per suggestion. Rejected suggestions stay until TTL so they are not
suggested again.

### 4.3 Applied state
`rtapplied:{tenant_id}:{profile}`: HASH, field = sandbox instance name,
`EXPIRE` 7 days (the same as `rtdrift`).
```json
{"state": "current | restart_required | tampered | reverted | apply_failed",
 "profile_hash": "sha256:...", "runtime_hash": "e732cd735480",
 "runtime_version": 3, "lock": "none | global", "reconcile": "revert | report",
 "detail": "read_write path '/tmp' cannot be removed on a live sandbox",
 "trusted": true, "at": 1790662400}
```
`trusted` is true only when the report was posted with an **admin-scoped key**
(`core.auth.caller_key_scope(request)` returns `("admin", True)`), whatever
`SHIELD_REGISTRY_WRITE_SCOPE` is set to. `require_registry_write` cannot be
used here: it is a no-op under its default `off`, which would make every agent
key trusted. Only trusted records count for attestation (§6), so the sidecar
must run with an admin-scoped key for live updates to satisfy attestation.
With any other key its reports are still recorded and shown, and attestation
stays strict.

## 5. How it works

### 5.1 Live apply (sidecar `examples/runtime/shield_runtime_sync.py`)
New flags. Without `--watch`, today's one-shot behaviour is unchanged.
```
--watch SECONDS           poll the signed bundle (ETag, so a 304 when unchanged)
--sandbox NAME            sandboxes to manage (repeatable)
--sandbox-prefix PREFIX   or every sandbox whose name starts with PREFIX
--reconcile revert|report default revert
--lock none|global        default none
```
Each tick:
1. GET the bundle. If it changed: verify the signature (existing code), then for each
   managed sandbox run `openshell policy set NAME --policy F --wait`.
2. Success: report `applied` with OpenShell's version and hash. Rejected as not
   changeable live: report `restart_required` with OpenShell's message, and
   leave that sandbox on its old policy. Any other failure: `apply_failed`, retried next tick.
3. Reconcile: `openshell policy get NAME -o json`. If its hash is not the one
   the sidecar last applied, report `tampered`, post each out-of-band endpoint
   as an `audit` network event (`detail.out_of_band: true`), and, with `revert`,
   re-apply and report `reverted`.

Reports go to the existing `POST /v1/shield/runtime/events` as
`kind: policy, decision: audit`, with `detail.op` set to one of `applied`,
`restart_required`, `tampered`, `reverted` or `apply_failed`, plus
`detail.instance`. Tampered reports have severity `critical`. Ingest writes
`rtapplied` for these ops. There is no new endpoint.

**Restart preview.** A new pure function,
`compilers.openshell.live_change(old_profile, new_profile) -> {live: bool, reasons: [...]}`,
encodes the §1 table (network: live; filesystem additions: live; filesystem
removals, process and landlock changes: restart). The portal shows it before
save, using §4.1 history. It is advisory only: OpenShell's answer in step 2 is
authoritative.

### 5.2 Advisor (aggregation in `core/runtime_policy/advisor.py`)
Input: the normalized deny events `ingest` already receives, from any source.
The profile is `event.profile`, or else the agent's registry binding
(`check.profile_for`). With neither, there is no suggestion (the audit row is still written).

| Deny event | Suggestion |
|---|---|
| network deny, host not in the profile | `network_allow`: host and port. Methods and paths come from observed L7 events; for an L4-only denial they default to `["GET"]`, marked `methods_observed: false` |
| L7 deny on a host already allowed | `network_method`: a **separate** allow entry with only the observed methods and paths. Merging into the existing entry would widen it (an entry is methods x paths, so POST merged into `GET /**` allows POST everywhere). OpenShell 0.0.80 allows a request if any policy does (verified: `GET /**` + `POST /zen` entries allowed POST /zen and denied POST /other) |
| network deny on an allowed host by a binary not in `allow_binaries` | `binary`: always flagged |
| file or process deny | none: shown as observed activity only |

Least privilege, deterministic, with no LLM:
- Paths are collapsed to at most 3 prefixes, each up to 2 segments deep plus `/**`.
- A suggestion never widens beyond what was observed.
- An L7 denial after a GET-only approval produces a new `network_method`
  suggestion, so privileges grow one observed step at a time.

**Flags**, each of which needs `confirm_flagged: true` to approve:
- `write_method`: POST, PUT, PATCH or DELETE
- `raw_ip`: an IP literal instead of a hostname
- `non_standard_port`: anything other than 443 or 80
- `binary`: a new binary
- `exfil_domain`: a built-in list (pastebin, transfer.sh, webhook.site, ngrok,
  trycloudflare, requestbin, and so on) extended by the tenant's xflow
  destinations classified `public`
- `out_of_band`: the rule came from a tamper diff, not a denial

**Approve:**
1. Takes a per-profile lock: `SET rtprofile_lock:{tenant}:{name} NX EX 5`, so
   concurrent approvals never overwrite each other.
2. Reads the latest profile and applies the (optionally edited) rule.
3. Validates with `validate_profile`, saves, and appends history.
4. Invalidates the check cache, writes an admin audit row, and marks the
   suggestion approved.

The live apply in §5.1 then pushes the change to sandboxes.

### 5.3 Lock
`--lock global` runs `openshell policy set --global --yes`. It applies only
when **every** sandbox on the gateway is managed by this sidecar, checked
against `openshell sandbox list` at start and every tick. Otherwise the sidecar
refuses to start, because a global lock would silently replace other sandboxes'
policies. Reconcile uses `policy get --global`. The sidecar never runs
`policy delete --global`. Unlocking is a manual operator action, which is
documented.

## 6. API

| Method | Path | Notes |
|---|---|---|
| GET | `/v1/tenant/me/runtime-profiles/{name}/advice?status=pending` | `{profile, current_hash, advice: [...], dropped}` |
| POST | `/v1/tenant/me/runtime-profiles/{name}/advice/{id}/approve` | Body `{methods?, paths?, confirm_flagged?: bool}`. Returns `{hash, profile, rule, live_change}`. 409 if already decided, 422 if flagged without `confirm_flagged`, 503 if Redis is down. `require_registry_write`. |
| POST | `/v1/tenant/me/runtime-profiles/{name}/advice/{id}/reject` | Body `{reason}`. `require_registry_write`. |
| GET | `/v1/tenant/me/runtime-profiles/{name}/history` | The last 20 versions, with hash, actor, reason and `live_change` compared with the previous version |
| GET | `/v1/tenant/me/runtime-profiles/{name}/drift` | **Extended, backward compatible.** Existing fields unchanged. Adds `instances: [{instance, state, profile_hash, runtime_hash, lock, reconcile, attested_hash, trusted, at}]` merged from `rtdrift` and `rtapplied`. |
| PUT | `/v1/tenant/me/runtime-profiles/{name}` | Unchanged contract. Also appends history and returns `live_change` compared with the previous version. |

Auth for all of these is `X-API-Key` or the portal session, the same as the
existing router. Events keep using `POST /v1/shield/runtime/events`.

**Attestation (`core/runtime_policy/attest.py`).** Today a live update would
break `enforce`: the agent token still claims H1 while the sandbox now runs
H2. On a mismatch only, `check_attestation` reads
`rtapplied[instance_id]`. It accepts the call when that record is `trusted`,
has `state: current` and has `profile_hash == current`. The broker must mint
the agent token with `agent_instance_id` = the sandbox name (documented).
Escape hatch: `SHIELD_RUNTIME_ATTEST_ACCEPT_APPLIED=0`.

## 7. Security & backward compatibility

- **Nothing changes by default:**
  - The sidecar without `--watch` behaves exactly as today.
  - Existing endpoints keep their response fields.
  - The advisor is passive: it writes suggestions and never changes a policy.
- **Escape hatches:**
  - `SHIELD_RUNTIME_ADVISOR=off` stops aggregation.
  - `SHIELD_RUNTIME_ATTEST_ACCEPT_APPLIED=0` restores strict token-claim
    attestation.
- **Who can loosen:** approving a suggestion is a profile write, behind
  `require_registry_write` and in the admin audit, exactly like PUT. An
  agent's own runtime key can create suggestions (it can cause denials). Once
  `SHIELD_REGISTRY_WRITE_SCOPE` is `enforce`, it cannot approve them. Under
  the default `off`, approval is as open as PUT is today. This spec does not
  change that; the docs point to `enforce` for production.
- **Events are evidence, not commands.** This invariant from #444 is kept. A
  report can mark a sandbox `tampered` or `restart_required` (more strict).
  Only a **trusted** `applied` report can satisfy attestation, so an agent
  cannot post "I run H2" with its own key to get a capability.
- **Signed bundles only.** Watch mode applies only bundles that verify. A bad
  signature is never applied, the last verified policy stays in place, and a
  `critical` event is raised.
- **Tamper window.** Without the lock, an out-of-band loosening is live until
  the next tick (≤ `--watch` seconds). The docs say this plainly and point
  production single-profile gateways to `--lock global`.
- **Suggestion poisoning.** A compromised agent can generate denials for
  `attacker.example` in the hope that an operator approves them. Mitigations:
  - Flags, including `exfil_domain` and `raw_ip`.
  - Explicit confirmation for flagged suggestions.
  - The portal lists which agents caused each suggestion.
- **`exfil_domain` uses a built-in host list only.** xflow apps are keyed by
  tool name, not hostname, so there is nothing to extend it with (a change
  from the draft, found while building task 5).
  - No bulk "approve all" that includes flagged suggestions.

## 8. Packaging & deploy

- **New module** `core/runtime_policy/advisor.py`. `Dockerfile.admin` already
  copies the whole `core/runtime_policy/` directory (line 146) and
  `api/routes_runtime_policy.py` (line 118), so no new COPY lines are needed.
  The admin-imports guard test covers it.
- **New pip dependencies:** none. The sidecar stays stdlib-only.
- **Env:**
  - `SHIELD_RUNTIME_ADVISOR` (on)
  - `SHIELD_RUNTIME_ADVICE_TTL_DAYS` (30)
  - `SHIELD_RUNTIME_ADVICE_MAX` (200)
  - `SHIELD_RUNTIME_ATTEST_ACCEPT_APPLIED` (1)
- **Rebuild:** both images (the data plane for ingest and attestation, the admin plane for the portal and API).
- **Docs:** `docs/infra-guardrails.md` gains "Live updates", "Advisor" and
  "Locking a gateway" sections (customer-facing, no em dashes).

## 9. Failure modes & edge cases

| Case | Behaviour |
|---|---|
| Shield unreachable during watch | **Fail static:** keep the last verified policy, keep reconciling against it, and report when back. Never remove a policy. |
| Bundle signature fails | Not applied. `critical` event. The last verified policy stays in place. |
| Profile deleted (404) | Keep the last policy and alert. Never wipe it. |
| OpenShell gateway down | Retry with backoff. The sandboxes keep their loaded policy (held by OpenShell). |
| Mixed change (network add + filesystem removal) | OpenShell rejects it atomically. `restart_required`, and the network part is **not** applied either. The restart preview warns about this before save. |
| Sidecar crash | The sandboxes keep their policy. Drift shows reports going stale by `at`. |
| Redis down | Aggregation is skipped (ingest still returns 202 and still audits). Approve and reject return 503. Attestation falls back to today's strict comparison. |
| Concurrent approvals | Serialized by the profile lock. If the lock is held for more than 5 s, the second gets 409 and retries. |
| Advice already decided | 409. |
| Deny storm, or many distinct hosts | Existing ingest rate limit, then the 200-pending cap with a `_dropped` count. |
| Event with no profile and no binding | No suggestion. The audit row is still written. |
| Deny for the Shield host itself | Never suggested (it is always allowed). Logged as an anomaly. |
| `--lock global` with unmanaged sandboxes on the gateway | Sidecar refuses to start and names them. |
| Suggestion would produce an invalid profile (e.g. a 201st allow entry) | Approve returns 422 with the validation errors. The suggestion stays pending. |

## 10. Test plan (Definition of Done)

- **Advisor (unit):**
  - Each event kind maps to the right suggestion kind.
  - L4 default GET with `methods_observed: false`; L7 method merge.
  - Path collapsing; each flag; no wildcard hosts; file and process denials
    make no suggestion.
  - Deterministic ids aggregate repeats; `HINCRBY` counts under concurrency.
  - Cap and `_dropped`; TTL refresh; rejected suggestions not re-suggested.
- **Approve / reject:**
  - Flagged without confirm gives 422; decided gives 409.
  - The lock serializes two approvals and neither rule is lost.
  - History is appended; the admin audit row is written; the check cache is invalidated.
  - `require_registry_write` enforced; Redis down gives 503.
- **History and restart preview:**
  - `live_change` covers every §1 row: network live, filesystem add live,
    filesystem removal restart, process restart.
- **Applied state and attestation:**
  - A trusted `applied` at the current hash passes `enforce` with an old token
    claim.
  - An untrusted report does not, including one posted with an unscoped key
    while `SHIELD_REGISTRY_WRITE_SCOPE=off` (the default).
  - `SHIELD_RUNTIME_ATTEST_ACCEPT_APPLIED=0` restores strict behaviour.
  - A matching claim still costs no Redis read.
- **Sidecar** (stub `openshell` on PATH, recording calls):
  - Live apply.
  - Rejection gives `restart_required`.
  - Tamper with `revert` re-applies; `report` does not.
  - Out-of-band endpoints are posted as events.
  - Shield unreachable is fail static; a bad signature is never applied.
  - `--lock global` refuses when unmanaged sandboxes exist.
  - No `--watch` means the output is byte-identical to today's.
- **Live OpenShell** (opt-in, extends `tests/test_runtime_openshell_live.py`):
  - A network change applies with no restart.
  - A filesystem removal is rejected, giving `restart_required`.
  - A `policy set` out of band is reverted within one tick.
  - Under `--lock global`, `policy set` is refused.
- **Regression:**
  - Existing drift fields unchanged.
  - The `Dockerfile.admin` import guard passes.
  - The full suite is green in a clean venv; CI `pytest` passes.

## 11. Task breakdown

One branch, `feat/runtime-live-policy`, one PR. There is one commit per task,
and each task is reviewable and shippable on its own.

| # | Task | Size |
|---|---|---|
| 1 | Profile history (store + GET `/history`), `live_change` pure function, PUT returns `live_change` | S |
| 2 | Applied state: ingest records `rtapplied` (with `trusted`), extended `/drift`, attestation accepts trusted `applied` | S |
| 3 | Sidecar `--watch`: live apply, `restart_required` / `apply_failed` reports, fail static | M |
| 4 | Sidecar reconcile (`revert` / `report`, out-of-band events) and `--lock global` with its gateway safety check | M |
| 5 | Advisor: aggregation, least-privilege narrowing, flags, advice list/approve/reject with lock and audit | M |
| 6 | Portal: Advisor panel, Sandboxes (drift) panel, History with restart preview; customer docs | M |
| 7 | Live OpenShell tests for tasks 3 and 4 | S |

## 12. Decisions taken (change any before approving)

1. **Shield builds suggestions from its own deny events** rather than mirroring
   OpenShell's draft chunks. It covers L7 and every runtime, and it narrows to
   observed methods and paths.
2. **Reconcile defaults to `revert`**, and the lock is opt-in per gateway,
   because it is gateway-wide in OpenShell.
3. **No filesystem or process suggestions**, and no automatic approval.
