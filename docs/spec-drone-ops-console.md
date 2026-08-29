---
title: "Spec: guarded drone demo and ops console"
layout: default
nav_order: 64
permalink: /spec-drone-ops-console/
description: "Rebuild the PX4 SITL demo so it enforces through real Shield calls instead of a local mock, and add a standalone operations console with a live decision feed and a supervisor approval queue."
---

# Spec: guarded drone demo and ops console
{: .no_toc }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. Problem & outcome

### The problem

`examples/drone_sitl/votal_guarded_drone_demo.py` does not use Shield. Its
`VotalDroneGuard` is a 70-line if/else class defined in the same file; the
imports are `asyncio`, `dataclasses`, `typing`, and `mavsdk`. There is no HTTP
call, no Shield client, no policy engine, no guardrail.

An engineer evaluating it reads the whole enforcement mechanism in one screen and
correctly concludes they could write it themselves before lunch. The demo does
not merely fail to sell the product, it argues against buying it.

Three supporting defects:

- **The interesting actions are no-ops.** `stream_video` does not stream. It
  calls `_allowed` and returns, so "data exfiltration blocked" blocks nothing.
- **The best guard is dead code.** `process_external_text` implements indirect
  prompt-injection detection and is never called from `main()`. That is the
  central OWASP threat for autonomous systems and it is absent from the demo.
- **The threat model is IT RBAC.** "Role X may not call action Y" is web-app
  access control. It is not what loses aircraft.

There is also a real bug: `fly_offset` converts longitude with a hardcoded
`75_000.0` m/deg, which is `111111·cos(lat)` at roughly 47.5 degrees, i.e.
correct only at PX4 SITL's default Zurich home. Anywhere else the aircraft flies
to the wrong place, silently.

### The outcome

A demo where every flight action is authorized by a real Shield call before it
reaches the flight controller, and a standalone operations console where a
supervisor sees the decision feed and approves or denies a held action.

Observable success conditions:

1. Removing the Shield deployment breaks the demo. Enforcement cannot be
   satisfied locally, because there is no local enforcement left.
2. A high-risk action returns `pending_confirmation`, appears in the console
   queue, and executes only after a supervisor approves it, with the approver
   identity recorded.
3. Every decision appears in tenant telemetry and the tamper-evident audit chain
   without the demo writing them itself.

### Non-goals

- No new guard, guardrail, or enforcement primitive. Everything this needs is
  built; the work is wiring and presentation.
- No portal changes. The console is a standalone page under
  `examples/drone_sitl/` (decision recorded 2026-08-28).
- No real airspace data. NOTAM and controlled-airspace integration are noted as
  future work, not built here.
- No autonomy or planning. The "AI planner" remains a scripted sequence of
  requested actions; this demo is about enforcement, not flight intelligence.
- Not a flight-safety system. Shield is a policy layer above the autopilot, and
  the demo must say so in as many words. PX4's own failsafes remain authoritative.

## 2. Plane & latency contract

**Both planes, and neither is modified.**

| Plane | Used for | Change |
|---|---|---|
| Data (`core/app.py`) | `POST /v1/shield/tool/check` authorizes each action | none, existing endpoint |
| Admin (`admin_app.py`) | `/v1/tenant/me/agentic/*` approvals and config | none, existing routes |

**Guard path: touched only as a caller.** The demo calls `tool/check`, which is
on the guard path, but adds no code to it. No new guardrail, no new middleware,
no change to `enforce_tool_call` or the tool guard chain.

**Off hot path, no guarded-traffic impact.** The console polls the admin plane
only. It never sits between the agent and the data plane, and no console request
is in the path of a flight action.

Latency note for honesty in the demo narration: `tool/check` is a network call
per action. At demo scale that is one hop on actions that already take seconds of
flight time. The spec deliberately does not claim this is suitable for inner-loop
flight control, and the README must say that plainly: this authorizes
**mission-level commands**, not stabilization.

## 3. Data model

No new Redis keys. The demo writes through existing endpoints and the console
reads through existing endpoints.

| Key | Owner | Used for |
|---|---|---|
| `agentic_cp:config:{tenant_id}` | `storage/agentic_control_plane.py` | approval rules that make an action require sign-off |
| `agentic_cp:approvals:{tenant_id}` | same | the pending queue the console renders |
| `data_policies:{tenant_id}` | `api/routes_data_policies.py` | the mission policy, as a real tenant data policy |

Tenant scoping is unchanged: `tenant_id` resolves from `X-API-Key` on every call,
never from the request body, so the demo cannot read or write another tenant.

The one new artifact is a config file in the repo, not in Redis:

- `examples/drone_sitl/mission_policy.json`, the mission policy as a data-policy
  document, posted to the tenant at setup. Same role as
  `saas/examples/mcp_input_protection_policy.json`.

## 4. API / interface

All endpoints exist today. None are added or modified.

### Authorizing a flight action (data plane)

```
POST /v1/shield/tool/check          H: X-API-Key
{
  "agent_key":   "drone-planner",
  "tool_name":   "fly_to_zone",
  "user_role":   "operator",
  "session_id":  "mission-perimeter-inspection-001",
  "workflow":    "perimeter_inspection",
  "tool_params": {"zone": "zone-c", "altitude_m": 120.0,
                  "battery_pct": 41.0, "over_people": false}
}
```

Response carries `allowed`, `action`, and `guardrail_results[]`. Three outcomes
drive the demo:

| `action` | Meaning | Demo behavior |
|---|---|---|
| `pass` | authorized | send to PX4 via MAVSDK |
| `block` | refused | never reaches the flight controller |
| `pending_confirmation` | held for a human | wait, poll, execute only on approval |

The held case is produced by the `approval_lifecycle` guardrail
([`api/routes_tool.py:541`](api/routes_tool.py:541)), whose details carry
`request_id` and `required_approvals`.

### Making an action require approval (admin plane)

```
PUT /v1/tenant/me/agentic/config    H: X-API-Key
{"approvals": {"enabled": true, "rules": [{
   "rule_id": "high-altitude-requires-supervisor",
   "tool_names": ["fly_to_zone"],
   "workflows": ["perimeter_inspection"],
   "min_approvals": 1,
   "request_ttl_seconds": 600,
   "single_use": true}]}}
```

Rule matching is `find_matching_approval_rule`
([`storage/agentic_control_plane.py:677`](storage/agentic_control_plane.py:677)):
empty `tool_names` / `workflows` / `agent_keys` mean "any".

### The console (admin plane, read plus two writes)

```
GET  /v1/tenant/me/agentic/approvals?status=pending
POST /v1/tenant/me/agentic/approvals/{request_id}/approve
POST /v1/tenant/me/agentic/approvals/{request_id}/deny
GET  /v1/tenant/me/telemetry?limit=50
```

The console is a single self-contained HTML file served from disk or any static
host. It holds the tenant key in a field the operator pastes in; it does not
embed one.

## 5. Security & backward compatibility

**Nothing changes for existing tenants.** This adds an example and a static page.
No default changes, no new flags, no schema migration, no behavior change to any
guard.

**Authz.** Every call is tenant-scoped by `X-API-Key`. The approve and deny
endpoints already exist and already enforce their own authorization; this spec
does not widen them.

**The demo must not ship a credential.** `mission_policy.json` carries policy
only. The tenant key comes from the environment for the Python side and from a
paste field for the console. No key in the repo, no key in the page, no key in a
screenshot.

**Console exposure.** It is a demo artifact under `examples/`, not a deployed
service and not mounted by either app. Anyone opening it must supply a key to see
anything. It should carry a visible banner saying it is a demonstration console,
so it is never mistaken for a flight-operations product.

**Honest framing is a security property here.** A drone audience that believes
Shield is a flight-safety layer will misuse it. The README and the console banner
must both state that PX4's failsafes are authoritative and Shield governs
mission-level command authorization.

## 6. Packaging & deploy

**No packaging changes. This is the low-risk part of the spec.**

- **`Dockerfile.admin`:** untouched. `admin_app.py` gains no import. The modules
  the console reads through (`api/routes_agentic_control_plane.py`,
  `storage/agentic_control_plane.py`, `core/approvals.py`) are already in the
  COPY allowlist at lines 103, 137, and 64.
- **`requirements.txt` / `requirements-test.txt`:** untouched. The demo's only
  third-party import is `mavsdk`, which belongs in
  `examples/drone_sitl/requirements.txt` as an example-local dependency, exactly
  as `examples/mcp_gateway/requirements.txt` handles `mcp`. It must **not** enter
  the root requirements: nothing in the product imports it, and adding it would
  put a drone SDK in the guardrail server image.
- **Env flags:** none added. The demo reads `SHIELD_URL` and `SHIELD_TENANT_KEY`.
- **Images to rebuild:** none.

## 7. Failure modes & edge cases

| Condition | Behavior | Rationale |
|---|---|---|
| `SHIELD_URL` or key unset | Print what to set and exit non-zero | Fail closed. A demo that "works" without Shield is the defect being fixed. |
| Shield unreachable mid-flight | **Refuse the action, then land** | Fail closed on authorization, but the safe response for an airborne vehicle is to land, not to hover indefinitely or continue unauthorized. |
| Shield returns 5xx or times out | Same as unreachable; one bounded retry, then refuse and land | Prevents a transient blip from ending a demo, without inventing permission. |
| PX4 not running | Detect at connect, print the `make px4_sitl` command, exit | Today's failure mode is a hang on `connect()`. |
| Approval never granted | Expire at `request_ttl_seconds`, treat as denied, land | Matches `expires_at` in the request; an unanswered hold is not an allow. |
| Approval denied | Skip the action, continue the mission, log it | A denial is a normal outcome, not an error. |
| Console polled with a bad key | Render the 401 as a message, not a blank page | Silent blankness reads as a broken console. |
| Redis down | Admin plane returns an error; console shows it verbatim | Governance surface, not the guard path. Not the demo's job to mask. |
| Concurrent approve and deny | Whichever lands first wins | Existing `update_approval_request` semantics. Not re-litigated here. |
| Telemetry empty | Show "no decisions yet" | First run before any action. |

**Fail-open vs fail-closed, stated:** authorization is **fail-closed**
throughout. There is no code path in which an action reaches MAVSDK without an
`allowed` decision from Shield. Vehicle response to a failure is **land**, which
is the conservative physical action, not a relaxation of the policy.

## 8. Test plan (Definition of Done)

The demo is an example, so tests target the pieces that can regress silently
rather than the flight sequence.

**Unit tests** (`tests/test_drone_demo_guard.py`, no PX4 and no network):

1. `pass` sends the action; a stub MAVSDK records the call.
2. `block` never touches MAVSDK. Asserted on the stub, not on stdout.
3. `pending_confirmation` does not send, then sends after an approval is
   simulated.
4. Approval expiry is treated as denial and triggers land.
5. Shield unreachable refuses and triggers land, and does **not** send.
6. Missing `SHIELD_URL` exits non-zero before connecting to anything.
7. The longitude conversion is latitude-correct: assert the offset at the
   equator, at 47.5 degrees, and at 60 degrees, pinning the bug that exists
   today.

**Regression guard:**

8. A test asserting the demo module imports **no** local policy-evaluation class,
   i.e. that `VotalDroneGuard` is gone and enforcement is remote. This is the
   drift-prone coupling: the mock is exactly what someone would reintroduce to
   "make the demo work offline", which would silently restore the defect this
   spec exists to remove.

**Not automated, verified by hand before demoing:** the console renders against a
live tenant, the approve button moves a request out of the queue, and the held
action then executes.

**Green bar:** full suite in a clean venv, CI `pytest` gate passing. New tests
must not require `mavsdk`; the stub is local and `mavsdk` imports are guarded so
the suite runs without it.

## Invariant risks

Called out explicitly per the template. This spec is unusually low-risk:

| Invariant | Risk | Mitigation |
|---|---|---|
| Off the hot path | **None.** Calls the guard path, adds nothing to it. | No guard-path code changes. |
| `Dockerfile.admin` allowlist | **None.** No new `admin_app.py` import. | Verified: the three modules read are already at lines 64, 103, 137. |
| Declare dependencies | **Low.** `mavsdk` is new. | Example-local `requirements.txt` only; explicitly kept out of root requirements so it never enters the server image. Tests stub it. |
| Secure by default, non-breaking | **None.** Additive example. | No default changes, no flags. |
| Self-contained PRs | Handled in the task breakdown below. | Each task ships its own tests. |

## Task breakdown

Three PRs, in order. Each is independently reviewable and leaves the tree green.

**PR 1. Make it real.** Replace `VotalDroneGuard` with `tool/check` calls
through `examples/shield_client.py`. Add `mission_policy.json` and a setup step
that posts it. Fix the longitude bug. Delete the dead `process_external_text`
branch or, better, wire it into the mission as the injection beat. Tests 1, 2,
5, 6, 7, 8.

*This PR alone fixes the credibility problem. If only one ships, ship this one.*

**PR 2. Flight-ops rules.** Extend the mission policy with energy envelope
(waypoint beyond battery return range) and kinetic risk (flight over people),
per the 2026-08-28 decision. Add the approval rule that produces the held state.
Tests 3, 4.

**PR 3. Ops console.** The standalone page: live decision feed, fleet state,
approval queue with approve and deny, and a geofence map showing the attempted
waypoint against the mission boundary. Manual verification, plus the banner and
key-handling requirements from §5.

## Open questions

1. **Which action is the held one?** `fly_to_zone` above a threshold is the
   obvious candidate, but a supervisor approving "fly higher" is a weaker story
   than approving something with consequence. A better beat may be flight over a
   populated area, or a data egress. Worth choosing deliberately before PR 2.
2. **Does the console need multi-drone fleet state**, or is one aircraft enough
   to carry the story? Multi-drone is more convincing and materially more work,
   and PX4 multi-vehicle SITL is its own setup burden.
