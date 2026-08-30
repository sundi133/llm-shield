---
title: "Spec: MAVLink arm authorization"
layout: default
nav_order: 65
permalink: /spec-mavlink-arm-authorization/
description: "Shield as the arm authority a flight controller already knows how to ask. A pre-flight gate over the standard MAVLink ARM_AUTHORIZATION mechanism, off the in-flight path, fail-closed on the ground."
---

# Spec: MAVLink arm authorization
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

Shield can govern an AI planner's tool calls. It cannot govern a vehicle, because
nothing in the product speaks the protocol vehicles speak. Every drone
integration therefore depends on the customer routing their planner through us
voluntarily, which protects exactly the agent that chose to be protected and
nothing else. An operator with a joystick, a second GCS, or a planner that skips
the SDK is entirely outside our reach.

The demo work makes this visible: `examples/drone_sitl/` guards a planner that
cooperates by construction. It is a real architecture and an incomplete one.

### What MAVLink already provides

PX4 implements a standard mechanism for exactly this, and it is off by default:

| Parameter | Meaning | Default |
|---|---|---|
| `COM_ARM_AUTH_REQ` | require external authorization to arm | `0`, off |
| `COM_ARM_AUTH_ID` | system id of the authorizer | `10` |
| `COM_ARM_AUTH_MET` | `0` one-arm, `1` two-step arm | `0` |

`Commander.cpp` calls `arm_auth_init` and `arm_auth_update`; MAVSDK exposes the
other side as `ArmAuthorizerServer` with `accept_arm_authorization(valid_time_s)`
and `reject_arm_authorization(reason)`, where reason is typed:
`INVALID_WAYPOINT`, `AIRSPACE_IN_USE`, `BAD_WEATHER`, `TIMEOUT`, `GENERIC`.

**The flight controller already knows how to ask permission.** Nobody has to
adopt an SDK, change their planner, or route traffic through a proxy. They set
one parameter.

### The outcome

A deployable that answers arm requests for a vehicle, using Shield's existing
policy engine to decide, and refusing with a reason the operator sees in
QGroundControl.

Observable success conditions:

1. With `COM_ARM_AUTH_REQ=1` and the authorizer running, a vehicle whose mission
   violates policy **cannot arm**, and QGC shows why.
2. The same vehicle with a compliant mission arms normally, and the added delay
   is imperceptible to the operator.
3. Every arm decision, accept or reject, appears in the tenant audit trail.
4. Killing the authorizer prevents arming rather than permitting it.

### Non-goals

- **Not in-flight command enforcement.** This is a pre-flight gate. An inline
  MAVLink command firewall is a much larger and riskier product and is sketched
  in §9 as a later phase, deliberately not built here.
- **Not a replacement for PX4 pre-arm checks.** PX4 continues to own airworthiness:
  sensors, calibration, EKF, battery. This adds *policy*, which PX4 has no
  opinion about.
- **Not message authentication.** MAVLink 2 signing is a separate mechanism, also
  present in PX4 (`MavlinkSignControl`), and is noted in §9.
- **No new guardrail.** The decision comes from the existing tool-check path.

## 2. Plane & latency contract

**A new deployable, not a change to either existing plane.**

| Component | Runs | Speaks |
|---|---|---|
| `shield-mavlink-authorizer` (new) | ground station or companion computer | MAVLink to the vehicle, HTTPS to Shield |
| Data plane | unchanged | serves `POST /v1/shield/tool/check` |
| Admin plane | unchanged | approvals, audit, policy authoring |

**Guard path: caller only.** The authorizer calls `tool/check` with
`tool_name="arm"`. It adds no code to `/guardrails/*`, `cap/mint`, or
`tools/call`. No new guardrail, no middleware, no change to the guard chain.

**Off hot path, no guarded-traffic impact.**

### Latency, which is the reason this is the right first product

Arming is not time-critical. A human has just pressed a button and is watching
the aircraft. Budget is **2 seconds end to end**, and PX4's own timeout bounds it
regardless.

This matters because it means the risky property an inline command firewall would
have, that a slow or failed policy check degrades flight, **does not exist here**.
The worst outcome is an aircraft that stays on the ground, which is the outcome a
safety engineer prefers by default.

## 3. Data model

No new Redis keys. Policy is authored with primitives that already exist.

| Key | Owner | Used for |
|---|---|---|
| `agentic_cp:config:{tenant}` | `storage/agentic_control_plane.py` | `parameter_policies["arm"]`, and an approval rule when arming needs a human |
| `agentic_cp:approvals:{tenant}` | same | the pending queue when an arm is held |
| `data_policies:{tenant}` | `api/routes_data_policies.py` | judged rules, when the link is up |

Tenant resolves from `X-API-Key`, never from the request, so an authorizer can
only ever decide for its own tenant.

New on-disk artifacts, not in Redis:

- `authorizer.yaml`: vehicle connection, tenant key reference, Shield URL,
  cached-bundle path, offline posture.
- the cached policy bundle, reusing the format
  `examples/drone_sitl/edge_policy.py` already reads.

## 4. API / interface

### Vehicle side

The authorizer joins the MAVLink network as `COM_ARM_AUTH_ID` (default system id
10) and answers `MAV_CMD_ARM_AUTHORIZATION_REQUEST`, via MAVSDK's
`ArmAuthorizerServer`:

```
accept_arm_authorization(valid_time_s: int)
reject_arm_authorization(reason: RejectionReason)
```

Shield verdict to MAVLink reason:

| Verdict | MAVLink rejection | Operator sees |
|---|---|---|
| geofence or waypoint violation | `INVALID_WAYPOINT` | which waypoint and which fence |
| outside approved window, airspace | `AIRSPACE_IN_USE` | the window it is outside of |
| wind or weather limit | `BAD_WEATHER` | the limit and the reading |
| held for approval, nobody answered | `TIMEOUT` | that approval is pending |
| anything else | `GENERIC` | the reason string |

The reason string is additionally sent as `STATUSTEXT` so QGC shows prose rather
than an enum. Typed reason for machines, sentence for the human.

### Shield side

No new endpoint. The existing tool check:

```
POST /v1/shield/tool/check        H: X-API-Key
{
  "agent_key":   "gcs-authorizer",
  "tool_name":   "arm",
  "user_role":   "pilot_in_command",
  "session_id":  "sortie-2026-08-29-01",
  "tool_params": {
    "aircraft_id": "AB-1234", "airframe": "quad_x500",
    "mission_waypoints": 12, "max_relative_altitude_m": 95,
    "mission_within_fence": true, "battery_pct": 96,
    "wind_ms": 7, "local_hour": 14,
    "operator_sub": "alice@example.com", "geofence_uploaded": true
  }
}
```

`pass` accepts, `block` rejects, `pending_confirmation` holds. The authorizer
polls the approval and accepts once granted, exactly as
`votal_guarded_drone_demo.py` already does.

### Configuration

```yaml
vehicle:   udpin://0.0.0.0:14540
system_id: 10                       # must equal COM_ARM_AUTH_ID
shield:    https://api.guardrails.votal.ai
agent_key: gcs-authorizer
grant_valid_time_s: 60
offline:   deny                     # deny | cached | allow, see §5
bundle:    ./policy_bundle.json
```

## 5. Security & backward compatibility

**Nothing changes for existing tenants.** A new optional deployable. No default
changes, no schema change, no behaviour change to any guard.

**Non-breaking by construction on the vehicle too.** `COM_ARM_AUTH_REQ` defaults
to `0`. A customer who installs nothing and sets nothing is unaffected. Enabling
it is a deliberate act on their own airframe.

### The offline posture, which is the load-bearing decision

Arming is exactly when the link is most likely to be present, and exactly when
being unable to fly is most annoying. Three postures, and the default is the
conservative one:

| `offline:` | Behaviour with no Shield | For |
|---|---|---|
| `deny` (default) | reject with `TIMEOUT` | the safe default: no authority, no authorization |
| `cached` | decide from the cached bundle, deterministic rules only, judged rules refused | disconnected operations that still want policy |
| `allow` | accept | explicitly opting out; must be a deliberate config act and is logged loudly |

`cached` reuses the edge evaluator, so an operator flying out of coverage still
gets geofence, ceiling, and window enforcement without needing the network.
`allow` exists because pretending nobody will want it produces a worse outcome:
they will disable `COM_ARM_AUTH_REQ` instead, and then nothing is enforced and
nothing is logged.

### Authz and threat model

The authorizer holds a tenant key and must be treated as a credential-bearing
component. What an attacker gains by compromising it: the ability to authorize
arming for that tenant's aircraft. What they do **not** gain: any in-flight
control, since this component sends no commands, only accept/reject.

**MAVLink identity is weak and this spec does not pretend otherwise.** Without
MAVLink 2 signing, a spoofed authorizer on the same network can send an accept.
That is a property of unsigned MAVLink, not of this design, and §9 covers
closing it. Documented plainly rather than glossed: this raises the bar on
policy, not on link security.

## 6. Packaging & deploy

- **`Dockerfile.admin`:** untouched. `admin_app.py` gains no import.
- **New pip dependency:** `mavsdk`, and it must **not** enter `requirements.txt`.
  Nothing in the data or admin plane imports it, and a drone SDK has no business
  in the guardrail server image. It belongs to the new component's own
  `packages/shield-mavlink/requirements.txt`, the pattern
  `examples/mcp_gateway/requirements.txt` already follows. `requirements-test.txt`
  gains nothing; tests stub it, as `tests/test_drone_demo_guard.py` does today.
- **New deployable:** `packages/shield-mavlink/`, its own image, shipped as a
  container the customer runs on their GCS or companion computer.
- **Images to rebuild:** none of the existing ones.

## 7. Failure modes & edge cases

| Condition | Behaviour | Rationale |
|---|---|---|
| Shield unreachable | per `offline:` posture, default reject `TIMEOUT` | no authority, no authorization |
| Shield slow | one retry inside the budget, then reject `TIMEOUT` | PX4 times out regardless; better to answer than to hang |
| Authorizer process dead | vehicle cannot arm | fail-closed, and the operator sees a timeout rather than silence |
| Vehicle link drops mid-request | request abandoned, next arm re-asks | arm authorization is not stateful across attempts |
| `COM_ARM_AUTH_ID` mismatched | vehicle never asks us | detect at startup by reading the param and warn loudly; a silent no-op is the worst failure here |
| Two authorizers on one network | both may answer, first wins | log it; a duplicate authorizer is a misconfiguration worth surfacing |
| Arm held for approval | reject `TIMEOUT` this attempt, accept on the retry once granted | PX4's window is short; approval is not |
| `pending_confirmation` never granted | remains unarmable | an unanswered hold is not an allow |
| Cached bundle missing under `offline: cached` | fall back to `deny` | degrading to permissive is never the fallback |
| Clock skew on the grant | `valid_time_s` short, default 60 s | bounded exposure if an accept is replayed |

**Fail-open versus fail-closed, stated:** fail-closed everywhere except the
explicit, logged `offline: allow`. The failure mode is an aircraft that stays on
the ground.

## 8. Test plan (Definition of Done)

**Unit, no vehicle and no network** (`tests/test_mavlink_arm_authorizer.py`):

1. `pass` produces `accept_arm_authorization` with the configured validity.
2. `block` produces `reject_arm_authorization`, and the verdict maps to the right
   typed reason, one case per row of the §4 table.
3. `pending_confirmation` rejects this attempt and accepts after the approval is
   granted.
4. Shield unreachable under `offline: deny` rejects; the stub records no accept.
5. Shield unreachable under `offline: cached` decides from the bundle, and
   refuses actions that need judged rules.
6. Missing bundle under `offline: cached` falls back to deny.
7. `offline: allow` accepts and emits the loud log line, asserted on.
8. The reason string reaches `STATUSTEXT`, not only the enum.

**Regression guards:**

9. Every `RejectionReason` the code can emit is one MAVSDK actually defines;
   pinned by reflection so an SDK rename fails here rather than at an airfield.
10. The authorizer imports nothing from `core/` or `api/`. It is a client of the
    HTTP API, not a second copy of the engine, and the parity problem
    `tests/test_edge_policy_parity.py` exists to prevent must not be reintroduced
    by the back door.

**Integration, against SITL, run by hand and documented:**

11. `COM_ARM_AUTH_REQ=1`, compliant mission, arms.
12. Same vehicle, mission breaching the fence, refuses, and QGC shows the reason.
13. Authorizer killed, vehicle cannot arm.

**Green bar:** full suite in a clean venv, CI `pytest` gate passing, and the new
tests must not require `mavsdk`.

## 9. Later phases, deliberately not built here

**MAVLink 2 message signing.** PX4 implements it (`MavlinkSignControl`,
`accept_unsigned_callback`, SETUP_SIGNING). Enforcing signed commands closes the
spoofing gap §5 admits. It is a separate spec because key distribution, not
verification, is the hard part.

**Inline command firewall.** The MCP gateway pattern applied to MAVLink: sit
between GCS and vehicle, filter `COMMAND_LONG`, `MISSION_ITEM_INT`,
`SET_POSITION_TARGET_*` against policy. Much higher value and much higher risk,
because it is in the in-flight path where a slow check degrades flight. Worth
doing only after the pre-flight gate has been in production long enough to trust
the policy layer.

**Passive audit tap.** Observe MAVLink, decide nothing, record everything.
Zero risk and useful on its own for customers unwilling to gate anything yet.
Arguably should ship before the firewall as the way to earn that trust.

## Invariant risks

| Invariant | Risk | Mitigation |
|---|---|---|
| Off the hot path | **None.** Calls `tool/check`, adds nothing to it | no guard-path code |
| `Dockerfile.admin` allowlist | **None.** No new `admin_app.py` import | verified |
| Declare dependencies | **Medium.** `mavsdk` is new | component-local requirements only, never root; tests stub it; asserted in a clean venv |
| Secure by default, non-breaking | **None.** New optional deployable, and `COM_ARM_AUTH_REQ` defaults off | nothing changes for anyone who does not opt in |
| Self-contained PRs | see task breakdown | each ships its own tests |

## Task breakdown

**PR 1. The authorizer.** `packages/shield-mavlink/`: connect, answer arm
requests, call `tool/check`, map verdicts to typed reasons, `STATUSTEXT`.
`offline: deny` only. Tests 1, 2, 4, 8, 9, 10.

*Shippable alone. This is the product.*

**PR 2. Offline postures.** `cached` via the edge evaluator, `allow` with the
loud log. Tests 5, 6, 7.

**PR 3. Approval-gated arming.** `pending_confirmation` handling and the retry.
Test 3.

**PR 4. Packaging.** Container, config schema, the SITL integration runbook
covering tests 11 to 13, and the `COM_ARM_AUTH_ID` mismatch check.

## Open questions

1. **What is PX4's actual arm-authorization timeout?** It bounds the whole
   budget, and I could not find it in `commander_params.yaml`. It needs measuring
   against SITL before §2's 2 second budget is more than an assumption.
2. **Should the authorizer be a Shield component or a customer-run one?** Running
   it ourselves means holding a credential that can authorize their aircraft.
   Customer-run is the safer default and is what §4 assumes, but it makes the
   tenant key a thing they must protect on a machine at an airfield.
3. **Does `COM_ARM_AUTH_MET=1` (two-step) fit the approval flow better?** Two-step
   arm may map more naturally onto a held approval than the one-arm method, since
   the operator explicitly re-commands after authorization.
