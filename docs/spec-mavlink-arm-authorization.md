---
title: "Spec: MAVLink arm authorization"
layout: default
nav_order: 65
permalink: /spec-mavlink-arm-authorization/
description: "Shield as the arm authority a flight controller already knows how to ask. Local-first: the decision is made on the aircraft from a signed policy bundle, with no network in the path. The cloud distributes policy and collects audit, asynchronously."
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

### Local-first, because the aircraft is where the decision has to happen

An earlier draft of this spec called Shield over HTTPS for every arm decision and
denied when unreachable. That is the wrong shape. Aircraft fly out of coverage as
a matter of routine, and a product that grounds the fleet when the link drops
will be switched off rather than debugged.

So the network is **not in the decision path at all**. The authorizer decides
locally, from a signed policy bundle cached on disk, and the cloud does two
asynchronous jobs on either side of that:

```
   ONLINE, whenever a link exists            ON THE AIRCRAFT, always
   ------------------------------            -----------------------
   author policy in the portal
        |  signed bundle, pulled
        +----------------------------->  verify signature, cache
                                              |
   fleet view, compliance  <---------+    DECIDE  (no network, microseconds)
        |  audit records, pushed     |         |
        +----------------------------+    hash-chain locally
```

The decision is local. Distribution and audit are eventual. A vehicle that has
never seen the internet since its bundle was installed enforces exactly the
policy operations authored.

### The outcome

A deployable that answers arm requests for a vehicle, decides from a locally
cached signed bundle with no network in the path, and refuses with a reason the
operator sees in QGroundControl.

Observable success conditions:

1. With `COM_ARM_AUTH_REQ=1` and the authorizer running, a vehicle whose mission
   violates policy **cannot arm**, and QGC shows why.
2. **Unplug the network entirely and every one of these still holds.** No
   degraded mode, no warning banner, no difference in behaviour.
3. A bundle whose signature does not verify is refused, and the aircraft does not
   arm on unverified policy.
4. Audit records accumulate offline and reconcile when a link returns, with the
   chain intact across the gap.
5. Killing the authorizer prevents arming rather than permitting it.

### Non-goals

- **Not in-flight command enforcement.** This is a pre-flight gate. An inline
  MAVLink command firewall is a much larger and riskier product and is sketched
  in §9 as a later phase, deliberately not built here.
- **Not a replacement for PX4 pre-arm checks.** PX4 continues to own airworthiness:
  sensors, calibration, EKF, battery. This adds *policy*, which PX4 has no
  opinion about.
- **Not message authentication.** MAVLink 2 signing is a separate mechanism, also
  present in PX4 (`MavlinkSignControl`), and is noted in §9.
- **No new guardrail.** The evaluation reuses the deterministic families
  `evaluate_parameter_policy` already defines, executed locally by the same code
  path `examples/drone_sitl/edge_policy.py` uses.
- **Not a judged-rules engine on the aircraft.** Prompt-injection and
  mission-scope judgement need a model. What happens without one is decided in
  §5 rather than fudged.

## 2. Plane & latency contract

**A new deployable that is autonomous by design.**

| Component | Runs | Network |
|---|---|---|
| `shield-mavlink-authorizer` (new) | companion computer or GCS | **none required to decide** |
| Data plane | unchanged | serves signed bundles, receives audit, both asynchronously |
| Admin plane | unchanged | policy authoring, approvals, fleet view |

**Guard path: not touched, and not called.** The authorizer does not call
`tool/check` on the decision path. It evaluates locally. That is a deliberate
departure from every other Shield integration, and the reason is that the
alternative fails exactly when a drone most needs it.

**Off hot path, no guarded-traffic impact.** The bundle pull and audit push are
background work on their own schedules, and neither blocks a decision.

### Latency

| Path | Budget | Measured |
|---|---|---|
| Local decision | under 10 ms | 3.3 us for the deterministic bundle today |
| Bundle refresh | best effort | background, never blocks |
| Audit sync | best effort | background, buffered on disk |

Arming is not time-critical, so even a slow local decision is invisible. The
point of the local path is not speed, it is **existence**: a decision that can
always be made beats a faster one that sometimes cannot.

## 3. Data model

### On the aircraft, which is now the authoritative copy at decision time

| Path | Contents | Notes |
|---|---|---|
| `policy_bundle.json` | signed bundle: `parameter_policies`, approval rules, `bundle_version`, `issued_at`, `expires_at` | the policy. Verified before use, never trusted from disk alone |
| `bundle.sig` | Ed25519 detached signature + `kid` | verified against a pinned public key shipped with the image |
| `audit/pending.jsonl` | hash-chained decision records awaiting sync | append-only, survives restart |
| `audit/head.json` | `{seq, record_hash}` chain head | lets the chain continue across reboots |

### In the tenant, unchanged

| Key | Owner | Used for |
|---|---|---|
| `agentic_cp:config:{tenant}` | `storage/agentic_control_plane.py` | authoring `parameter_policies["arm"]` and approval rules; source of the bundle |
| `auditchain:{scope}` / `auditchain:ckpt:{scope}` | `storage/audit_chain.py` | where synced records land, and the signed checkpoints over them |

Tenant scoping is unchanged. The bundle is issued for one tenant and one fleet,
and the signature covers that binding, so a bundle lifted from one customer's
aircraft does not verify on another's.

### Bundle expiry, which is the replacement for connectivity

A bundle carries `expires_at`. An aircraft offline for longer than the validity
window is flying policy nobody has reconfirmed, and §7 says what happens then.
This is the mechanism that keeps "works offline" from quietly becoming "never
checks in again".

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

### Deciding, locally

No call to Shield. The authorizer evaluates the arm request against the cached
bundle using the same deterministic families the server defines, executed by the
evaluator in `examples/drone_sitl/edge_policy.py`:

```python
verdict = policy.check("arm", {
    "aircraft_id": "AB-1234", "airframe": "quad_x500",
    "mission_waypoints": 12, "max_relative_altitude_m": 95,
    "mission_within_fence": True, "battery_pct": 96,
    "wind_ms": 7, "local_hour": 14, "operator_role": "pilot_in_command",
})
```

`tests/test_edge_policy_parity.py` already proves that evaluator agrees with
`evaluate_parameter_policy`, and it must be extended to cover the arm tool. That
parity test is what makes local evaluation safe to ship: without it, an aircraft
enforces something subtly different from what operations authored, and both sides
believe they agree.

### Getting policy, asynchronously

```
GET /v1/tenant/me/policy-bundle          H: X-API-Key   -> signed bundle + sig
```

A new read-only admin-plane route that serializes the tenant's arm-relevant
policy and signs it with `core.signers` (the same Ed25519 machinery
`storage/audit_chain.py` uses for checkpoints, and `core/approvals.py` for
grants). Pulled on a timer; a failed pull is not an error, it is Tuesday.

### Returning audit, asynchronously

```
POST /v1/tenant/me/audit-sync            H: X-API-Key   <- buffered records
```

Records are hash-chained on the aircraft as they are made, using
`storage/audit_chain.py`'s existing `record_hash` construction, so the chain is
built offline and verified centrally on arrival. A gap in the sequence is
detectable; a rewritten record does not verify. Sync order does not matter.

### Configuration

```yaml
vehicle:    udpin://0.0.0.0:14540
system_id:  10                      # must equal COM_ARM_AUTH_ID
agent_key:  gcs-authorizer
grant_valid_time_s: 60

bundle:
  path:        ./policy_bundle.json
  public_key:  ./bundle_signing.pub  # pinned; a bundle that does not verify is refused
  refresh_s:   900                   # best effort, never blocks a decision
  on_expired:  deny                  # deny | warn, see section 5

audit:
  spool:  ./audit/
  sync_s: 300                        # best effort

shield: https://api.guardrails.votal.ai   # optional. Absent means never sync.
```

`shield:` being optional is the point. An air-gapped install sets a bundle by
hand, never sets a URL, and works.

## 5. Security & backward compatibility

**Nothing changes for existing tenants.** A new optional deployable, plus two new
read-only-ish admin routes. No default changes, no schema change, no behaviour
change to any guard.

**Non-breaking on the vehicle too.** `COM_ARM_AUTH_REQ` defaults to `0`. A
customer who installs nothing is unaffected; enabling it is a deliberate act on
their own airframe.

### The bundle is the policy, so the signature is the whole security model

Once the decision is local, an attacker who can write `policy_bundle.json` owns
the guardrails. This is the central risk the local-first design creates, and it
did not exist in the call-the-server version.

- Bundles are **Ed25519 signed** by `core.signers`, the same machinery already
  signing audit checkpoints and approval grants. No new crypto.
- The verifying public key is **pinned in the deployed image**, not fetched. A key
  fetched over the network is a key an attacker on that network can replace.
- The signature covers `tenant_id`, `fleet_id`, `bundle_version`, `issued_at`,
  `expires_at`, and the policy body, so a valid bundle cannot be replayed onto a
  different tenant, a different fleet, or forward in time.
- **A bundle that does not verify is not used, and the aircraft does not arm.**
  Falling back to a previous bundle on verification failure is tempting and
  wrong: it hands an attacker a downgrade primitive.

### Judged rules offline: stated, not fudged

Prompt-injection and mission-scope rules need a model. On an aircraft with no
link and no local model there is no honest way to evaluate them.

**Judged rules are absent offline, and actions that depend on them are refused
rather than approximated.** A keyword list standing in for judgement is how a
deterministic engine starts silently answering questions it cannot answer, which
`tests/test_edge_policy_parity.py` already forbids for the edge evaluator.

For arm authorization this costs little in practice: the arm decision is
overwhelmingly geometric and numeric, which is exactly what survives offline. A
deployment that wants judged rules in the air needs a local model on the
companion computer, and that is a separate spec.

### Expired bundles

`on_expired: deny` (default) refuses to arm on stale policy. `warn` arms and logs
loudly, for operators whose sorties genuinely outrun their refresh window.

The default is deny because an indefinitely stale bundle is indistinguishable
from an aircraft that has been quietly removed from governance.

### Threat model, honestly

| Attacker capability | Gains | Mitigated by |
|---|---|---|
| Network position between aircraft and Shield | nothing on the decision path; can withhold updates | decisions are local; `expires_at` bounds withholding |
| Write access to the bundle file | nothing, without the signing key | Ed25519 signature, pinned public key |
| Steals the tenant API key | can pull bundles and push audit; **cannot** author policy or sign a bundle | signing key never leaves the admin plane |
| Spoofs MAVLink as the authorizer | can send an accept | **not mitigated.** Unsigned MAVLink. See section 9 |

That last row is the honest gap. This design raises the bar on *policy*, not on
link security, and MAVLink 2 signing is the separate answer.

## 6. Packaging & deploy

- **`Dockerfile.admin`: MUST be updated, and this is the invariant most likely to
  bite.** PR 1 and PR 4 add `api/routes_policy_bundle.py` and
  `api/routes_audit_sync.py`, both mounted on `admin_app.py`. That file is a
  curated per-file COPY allowlist, so a new import that is not added to it
  crash-loops the admin image at boot. `tests/test_admin_dockerfile_imports.py`
  enforces it, and the COPY lines belong in the SAME PR as the routes.
  An earlier draft of this spec claimed this section was untouched, which was
  wrong: it was written when the authorizer called an existing endpoint, and it
  stopped being true the moment policy distribution moved server-side.
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

The table is reordered around one premise: **absence of network is normal
operation, not a failure.** It appears here only to say it changes nothing.

| Condition | Behaviour | Rationale |
|---|---|---|
| **No network at all, ever** | decides normally from the cached bundle | the design centre, not a degraded mode |
| Shield unreachable at refresh time | keep using the current bundle until `expires_at` | a failed pull is routine |
| Bundle expired, `on_expired: deny` | refuse `TIMEOUT`, STATUSTEXT says the bundle is stale | stale policy is ungoverned policy |
| Bundle expired, `on_expired: warn` | arm, log loudly, record it | for sorties that outrun the window |
| **Bundle signature invalid** | refuse, and do **not** fall back to a previous bundle | falling back is a downgrade primitive |
| Bundle absent on first boot | refuse to arm; the authorizer is not configured | silent permissiveness is the worst default |
| Bundle for the wrong tenant or fleet | signature binding fails, treated as invalid | prevents lifting a bundle between customers |
| Audit spool full or unwritable | **refuse to arm** | an unrecordable decision is one nobody can review afterwards, which is the property regulated buyers buy |
| Audit sync fails | keep spooling, retry | the chain tolerates arbitrary delay |
| Clock wrong on the companion computer | `expires_at` may misjudge; log the skew when a sync reveals it | an aircraft with no network also has no NTP; worth surfacing, not solvable here |
| Judged rule needed, no model available | refuse that action | see section 5; never approximated |
| Authorizer process dead | vehicle cannot arm | fail-closed, and the operator sees a timeout rather than silence |
| `COM_ARM_AUTH_ID` mismatched | vehicle never asks | read the param at startup and warn loudly; a silent no-op is the worst failure here |
| Two authorizers on one network | both may answer, first wins | log it; a duplicate is a misconfiguration worth surfacing |
| Arm held for approval, no link | refuse this attempt; approval needs a reachable human | an unanswered hold is not an allow |

**Fail-open versus fail-closed, stated:** fail-closed throughout, including the
audit-unwritable case, which is the one people usually get wrong. The failure
mode is an aircraft that stays on the ground.

## 8. Test plan (Definition of Done)

**Unit, no vehicle and no network** (`tests/test_mavlink_arm_authorizer.py`):

1. A compliant request produces `accept_arm_authorization` with the configured validity.
2. Each violation class maps to the right typed reason, one case per row of the section 4 table.
3. The reason string reaches `STATUSTEXT`, not only the enum.
4. **A tampered bundle is refused, and the previous bundle is not used.** The downgrade path is the one that matters.
5. A bundle signed for another tenant or fleet is refused.
6. An expired bundle refuses under `deny` and arms with a loud log under `warn`.
7. A missing bundle refuses.
8. An unwritable audit spool refuses to arm.
9. Records written offline form a valid hash chain, verified with `storage/audit_chain.py`'s own verifier.
10. A sync gap is detectable, and out-of-order arrival still verifies.

**Regression guards:**

11. **Parity: the local evaluator and `evaluate_parameter_policy` agree on the arm tool**, extending `tests/test_edge_policy_parity.py`. Local evaluation is only safe while this holds.
12. The authorizer imports nothing from `core/` or `api/` except the signature verifier and chain helpers, so it stays a client rather than a second copy of the engine.
13. Every `RejectionReason` emitted exists in MAVSDK, pinned by reflection, so an SDK rename fails here rather than at an airfield.

**Integration, against SITL, by hand and documented:**

14. `COM_ARM_AUTH_REQ=1`, compliant mission, arms.
15. Mission breaching the fence, refuses, QGC shows the reason.
16. **Network cable pulled: every one of 14 and 15 behaves identically.** This is the headline claim and it gets an explicit test.
17. Authorizer killed, vehicle cannot arm.

**Green bar:** full suite in a clean venv, CI `pytest` gate passing, new tests must not require `mavsdk`.

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
| `Dockerfile.admin` allowlist | **HIGH.** PR 1 and PR 4 each add a router `admin_app.py` imports | COPY lines ship in the same PR as the route; `tests/test_admin_dockerfile_imports.py` is the gate |
| Declare dependencies | **Medium.** `mavsdk` is new, and the authorizer needs the Ed25519 verifier | `mavsdk` in component-local requirements only, never root; tests stub it. The verifier is `cryptography`, already a root dependency, so no new crypto library |
| Secure by default, non-breaking | **None.** New optional deployable, and `COM_ARM_AUTH_REQ` defaults off | nothing changes for anyone who does not opt in |
| Self-contained PRs | see task breakdown | each ships its own tests |

## Task breakdown

Five PRs. Each leaves the tree green and is independently reviewable.

**PR 1. Bundle signing and distribution.** `GET /v1/tenant/me/policy-bundle`,
serializing arm-relevant policy and signing it with `core.signers`. A verifier
usable without the rest of Shield. Tests 4, 5.

*First because everything else trusts it. A local decision built on an unsigned
bundle is worse than no local decision.*

**PR 2. The authorizer, offline only.** `packages/shield-mavlink/`: connect,
answer arm requests from the cached bundle, map verdicts to typed reasons,
STATUSTEXT. No network code at all. Tests 1, 2, 3, 6, 7, 11, 12, 13.

*Shippable alone, and air-gapped installs need nothing further.*

**PR 3. Offline audit.** Local hash chain, spool, refuse-when-unwritable.
Tests 8, 9.

**PR 4. Sync.** `POST /v1/tenant/me/audit-sync`, background refresh and push.
Test 10.

**PR 5. Packaging.** Container, config schema, key provisioning, the SITL runbook
covering tests 14 to 17, and the `COM_ARM_AUTH_ID` mismatch check.

## Open questions

1. **What is PX4's actual arm-authorization timeout?** It bounds the budget and
   is not in `commander_params.yaml`. Needs measuring against SITL. Less critical
   now that the decision is local and sub-millisecond, but still unknown.
2. **How does the signing key reach the aircraft image?** The public key is
   pinned, which means a build-time or provisioning-time step, and rotating it
   means reflashing or a provisioning channel. This is the operationally hardest
   part of the design and is not yet specified.
3. **What is the right default `expires_at`?** Too short grounds aircraft that are
   legitimately out of contact; too long lets one drift out of governance
   unnoticed. Probably a fleet policy rather than a constant.
4. **Do we run the authorizer, or does the customer?** Customer-run is assumed
   throughout and is the safer default, but it puts a tenant key on a machine at
   an airfield.
5. **Does `COM_ARM_AUTH_MET=1` (two-step) fit a held approval better?** The
   operator re-commands after authorization, which may map onto a pending
   approval more naturally than the one-arm method.
