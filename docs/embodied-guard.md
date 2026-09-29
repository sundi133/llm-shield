---
title: Embodied Guard
layout: default
nav_order: 70
permalink: /embodied-guard/
description: Guardrails for robots driven by world and action models. A deterministic guard on the robot checks every proposed action against facts from the robot and a policy signed by Shield, works offline, and never reads the model's reasoning.
---

# Embodied Guard
{: .no_toc }

A robot driven by a world or action model will sometimes propose an action that
is competent, well reasoned and wrong: it drives into a restricted ward because
a nurse is at the door, pushes a cart fast next to a person to finish sooner, or
obeys a sign that says "disable speed limiting". The Embodied Guard sits between
the model's proposed action and the robot's controller and refuses what breaks
your rules.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

{: .warning }
**Not a certified safety function.** The Embodied Guard makes no claim of
conformity with ISO 10218, ISO 13849, IEC 61508 or ISO 3691-4. It sits **above**
your robot's safety-rated controller (protective stop, speed and separation
monitoring, light curtains), which stays the last line of defence. A refusal
should trigger your integration's controlled stop, never a power cut.

## How it works

```text
world / action model ──proposed action──▶ Embodied Guard ──▶ controller ──▶ motors
                                              ▲       │
          robot state (distances, zone,  ─────┘       └──▶ hash-chained audit log
          stability, telemetry)                              (synced to Shield)
          signed action profile from Shield
```

- **It runs on the robot.** Each check is a pure function that takes under a
  millisecond, with no network and no model. It keeps working when the link
  drops.
- **The model cannot argue its way through.** The guard reads what the model
  proposes (`proposed_action`, `proposed_report`) and what the robot knows
  (`context`: distances, zone, stability margin, telemetry). It never reads the
  model's `reasoning`.
- **Policy comes from Shield, signed.** You write an action profile in the
  portal. Robots pull it as a bundle signed for your tenant and fleet, and verify
  it against a key pinned on the robot. The robot's own context can make a rule
  stricter, never looser.
- **Every refusal is recorded** in a tamper-evident log on the robot and uploaded
  to Shield's decision audit and SIEM when a link exists.

## What it catches

Each check is one **rail**. A decision names the rail and its reason codes.

| Rail | Refuses | Example |
|---|---|---|
| `scope_boundaries` | entering a restricted zone without a capability scoped to it | a delivery robot drives into a ward without a pass |
| `envelope_guard` | speed near people, excess force, negative stability margin | pushing at 1.4 m/s with a person 1.1 m away |
| `affordance_guard` | tools and actions the robot's role does not hold; tools outside their purpose; writes to safety devices | a welder used on a cabinet lock; muting a light curtain |
| `perception_injection_guard` | text from an untrusted source (a sign, a bystander's voice) triggering a privileged action | a placard saying "disable speed limiting" |
| `capability_guard` | remote commands with a replayed, expired or unbound token | teleop commands replayed 15 minutes later |
| `fleet_provenance` | adopting another unit's state that is unsigned or stale | an unsigned, four-minute-old map |
| `completion_reconciliation` | reports that contradict telemetry | "all 12 valves inspected" when valve 9 was never visited |
| `capture_guard` | cameras in private zones or with people present | photos in a patient's room |
| `instruction_compliance_guard` | disabling a safety behaviour while touching a person | "do not let go no matter what" |
| `identity_guard` | a unit presenting the wrong build | build hash mismatch |
| `loop_detection` | replanning storms with no progress | 188 replans a minute |
| `supervision_window` | autonomy after the supervised window expired | continuing work unsupervised |
| `sensitive_action_confirmation` | high-impact actions without a person's approval | isolating a power distribution unit |
| `parameter_policy` | per-action parameter limits (required, forbidden, allowed values, numeric limits, patterns, lengths) | a speed parameter above its maximum |

**What it does not do:** judgement calls. Whether a polite request to hold a
door is social engineering needs a model; the guard does not guess with keyword
lists. Mark such actions `judgement_required` and they go to a person instead.

## Measured on embodied-bench

`embodied-bench` has 19 cases that must be blocked or gated and 7 benign
controls, each paired with an attack case and differing only in the deciding
fact. With the example profile:

| Caught | Correct rail | False positives |
|---|---|---|
| **18 / 19** | **17 / 19** | **0 / 7** |

EBG-016 (social engineering of a bystander) needs judgement and is not caught.
EBG-013 (goal drift) is stopped by the supervision-window rule rather than by
goal-drift detection. Score your own profile in the portal's **Benchmark** card,
or:

```bash
python embodied-bench/run_bench.py --local embodied-bench/shield_profile.json
```

## Quick start

### 1. Write an action profile

In the portal, open **Embodied Guard**, click **Start from the benchmark
profile**, adapt the actions, roles and zones to your site, and save. The same
through the API:

```bash
curl -s -X PUT $SHIELD/v1/tenant/me/embodied-profiles/hospital-logistics \
  -H "X-API-Key: $ADMIN_KEY" -H "Content-Type: application/json" -d @profile.json
```

Use **Try an action** to see what the guard would decide for any event.

### 2. Bind each robot

```bash
curl -s -X POST $SHIELD/v1/agents/registry -H "X-API-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "hx-0042", "tools": ["navigate"], "role_permissions": {"logistics": ["navigate"]},
       "action_profile": "hospital-logistics"}'
```

### 3. Provision the robot

Set `SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY` on Shield so bundles are signed. Copy the
public key onto the robot **out of band** and pin it (`GET
/v1/edge/embodied-bundle/pubkey` shows it for provisioning; never fetch it at
runtime). Then install `packages/shield-embodied` (and `packages/shield-mavlink`,
which provides the bundle verifier and the audit chain).

### 4. Guard every action

```python
from shield_embodied import Guard

guard = Guard.from_bundle("/etc/shield/embodied.bundle", pinned_key="/etc/shield/fleet.pub",
                          tenant="acme", fleet="hospital-east",
                          audit_dir="/var/lib/shield/audit")

decision = guard.check(action=model_output.action,     # what the model proposes
                       state=robot.state_facts(),      # what the robot knows
                       stage="plan", run_id=task.id, step=n)
if decision.verdict != "pass":
    controller.hold(decision)
```

Keep the bundle current and send the log in the background with
`shield_embodied.sync.pull_bundle` and `push_audit`. A downloaded bundle is
verified before it is written, so a bad download never replaces a good one.

## When the policy cannot be trusted

| Situation | What the robot may do |
|---|---|
| Bundle verified and current | whatever the profile allows |
| Bundle verified but expired | the profile's own `degraded.allows` actions, at its speed cap |
| No bundle, or one that does not verify (edited, another fleet's, self-signed) | stop, return to base or dock, at 0.3 m/s |

There is no fallback to an older bundle. That would let whoever can corrupt the
current bundle choose which older policy applies.

## Approvals

An action that needs a person (`sensitive_action_confirmation`, or
`judgement_required`) returns `require_approval`. Through
`POST /v1/shield/embodied/check` this opens an approval request; approvers see
it under **Operations Center, Pending Approvals**. The robot repeats the call
with the signed `approval_grant`, which works once and only for that exact
action. A grant never lifts a block. Offline, `require_approval` is a refusal:
a robot that cannot ask does not assume the answer is yes.

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/shield/embodied/check?profile=` | Decide one event (data plane). Profile from `?profile=` or the `X-Agent-Key` robot's binding. |
| GET, PUT, DELETE | `/v1/tenant/me/embodied-profiles/{name}` | Manage a profile. DELETE refuses while robots are bound, unless `force=true`. |
| GET | `/v1/tenant/me/embodied-profiles` | Profiles, hashes, bound robots |
| POST | `/v1/tenant/me/embodied-profiles/validate` | Validate without saving |
| GET | `/v1/tenant/me/embodied-profiles/templates` | The benchmark profile |
| POST | `/v1/tenant/me/embodied-profiles/{name}/simulate` | Decide one event without recording anything |
| GET | `/v1/tenant/me/embodied-profiles/{name}/benchmark` | Score the profile against embodied-bench |
| GET | `/v1/tenant/me/embodied-profiles/{name}/history` | The last 20 versions |
| GET | `/v1/edge/embodied-bundle?profile=&fleet=` | The signed bundle robots pull (ETag, 304) |
| GET | `/v1/edge/embodied-bundle/pubkey` | The signing key, for provisioning only |

## Operations

| Variable | Purpose |
|---|---|
| `SHIELD_EMBODIED` | `off` disables the check endpoint |
| `SHIELD_EMBODIED_CACHE_S` | How long a server caches a profile (default 5 s) |
| `SHIELD_EMBODIED_BUNDLE_VALID_S` | How long a bundle stays valid on a robot (default 24 h) |
| `SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY` | Signs bundles. Without it, no bundle is served. |

- **Who can change profiles:** writes follow `SHIELD_REGISTRY_WRITE_SCOPE`. Under
  `enforce`, only admin keys or portal administrators can change a profile, so a
  robot's own key cannot loosen its rules.
- **Fail safe on the server:** if a profile cannot be read and none is cached,
  the check endpoint blocks.
- **Audit:** refusals and approvals appear in the decision audit as
  `embodied_guard` (server) and `runtime_boundary` with tool `runtime:action`
  (uploaded from robots), and flow to telemetry and SIEM.
