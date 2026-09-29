# shield-embodied

Guardrails for world and action models, decided on the robot.

A small deterministic guard runs between the model's proposed action and the
controller. It checks each action against facts from the robot itself
(distances, zone, stability margin, telemetry) and a policy signed by Shield,
and refuses what breaks a rule. No network in the decision, under a millisecond
per check, no model, and the model's own reasoning is never read.

Spec: [docs/specs/embodied-action-guard.md](../../docs/specs/embodied-action-guard.md)

**This is not a certified safety function.** It sits above the robot's
safety-rated controller (protective stop, speed and separation monitoring,
light curtains), which stays the last line of defence. A refusal should trigger
your integration's controlled stop, never a power cut.

## Use it

```python
from shield_embodied import Guard

guard = Guard.from_bundle("/etc/shield/embodied.bundle", pinned_key="/etc/shield/fleet.pub",
                          tenant="acme", fleet="hospital-east",
                          audit_dir="/var/lib/shield/audit")

decision = guard.check(action=model_output.action,     # what the model proposes
                       state=robot.state_facts(),      # what the robot knows; never from the model
                       stage="plan", run_id=task.id, step=n)
if decision.verdict != "pass":
    controller.hold(decision)
```

`decision.verdict` is `pass`, `block` or `require_approval` (a person must
approve; offline that is a refusal). `decision.rail` and `decision.reasons` say
why, using the embodied-bench reason codes.

## Provisioning

1. Write the action profile in Shield (`/v1/tenant/me/embodied-profiles/{name}`).
2. Copy the signing public key onto the robot **out of band** and pin it:
   `GET /v1/edge/embodied-bundle/pubkey` gives it for provisioning only.
3. In the background, keep the bundle current and send the audit log:

```python
from shield_embodied import sync
sync.pull_bundle(SHIELD, KEY, profile="hospital", fleet="hospital-east", tenant="acme",
                 bundle_path="/etc/shield/embodied.bundle", pinned_key_hex=PINNED)
sync.push_audit(SHIELD, KEY, audit_dir="/var/lib/shield/audit", robot_id="hx-0042",
                profile="hospital")
```

A downloaded bundle is verified before it is written, so a bad download never
replaces a good bundle.

## When the policy cannot be trusted

| Situation | Mode | What the robot may do |
|---|---|---|
| Bundle verified, not expired | `normal` | whatever the profile allows |
| Bundle verified but expired | `degraded_expired` | the profile's own `degraded.allows`, at its speed cap |
| No bundle, or one that does not verify (edited, another fleet's, self-signed) | `degraded_unverified` | only stop, return to base or dock, at 0.3 m/s |

There is no fallback to an older bundle: that would let whoever can corrupt the
current one choose which older policy applies.

## Facts from security material

`shield_embodied.facts` turns signed tokens and peer state into the facts the
guard reads: `capability_facts` (remote commands, with replay detection via
`NonceCache`), `zone_tokens` (restricted-zone grants) and `peer_state_facts`
(adopting another unit's map). A token that does not verify produces no facts,
so the guard refuses.

## Audit

Every refusal is appended to a hash-chained log on disk (shield-mavlink's
`OfflineAuditChain`); `audit_passes=True` records passes too. A decision that
cannot be recorded is refused.

## Requirements

`cryptography`, plus `packages/shield-mavlink` for the bundle verifier and the
audit chain (found automatically from a Shield checkout). `evaluator.py` and
`model.py` are byte-identical to Shield's `core/embodied/`; a test fails if they
drift.
