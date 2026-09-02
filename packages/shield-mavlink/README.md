# shield-mavlink

Policy enforcement for aircraft, decided on the aircraft.

The network is not in the decision path. A signed policy bundle is cached on the
companion computer, verified against a pinned key, and evaluated locally. The
cloud distributes policy and collects audit, both asynchronously and both
optional. An air-gapped install sets a bundle by hand, never sets a URL, and
works.

Spec: [docs/spec-mavlink-arm-authorization.md](../../docs/spec-mavlink-arm-authorization.md)

## Prove it rather than believe it

```bash
python packages/shield-mavlink/prove.py
```

Runs from anywhere, by absolute path, with no `PYTHONPATH`. The only requirement
is `cryptography`; if it is missing the script says so rather than raising.

Seven attacks, executed rather than described, with no network:

| # | Attempt | Result |
|---|---|---|
| 2 | Edit the altitude ceiling in the bundle on disk | signature fails, aircraft will not arm |
| 3 | Generate your own key and sign a permissive policy | pinned key rejects it |
| 4 | Install a genuinely signed bundle from another fleet | binding rejects it |
| 5 | Keep flying on a bundle that has lapsed | expiry rejects it |
| 6 | Fly offline, then change a denial to an approval in the log | detected, and the record number is named |
| 7 | Delete the inconvenient record entirely | detected as a sequence break |

Every one is reproducible by hand in the temp directory the script prints.

## Show it with and without

```bash
python packages/shield-mavlink/scenarios.py
```

Ten operational failures, each run against the shipped policy, each stating what
it costs when nothing refuses it. A refusal on its own proves nothing: the
audience cannot tell whether the action would have succeeded, so the block reads
as a script printing the word blocked. The WITHOUT column is what makes the WITH
column mean something.

| Scenario | Requires | Without the guard |
|---|---|---|
| Certificate lapsed over the weekend | no attacker | an uninsured, possibly unlawful sortie |
| Planner believed a placard | someone who can hang a sign | a route nobody approved, perfectly well formed |
| Footage to an unapproved host | a misconfiguration | site imagery on somebody else's storage |
| Redaction silently skipped | a library that failed to load | identifiable faces and plates leave the aircraft |
| Release over a car park | no attacker | the one on this list that injures somebody |
| Gusts outside release limits | weather | payload lands somewhere other than the pad |
| 2D GPS fix | no attacker | every vertical limit becomes unenforceable |
| Detector floor raised to 0.99 | a model update | a blind aircraft that reports a clean site |
| Logs cleared after an incident | an insider | the only record of what happened |
| Ceiling edited in the hangar | filesystem access | reports that say compliant while it is not |

`--only <id>` runs one with its full narration, `--list` shows the ids. Every
scenario is pinned by a test, because a demo that keeps printing its story after
the policy stops covering it is worse than no demo.

## Grade the policy, then grade the corpus

`prove.py` shows the policy cannot be tampered with. This shows it does what its
authors believe, and that somebody would notice if it stopped.

```bash
python packages/shield-mavlink/verify_policy.py
```

Three passes, and the third is the one that matters:

| Pass | Answers |
|---|---|
| **Score** | false negatives (attacks that flew) and false positives (legitimate work refused). A block count shows neither. |
| **Coverage** | which declared rules does the corpus actually exercise? A rule nothing tests can be deleted in a refactor with a green suite. |
| **Mutation** | weaken each rule on purpose. If the corpus does not notice, that rule was never defended, and the score was telling you nothing about it. |

Run against the shipped corpus it reports 119/119 cases, 103/103 rules
covered, 103/103 weakenings caught, across 17 subsystems. That third number is the claim: **delete any single rule from
this policy and a case fails.**

It found two real gaps the first time it ran, on a corpus already scoring 100
percent: `forbidden_fields.override_policy` and the lower bound on
`distance_from_home_m` were both declared and neither was defended. Both are now
covered, and the cases say in the file that mutation is what found them.

Rules and cases are both data, so the policy grows without touching code:

| File | Holds |
|---|---|
| `corpus/arm_policy.json` | 103 rules over 5 tools, each field tagged to a subsystem |
| `corpus/arm.json` | 119 labelled cases, each naming the rule that should refuse |

### Why five tools and not one

Arming checks subsystem **state** at a single moment. Camera capture, payload
release, upload and log erase all happen *after* that gate is finished, so an
arm check structurally cannot govern them. Each gets its own policy, on the same
engine, keyed by tool.

That distinction is what makes the subsystem report meaningful: the camera is
covered at arm time (is it working, is there storage) **and** at capture time
(is redaction on, are we over people).

Coverage is reported per subsystem, because "103 of 103 rules" answers a
question nobody asked and "is the camera governed" is the one they do:

| Subsystem | Rules | Governed at |
|---|---|---|
| route_planner | 12 | arm |
| camera | 11 | arm, camera_capture |
| logs_storage | 10 | arm, log_erase |
| network | 8 | arm, upload_media |
| payload | 8 | arm, payload_release |
| identity | 8 | all five tools |
| operator, weather, guard_defeat | 7 each | arm and the runtime tools |
| object_detector | 5 | arm |
| flight_controller, airspace, energy | 4 each | arm |
| gps | 3 | arm |
| airframe, annotation | 2 each | arm |
| radio_link | 1 | arm |

Every rule is attributed to a subsystem, and a test fails if one is not: an
unattributed rule cannot be reported on, so it is invisible to whoever is
deciding whether their fleet is covered.

`--bundle` grades a signed bundle rather than the shipped policy.

## Which hazard does this mitigate

```bash
python packages/shield-mavlink/verify_policy.py --hazards
```

Seventeen hazards, 103 rules, mapped in both directions and machine-checked.
Every rule names the hazard it mitigates; every hazard names what covers it, at
which gate, with the residual risk stated.

The residual is the part worth reading, because it says what is still uncovered:

> **H-01 Loss of containment of payload over people** (12 rules, at arm,
> camera_capture, payload_release)
> Shield refuses the release command when the arguments say people are below.
> It cannot detect people the detector missed, so this reduces the chance of an
> AUTHORIZED release over people, not the chance of people being present.

> **H-09 Degraded or spoofed navigation** (5 rules, at arm)
> Refuses on fix type, satellite count, HDOP and EKF status, which catches
> degradation. It CANNOT detect a well-formed spoofed fix: that is
> estimator-level and outside anything Shield can see.

Every hazard also lists what else mitigates it, because claiming sole mitigation
of something PX4 covers too is a false claim by omission.

Tests fail the build rather than warn. A rule with no hazard, a hazard with no
rules, a mapping for a rule that was renamed, a residual under forty characters,
or hazard metadata leaking into a signed bundle: all are build failures. This is
the artefact most likely to be quoted at a regulator, and its value is entirely
in being complete.

## What it does not prove

Stated because a proof that overclaims is worth less than a narrow one.

- It does **not** prove the aircraft recorded every decision it made. Nothing
  running only on that aircraft can; a compromised process could decide and stay
  silent. Central checkpointing on sync closes it.
- It does **not** authenticate MAVLink. An attacker on the same network can spoof
  the authorizer, because unsigned MAVLink permits that. MAVLink 2 signing is the
  separate answer.

## Modules

| Module | Needs | Purpose |
|---|---|---|
| `shield_mavlink/bundle.py` | `cryptography` | sign, verify, pin, expire |
| `shield_mavlink/audit.py` | stdlib only | hash-chained decision log |

Neither imports `mavsdk`, so both run on a machine with no drone SDK installed.
