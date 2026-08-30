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

Run against the shipped corpus it reports 67/67 cases, 55/55 rules covered,
55/55 weakenings caught. That third number is the claim: **delete any single rule from
this policy and a case fails.**

It found two real gaps the first time it ran, on a corpus already scoring 100
percent: `forbidden_fields.override_policy` and the lower bound on
`distance_from_home_m` were both declared and neither was defended. Both are now
covered, and the cases say in the file that mutation is what found them.

Rules and cases are both data, so the policy grows without touching code:

| File | Holds |
|---|---|
| `corpus/arm_policy.json` | 55 pre-flight rules across 7 families |
| `corpus/arm.json` | 67 labelled cases, each naming the rule that should refuse |

The rules cover identity and attribution, the flags that exist only to defeat a
guard, pre-flight vehicle state (GPS fix quality, EKF, compass, RC link),
energy including per-cell voltage, geometry including RTL altitude, navigation
quality, weather, airframe service state, and operator certification. Every one
has a case, and weakening any one of them breaks that case.

`--bundle` grades a signed bundle rather than the shipped policy.

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
