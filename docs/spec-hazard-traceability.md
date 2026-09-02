---
title: "Spec: hazard to rule traceability"
layout: default
nav_order: 66
permalink: /spec-hazard-traceability/
description: "Every rule states which hazard it mitigates, and every hazard names the rules that cover it. The first artefact a safety assessor asks for, and the cheapest one to produce."
---

# Spec: hazard to rule traceability
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

The policy has 103 rules over 5 tools, tagged to 17 subsystems, every one
exercised by a case and defended against mutation. That answers "do the rules
work". It does not answer the question a safety assessor opens with:

> Which hazard does this mitigate, and how do you know the set is complete?

Today the answer lives in prose, in commit messages, and in the heads of whoever
wrote the rules. `payload_release` refuses when `wind_ms` exceeds 8 while flight
permits 10, and the reason (release limits are tighter than flight limits) is a
comment in a corpus case. That is a fine comment and a poor safety argument.

The gap is not evidence. It is that the evidence is not addressable: nobody can
ask "show me everything that mitigates loss of containment of the payload" and
get an answer.

### Why this is the cheap step

The expensive path to mission-critical is a verified core in a language with
bounded execution, which is months and only pays off if a customer is blocked on
it. This is weeks, and it is what an operational safety case is actually made of.

Under SORA, and under most operational-approval routes, what earns credit is a
demonstrated mitigation with evidence behind it, not certified avionics. A
guardrail that measurably reduces a hazard can lower the assurance demanded of
other mitigations. To claim that, the hazard has to be named.

### The outcome

Two directions, both machine-checked:

1. **Rule to hazard.** Every rule declares the hazard it mitigates. A rule that
   cannot name one is either unnecessary or the hazard list is incomplete, and
   both are worth knowing.
2. **Hazard to rules.** Every hazard lists what covers it, at which gate, with
   the residual risk stated. A hazard with no rules is an admitted gap rather
   than an oversight.

Observable success conditions:

- `verify_policy.py` reports coverage by hazard as it already does by subsystem.
- A rule added without a hazard fails CI.
- A hazard declared with nothing behind it fails CI, unless explicitly marked
  as accepted with a reason.
- The residual risk for each hazard is written down, including "none of this
  helps" where that is true.

### Non-goals

- **Not a SORA submission.** This produces an input to one. The operational
  safety case is the customer's, and it covers far more than software.
- **Not a claim of certification.** Nothing here is DO-178C or an equivalent,
  and the document must not be phrased so it could be read that way.
- **No new enforcement.** Purely descriptive: metadata plus reporting plus tests.
  Zero effect on any decision the aircraft makes.
- **Not a risk quantification.** Severity and likelihood scoring belongs to the
  operator's own assessment, which knows their airspace and their operation.
  Claiming a number here would be inventing one.

## 2. Plane & latency contract

**Neither plane. This is data and tooling.**

| Component | Change |
|---|---|
| Data plane | none |
| Admin plane | none |
| `packages/shield-mavlink` | a `hazards` block in the policy file, plus reporting |
| Aircraft decision path | **none.** The metadata is never read at decision time |

**Off hot path, no guarded-traffic impact.** The hazard block is stripped from
the bundle the aircraft receives, or ignored by the evaluator. An aircraft
carrying documentation it never reads is weight; more importantly, metadata that
reached the decision path could change a decision, and this must not be able to.

## 3. Data model

No Redis. Two additions to `corpus/arm_policy.json`, which is already the
authoring surface for rules.

### `hazards`

```json
"hazards": {
  "H-01": {
    "title": "Loss of containment of payload over people",
    "description": "An object leaves the aircraft above an area occupied by people not under the operator's control.",
    "severity_class": "catastrophic",
    "mitigated_by_others": ["PX4 geofence", "operational site survey"],
    "residual": "Shield refuses the release command. It cannot detect people the detector missed, so this reduces the chance of an authorized release over people, not of people being present."
  }
}
```

`severity_class` is a label the operator maps onto their own scheme, not a score
this project invents. `residual` is required and is the field most likely to be
written carelessly; §8 tests that it is not empty and §5 explains why it matters
more than the mitigation claim.

### `rule_hazards`

Maps a rule to the hazards it mitigates. Keyed the way rules are already
identified in coverage output, so the two reports line up:

```json
"rule_hazards": {
  "payload_release.allowed_values.over_people": ["H-01"],
  "payload_release.max.wind_ms":                ["H-01", "H-04"],
  "arm.min.operator_cert_days_remaining":       ["H-07"]
}
```

A rule may mitigate several hazards, and a hazard is normally covered by several
rules across several gates. Both directions are derived from this one table.

### Accepted gaps

```json
"accepted_gaps": {
  "H-09": "GNSS spoofing is estimator-level. Shield can refuse to act on incoherent sensor claims, which is arm.allowed_values.gps_fix_type, but cannot detect a well-formed spoofed fix. Accepted; mitigated elsewhere or not at all."
}
```

Without this, the only way to make CI green is to delete an inconvenient hazard,
which is the exact failure mode the spec exists to prevent.

## 4. API / interface

No endpoints. Tooling only.

```
python verify_policy.py --hazards      # coverage by hazard, both directions
python verify_policy.py                # unchanged; hazard summary appended
```

Report shape, matching the existing subsystem block:

```
HAZARDS
     H-01  Loss of containment over people      4 rules  payload_release, arm
     H-04  Release in conditions outside limits 3 rules  payload_release
  !! H-09  GNSS spoofing                        0 rules  ACCEPTED GAP
```

The `!!` marker already exists for subsystem gaps and is reused, so an operator
reading either report reads the same convention.

## 5. Security & backward compatibility

**Nothing changes for anyone.** Additive metadata in a file that is already
authored by hand. No default changes, no schema migration, no behaviour change.

**The metadata must not reach the aircraft.** Stripped at bundle generation. Two
reasons, and the second is the one that matters: it is dead weight on a
companion computer, and anything the evaluator can read is something that could
one day influence a decision. A hazard note is documentation, and documentation
that can change enforcement is a defect waiting to be written.

### The honest-claim problem

This document is the one most likely to be quoted at a regulator, which makes
its failure mode different from the rest of the repo. An overstated mitigation
does not cause a bug; it causes somebody to fly on an assumption that was never
true.

Three rules follow from that:

- **`residual` is mandatory and must say what is still uncovered.** A residual
  reading "none" is almost always wrong and should be treated as unfinished.
- **`mitigated_by_others` must be populated where it applies.** Claiming sole
  mitigation of a hazard PX4 also covers is a false claim by omission.
- **`accepted_gaps` is a first-class outcome, not a failure.** A hazard nothing
  covers, stated plainly, is more useful to an assessor than a rule stretched to
  claim coverage it does not provide.

## 6. Packaging & deploy

- **`Dockerfile.admin`:** untouched. No new `admin_app.py` import.
- **Dependencies:** none. JSON and the existing tooling.
- **Bundle generation:** must strip `hazards`, `rule_hazards`, and
  `accepted_gaps`, and a test asserts the stripped bundle is byte-identical to
  one generated from a policy that never had them. Otherwise the signature
  covers documentation, and editing a comment invalidates every aircraft's
  policy.

## 7. Failure modes & edge cases

| Condition | Behaviour | Rationale |
|---|---|---|
| Rule with no hazard | CI fails | either unnecessary or the hazard list is short |
| Hazard with no rules, not accepted | CI fails | an uncovered hazard must be a decision, not an oversight |
| Hazard with no rules, in `accepted_gaps` | reported, CI passes | the honest outcome, and it needs a route that is not deletion |
| Hazard id referenced but undefined | CI fails | a dangling reference reads as coverage and is not |
| `residual` empty or absent | CI fails | the field most likely to be skipped and most load-bearing |
| Hazard block present in a generated bundle | CI fails | documentation must not reach the decision path |
| Rule renamed, mapping stale | CI fails on the dangling rule key | the mapping is keyed on rule identity, so drift surfaces |

**Fail-closed on documentation, which is unusual and deliberate.** A missing
hazard mapping breaks the build rather than warning. A warning would be ignored,
and the value of this artefact is entirely in its completeness.

## 8. Test plan (Definition of Done)

`tests/test_hazard_traceability.py`:

1. Every declared rule appears in `rule_hazards`.
2. Every hazard id referenced by a rule is defined in `hazards`.
3. Every defined hazard has at least one rule, or an entry in `accepted_gaps`.
4. Every hazard has a non-empty `residual` and `description`.
5. Every accepted gap names the hazard and gives a reason longer than a token.
6. No hazard is both covered and listed as an accepted gap.
7. A generated bundle contains no hazard metadata, and is byte-identical to one
   built from a policy stripped of it beforehand.
8. `--hazards` output lists every hazard exactly once, covered or accepted.

**Regression guard:**

9. The rule keys in `rule_hazards` match `declared_rules` exactly, in both
   directions. This is the coupling that rots: rules get renamed, mappings do
   not, and a stale mapping reads as coverage.

**Green bar:** full suite in a clean venv, CI `pytest` gate passing.

## Invariant risks

| Invariant | Risk | Mitigation |
|---|---|---|
| Off the hot path | **None.** Metadata, never read at decision time | stripped from the bundle, asserted by test 7 |
| `Dockerfile.admin` allowlist | **None.** No new admin import | tooling lives in the package |
| Declare dependencies | **None.** No new dependency | JSON only |
| Secure by default, non-breaking | **None.** Additive metadata | no behaviour change anywhere |

## Task breakdown

**PR 1. The hazard list.** Author `hazards` for the ten scenarios in
`scenarios.py`, which are already written as operational failures and are the
natural seed. Tests 4, 5, 8.

**PR 2. The mapping.** `rule_hazards` for all 103 rules, `accepted_gaps` for
what nothing covers. Tests 1, 2, 3, 6, 9.

*This is the PR where the real work is, and where uncovered hazards surface.*

**PR 3. Reporting.** `--hazards`, and the summary appended to the default run.

**PR 4. Bundle hygiene.** Strip metadata at generation. Test 7.

## Open questions

1. **How many hazards is the right number?** Ten scenarios seed it, but a real
   list for an inspection operation is plausibly thirty to fifty. Too few and
   the mapping is trivially satisfied; too many and it is never finished.
2. **Whose severity scheme?** SORA, ARP4761, and an operator's internal register
   do not share vocabulary. Carrying a label rather than a score avoids picking,
   but an assessor may want the mapping made explicit.
3. **Should hazards be per-fleet?** An inspection operation and a delivery
   operation have different registers, and a single shared list will fit neither
   well. Probably a base list plus per-fleet additions, but that is a data-model
   decision worth making deliberately rather than discovering.
4. **Does the residual field need review workflow?** It is the field most likely
   to be written optimistically by the person who wrote the rule, and a
   self-reviewed residual risk statement is worth less than an assessed one.
