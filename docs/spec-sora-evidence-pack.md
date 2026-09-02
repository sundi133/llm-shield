---
title: "Spec: SORA evidence pack"
layout: default
nav_order: 67
permalink: /spec-sora-evidence-pack/
description: "Emit the artefact a safety assessor can actually use. Maps rules and hazards onto SORA Operational Safety Objectives, states the assurance level claimed, and refuses to overstate."
---

# Spec: SORA evidence pack
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

The product can say: 17 hazards, 103 rules, every rule mapped, every rule
defended by mutation, decisions signed and recorded. That is a good engineering
answer to a question no buyer is asking.

What blocks a drone operator from the missions that pay is **approval**. BVLOS,
flight over people, operations at scale: each needs an operational safety case,
and building one is expensive because the evidence does not exist in a form an
assessor can consume. Our output today is a rule count. An assessor works in
Operational Safety Objectives, and cannot use a rule count at all.

So the gap is a translation gap, not a capability gap. The evidence exists. It
is addressed in our vocabulary instead of theirs.

### What SORA actually wants

SORA (JARUS, adopted by EASA and increasingly referenced elsewhere) assigns an
operation a SAIL, and each SAIL demands a set of **Operational Safety Objectives**
at a stated **robustness**, which is the pair (integrity, assurance):

- **Integrity** is how good the mitigation is.
- **Assurance** is how well you have shown that it is that good.

The second is where software vendors usually fail, and it is the half this
product is unusually well placed to supply. Mutation-verified rules, signed
policy, and a tamper-evident decision log are assurance evidence. Nobody has to
take our word for the integrity claim, which is the whole point.

### The outcome

A generated evidence pack, per fleet, that an assessor or a consultant can read
without knowing anything about this product:

1. **Per OSO**: which of our controls contribute, what they do, the robustness
   claimed, and the evidence that supports the claim, each item runnable or
   inspectable.
2. **Per hazard**: unchanged from the traceability work, carried through so the
   two documents reconcile.
3. **What we do not claim**: OSOs this product does not touch, stated as such.

Observable success conditions:

- `python evidence_pack.py --fleet inspection-north` emits a dated document with
  every claim traceable to a rule, a test, or a runnable command.
- Every OSO claim names its evidence; a claim with none fails generation.
- An OSO the product does not address is listed as not addressed, not omitted.
- Regenerating from an unchanged policy produces a byte-identical pack, so a
  reviewer can diff two revisions and see only what changed.

### Non-goals

- **Not a safety case.** The operational safety case belongs to the operator and
  covers ground risk, air risk, containment, and much that no software touches.
  This is one input to it.
- **Not a certification claim.** Nothing here is DO-178C, and the document must
  not be phrased so anyone could read it that way.
- **Not a SAIL determination.** Which SAIL an operation lands in depends on the
  operation, not the software. The pack states what it supports at each level,
  never which level the operator qualifies for.
- **Not legal or regulatory advice.** The pack is evidence about software
  behaviour. The argument built on it is the operator's, reviewed by people
  qualified to make it.
- **No new enforcement.** Reporting only. Nothing on the decision path.

## 2. Plane & latency contract

**Neither plane. A generator in `packages/shield-mavlink`.**

| Component | Change |
|---|---|
| Data plane | none |
| Admin plane | none |
| Aircraft decision path | **none.** OSO metadata is stripped from bundles exactly as hazard metadata already is |

**Off hot path, no guarded-traffic impact.** The pack is generated on a laptop or
in CI, from files already in the repository.

## 3. Data model

Additive to `corpus/arm_policy.json`, next to `hazards` and `rule_hazards`.

### `oso_claims`

```json
"oso_claims": {
  "OSO-08": {
    "title": "Operational procedures are defined, validated and adhered to",
    "contributes": ["H-07", "H-08", "H-16"],
    "what_we_do": "Refuses to arm when the declared operation is outside the authorised procedure: uncertified operator, unapproved or unuploaded mission, airframe overdue for service.",
    "integrity": "medium",
    "assurance": "medium",
    "assurance_basis": [
      "Each rule is exercised by a labelled case (corpus/arm.json)",
      "Weakening any rule fails a case (verify_policy.py mutation pass)",
      "Enforcement runs from a signed bundle; a tampered policy refuses to start (prove.py act 2)"
    ],
    "limits": "Adherence is checked against values the caller declares. Shield does not verify that a certificate exists in the operator's records, only that the call asserts a valid one."
  }
}
```

`limits` is mandatory and is the field this document lives or dies on. See §5.

### `oso_not_addressed`

```json
"oso_not_addressed": {
  "OSO-05": "Concerns UAS design and airworthiness. No software policy layer contributes to it."
}
```

Every OSO in the reference list must appear in exactly one of the two maps. A
missing OSO is indistinguishable from an overlooked one, and an assessor reading
a pack with holes in it will assume the holes are the interesting part.

### `fleets`

```json
"fleets": {
  "inspection-north": {
    "operation": "Utility asset inspection, VLOS and EVLOS, populated area transit under approval",
    "jurisdiction": "UK CAA",
    "airframes": ["quad_x500", "hex_survey"]
  }
}
```

The pack is per fleet because the operation determines which OSOs matter, and one
document covering every operation an operator runs is a document covering none
of them well.

## 4. API / interface

No endpoints.

```
python evidence_pack.py --fleet inspection-north            # markdown to stdout
python evidence_pack.py --fleet inspection-north --out pack.md
python evidence_pack.py --check                             # CI: claims complete
```

### Pack structure

```
1  Scope and limitations          what this is, what it is not, in that order
2  The system under evidence      version, policy digest, bundle signing key id
3  OSO coverage summary           table: OSO, contributes, integrity, assurance
4  Per-OSO detail                 claim, basis, limits, how to verify
5  Hazard register                carried from the traceability work
6  Not addressed                  OSOs this product does not touch, with reasons
7  How to reproduce               commands that regenerate every claim
```

**Scope and limitations comes first, before any claim.** An assessor who reads
the limitations after the claims has already formed a view, and a pack that
buries its caveats reads as advocacy rather than evidence.

### Reproducibility

The pack embeds the policy digest and the corpus digest, and regenerating from
unchanged inputs is byte-identical. A reviewer diffing two revisions sees the
change, not a re-rendering. This matters more than it sounds: an assessor
returning after six months needs to know what moved.

## 5. Security & backward compatibility

**Nothing changes for anyone.** Additive metadata plus a generator. No default
change, no schema migration, nothing on any decision path.

### The overstatement problem, which is the whole risk

Every other document in this repository fails by being wrong about software.
This one fails by being wrong about **what somebody is allowed to fly**, and the
failure is silent: nobody discovers an overstated assurance claim until the
event it was supposed to have covered.

Four rules follow, and they are enforced in §8 rather than left to good
intentions:

- **`limits` is mandatory on every claim, and the generator refuses without it.**
  It must say what the control does not do. "None" is not an acceptable value.
- **Assurance claims must name evidence that can be run or read.** A basis item
  is a file path, a test name, or a command. Prose alone is not a basis.
- **We never claim high assurance we cannot support.** A claim of `high` requires
  a basis item that is independent of us, and today there is none, so the
  generator caps assurance at `medium` and says so in the pack. That cap is a
  feature: an uncapped generator would happily print the strongest claim its
  author typed.
- **The pack states the SAIL it does not determine.** It says what it supports,
  never what the operator qualifies for.

### Why the cap matters commercially as well as ethically

An assessor who finds one inflated claim discounts the entire document, and the
second submission is harder than the first. A pack that visibly refuses to
overstate is worth more than one that claims more, which is an unusual position
for a sales artefact and the correct one here.

## 6. Packaging & deploy

- **`Dockerfile.admin`:** untouched.
- **Dependencies:** none. JSON in, markdown out.
- **Bundle hygiene:** `oso_claims`, `oso_not_addressed` and `fleets` are stripped
  at bundle generation with the rest of the documentation metadata, covered by
  the existing test.

## 7. Failure modes & edge cases

| Condition | Behaviour | Rationale |
|---|---|---|
| OSO claim with no `limits` | generation fails | the field the whole document rests on |
| `limits` of "none" or under 40 characters | generation fails | a real limitation is hard to state in ten characters |
| Assurance basis with no runnable or readable reference | generation fails | prose is not evidence |
| Claim of `high` assurance | generation fails | no independent basis exists today; the cap is deliberate |
| OSO in neither map | generation fails | a hole reads as an oversight, and an assessor will assume the worst |
| OSO in both maps | generation fails | contradictory |
| Claim references an undefined hazard | generation fails | dangling reference reads as coverage |
| Hazard referenced by a claim but covered by no rule | generation fails | the claim would rest on nothing |
| Fleet not defined | generation fails with the list of known fleets | a pack for an unnamed operation means nothing |
| Policy changed since the corpus last passed | **warn loudly in the pack itself** | an assessor must see that the evidence and the policy may have diverged |

**Fail-closed on documentation.** Every row above stops generation rather than
warning, except the last, which must appear in the artefact because that is where
the reader is.

## 8. Test plan (Definition of Done)

`tests/test_sora_evidence_pack.py`:

1. Every OSO in the reference list is in exactly one map.
2. Every claim has `contributes`, `what_we_do`, `integrity`, `assurance`,
   `assurance_basis`, `limits`.
3. Every `limits` is over 40 characters and is not a variant of "none".
4. Every `assurance_basis` item resolves: a file that exists, a test that is
   collected, or a command whose script is present.
5. No claim asserts `high` assurance.
6. Every hazard referenced by a claim exists and has at least one rule.
7. Every `oso_not_addressed` entry gives a reason over 40 characters.
8. Generation is deterministic: two runs over unchanged inputs are identical.
9. The pack contains the policy digest and the corpus digest.
10. Scope and limitations appear before the first claim in the output.

**Regression guards:**

11. Every hazard in the register is referenced by at least one OSO claim, or
    listed as contributing to none with a reason. A hazard we mitigate but
    cannot attach to an objective is a signal the objective list is incomplete.
12. OSO metadata never reaches a signed bundle, alongside the existing hazard
    check.

**Not automated:** whether the claims are *correct*. That needs somebody
qualified in the framework, and §9 says so.

## 9. What this cannot do, stated in the spec so it reaches the pack

The generator can enforce that a claim is complete, evidenced, and not
overstated. It cannot tell whether the claim is *right*: whether refusing an arm
on a declared certificate genuinely satisfies OSO-08 at medium integrity is a
judgement belonging to somebody who does this professionally.

The honest positioning is that this produces a **reviewable first draft** with
the evidence already attached, replacing a blank page and a fortnight of
consultant time. It does not replace the consultant, and a pack claiming
otherwise would be the exact overstatement §5 exists to prevent.

## Invariant risks

| Invariant | Risk | Mitigation |
|---|---|---|
| Off the hot path | **None.** Generator, run in CI or by hand | nothing on any decision path |
| `Dockerfile.admin` allowlist | **None.** No new admin import | tooling lives in the package |
| Declare dependencies | **None** | JSON and stdlib |
| Secure by default, non-breaking | **None.** Additive metadata | no behaviour change |

## Task breakdown

**PR 1. The OSO reference list and the not-addressed map.** Enumerate the
objectives, and record which this product does not touch and why. Tests 1, 7.

*Deliberately first. Writing down what we do not cover, before writing a single
claim, sets the tone of the artefact and is the part most likely to be skipped
if it comes last.*

**PR 2. Claims for the objectives we do support.** With `limits` on every one.
Tests 2, 3, 4, 5, 6, 11.

**PR 3. The generator.** Markdown out, deterministic, digests embedded, scope
first. Tests 8, 9, 10.

**PR 4. Bundle hygiene and CI.** `--check` in the suite. Test 12.

## Open questions

1. **Which SORA revision?** The OSO list and robustness tables differ between
   2.0 and 2.5, and an operator working to one will not accept a pack written
   against the other. Probably needs to be a parameter rather than a constant.
2. **Who reviews the claims?** §9 says a qualified person must. Whether that is
   a partner, a customer's own consultant, or somebody hired here changes what
   the product is selling.
3. **Does `integrity` belong to us at all?** Assurance is evidence about our own
   behaviour and is clearly ours to claim. Integrity is a judgement about how
   good the mitigation is in a specific operation, and that may not be ours to
   assert at any level.
4. **Per fleet or per operation?** A fleet can fly several operations with
   different objectives. Modelling on fleet is simpler and may be wrong.
5. **What happens when SORA moves?** The pack embeds claims against a framework
   that revises. Stale claims presented as current are the overstatement problem
   arriving by a slower route.
