"""Grade a policy against a labelled corpus, and then grade the corpus.

prove.py answers "can this be tampered with". It is deliberately small, because
its value is that a sceptic reads all of it. This answers the harder question,
and it is the one an engineer cannot wave away as standard technique:

    does this policy do what its authors believe, and would anybody notice
    if it stopped?

Three passes, each answering something the previous cannot.

    SCORE       run the corpus. False negatives are attacks that got through;
                false positives are legitimate work refused, which is how
                guardrails end up switched off. A block count shows neither.

    COVERAGE    which declared rules does the corpus actually exercise? A rule
                nothing tests is a rule that can be deleted, weakened, or broken
                in a refactor with a green suite. Aggregate scores hide this
                completely: a corpus can score 100 percent while testing a third
                of the policy.

    MUTATION    weaken each rule on purpose and re-run. If the corpus still
                passes, that rule is not really tested and the score was
                telling you nothing about it. This is the pass that grades the
                CORPUS rather than the policy, and it is the one that makes the
                other two trustworthy.

Mutation is the load-bearing idea. Anyone can write rules; anyone can write
cases. Knowing whether the cases would catch the rules regressing is a
different problem, and it is the one that compounds: a corpus that survives
mutation is an asset that keeps its value as the policy changes underneath it.

    python verify_policy.py                     # the shipped arm corpus
    python verify_policy.py --bundle b.json     # against a signed bundle
    python verify_policy.py --no-mutation       # score and coverage only
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

from shield_mavlink.policy import LocalPolicy  # noqa: E402

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "corpus" / "arm.json"
POLICY_FILE = HERE / "corpus" / "arm_policy.json"

def load_policy(path: Path = POLICY_FILE) -> dict[str, Any]:
    """Rules are data. The policy an aircraft flies is a file, not a literal."""
    d = json.loads(path.read_text())
    return {"parameter_policies": d["parameter_policies"]}


@dataclass
class Score:
    passed: int = 0
    false_negatives: list[str] = field(default_factory=list)   # attack got through
    false_positives: list[tuple[str, str]] = field(default_factory=list)
    wrong_rule: list[tuple[str, str, str]] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not (self.false_negatives or self.false_positives)


def load_corpus(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def case_params(corpus: dict, case: dict) -> dict[str, Any]:
    """Baseline with the case applied.

    `set` assigns values, `unset` removes fields. They are separate because
    overloading null to mean "absent" made it impossible to write a case for a
    field whose value legitimately is null, and made "missing required field"
    cases silently depend on which fields the loader special-cased.
    """
    params = dict(corpus["baseline"])
    for k in case.get("unset", []):
        params.pop(k, None)
    params.update(case.get("set", {}))
    return params


def score(policy: LocalPolicy, corpus: dict) -> Score:
    s = Score()
    for case in corpus["cases"]:
        v = policy.check("arm", case_params(corpus, case))
        expected_deny = case["expect"] == "deny"

        if expected_deny and v.blocked:
            s.passed += 1
            want = case.get("rule")
            if want and v.rule != want:
                # Refused for the wrong reason. It still blocks, so the score
                # looks fine, but the operator gets a misleading message and the
                # case is not testing the rule its author thought it was.
                s.wrong_rule.append((case["id"], want, v.rule))
        elif not expected_deny and v.allowed:
            s.passed += 1
        elif expected_deny and v.allowed:
            s.false_negatives.append(case["id"])
        else:
            s.false_positives.append((case["id"], v.reason))
    return s


def declared_rules(policy_dict: dict, tool: str = "arm") -> list[tuple[str, str]]:
    """Every (family, field) the policy declares. The denominator for coverage."""
    p = policy_dict["parameter_policies"][tool]
    out: list[tuple[str, str]] = []
    for f in p.get("required_fields", []):
        out.append(("required", f))
    for f in p.get("forbidden_fields", []):
        out.append(("forbidden", f))
    for f in p.get("allowed_values", {}):
        out.append(("allowed_values", f))
    for f, lim in p.get("numeric_limits", {}).items():
        if lim.get("min") is not None:
            out.append(("min", f))
        if lim.get("max") is not None:
            out.append(("max", f))
    for f in p.get("regex_rules", {}):
        out.append(("regex", f))
    for f in p.get("max_string_lengths", {}):
        out.append(("max_length", f))
    return out


def coverage(policy: LocalPolicy, policy_dict: dict, corpus: dict
             ) -> tuple[set[tuple[str, str]], list[tuple[str, str]]]:
    """Which declared rules does any case actually trip?"""
    hit: set[tuple[str, str]] = set()
    for case in corpus["cases"]:
        v = policy.check("arm", case_params(corpus, case))
        if v.blocked:
            hit.add((v.rule, v.field))
    declared = declared_rules(policy_dict)
    return hit, [r for r in declared if r not in hit]


def mutations(policy_dict: dict, tool: str = "arm") -> Iterator[tuple[str, dict]]:
    """Weaken one rule at a time, the way a careless edit or refactor would.

    Every mutation makes the policy MORE permissive. A corpus that does not
    notice is a corpus that would not notice the same change in production.
    """
    p = policy_dict["parameter_policies"][tool]

    for f, lim in p.get("numeric_limits", {}).items():
        if lim.get("max") is not None:
            m = copy.deepcopy(policy_dict)
            m["parameter_policies"][tool]["numeric_limits"][f]["max"] = 10 ** 9
            yield f"numeric_limits.{f}.max removed", m
        if lim.get("min") is not None:
            m = copy.deepcopy(policy_dict)
            m["parameter_policies"][tool]["numeric_limits"][f]["min"] = -(10 ** 9)
            yield f"numeric_limits.{f}.min removed", m

    for f in list(p.get("allowed_values", {})):
        m = copy.deepcopy(policy_dict)
        del m["parameter_policies"][tool]["allowed_values"][f]
        yield f"allowed_values.{f} dropped", m

    for i, f in enumerate(p.get("required_fields", [])):
        m = copy.deepcopy(policy_dict)
        m["parameter_policies"][tool]["required_fields"] = [
            x for x in p["required_fields"] if x != f]
        yield f"required_fields.{f} dropped", m

    for f in list(p.get("forbidden_fields", [])):
        m = copy.deepcopy(policy_dict)
        m["parameter_policies"][tool]["forbidden_fields"] = [
            x for x in p["forbidden_fields"] if x != f]
        yield f"forbidden_fields.{f} dropped", m

    for f in list(p.get("regex_rules", {})):
        m = copy.deepcopy(policy_dict)
        m["parameter_policies"][tool]["regex_rules"][f] = ".*"
        yield f"regex_rules.{f} weakened to .*", m

    for f in list(p.get("max_string_lengths", {})):
        m = copy.deepcopy(policy_dict)
        m["parameter_policies"][tool]["max_string_lengths"][f] = 10 ** 9
        yield f"max_string_lengths.{f} removed", m


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", help="signed bundle to grade instead of the default")
    ap.add_argument("--pubkey", help="pinned key, required with --bundle")
    ap.add_argument("--corpus", default=str(CORPUS))
    ap.add_argument("--no-mutation", action="store_true")
    args = ap.parse_args()

    corpus = load_corpus(Path(args.corpus))

    if args.bundle:
        if not args.pubkey:
            print("--bundle needs --pubkey: grading policy nobody verified proves nothing")
            return 2
        from shield_mavlink.bundle import BundleError, load_and_verify
        try:
            policy_dict = load_and_verify(args.bundle, args.pubkey,
                                          expect_tenant="bankco",
                                          expect_fleet="inspection-north")
        except BundleError as e:
            print(f"bundle rejected: {e}")
            return 3
    else:
        policy_dict = load_policy()

    policy = LocalPolicy(policy_dict)
    rules = declared_rules(policy_dict)

    print(f"corpus  {corpus['corpus']}: {len(corpus['cases'])} cases")
    print(f"policy  {len(rules)} declared rules across "
          f"{len({r[0] for r in rules})} families\n")

    # ── 1. score ───────────────────────────────────────────────────────────
    s = score(policy, corpus)
    print(f"SCORE      {s.passed}/{len(corpus['cases'])} cases correct")
    for cid in s.false_negatives:
        print(f"  MISS         {cid}: expected a refusal, the request was allowed")
    for cid, why in s.false_positives:
        print(f"  FALSE ALARM  {cid}: legitimate request refused ({why})")
    for cid, want, got in s.wrong_rule:
        print(f"  WRONG RULE   {cid}: expected {want!r}, refused by {got!r}. "
              f"Blocks, but the operator is told the wrong thing")
    if s.clean and not s.wrong_rule:
        print("           no misses, no false alarms, every refusal for the stated reason")

    # ── 2. coverage ────────────────────────────────────────────────────────
    hit, untested = coverage(policy, policy_dict, corpus)
    print(f"\nCOVERAGE   {len(rules) - len(untested)}/{len(rules)} declared rules exercised")
    for family, fieldname in untested:
        print(f"  UNTESTED     {family}.{fieldname}: no case trips this. It could be "
              f"deleted and the suite stays green")
    if not untested:
        print("           every declared rule is exercised by at least one case")

    # ── 3. mutation ────────────────────────────────────────────────────────
    if args.no_mutation:
        return 0 if s.clean else 1

    print("\nMUTATION   weakening each rule in turn; the corpus should notice")
    survived: list[str] = []
    total = 0
    for label, mutated in mutations(policy_dict):
        total += 1
        ms = score(LocalPolicy(mutated), corpus)
        if ms.clean:
            survived.append(label)
    caught = total - len(survived)
    print(f"           {caught}/{total} weakenings caught by the corpus")
    for label in survived:
        print(f"  SURVIVED     {label}: the corpus does not notice. That rule is "
              f"declared but not defended")

    print()
    if s.clean and not untested and not survived:
        print("This policy does what its corpus says, every rule is exercised, and")
        print("weakening any one of them breaks a case. The score means something.")
    else:
        print("The score alone would have looked fine. Coverage and mutation are")
        print("what turn it into evidence.")
    return 0 if (s.clean and not survived) else 1


if __name__ == "__main__":
    raise SystemExit(main())
