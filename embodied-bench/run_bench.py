#!/usr/bin/env python3
"""Score a guard endpoint against the embodied guardrail benchmark.

Standard library only, so this runs anywhere without touching requirements.txt.

  # validate the corpus without calling anything
  python embodied-bench/run_bench.py --dry-run

  # score the Shield evaluator in process, no server (needs the Shield repo)
  python embodied-bench/run_bench.py --local embodied-bench/shield_profile.json

  # score a live endpoint
  python embodied-bench/run_bench.py \
      --endpoint https://shield.internal/v1/shield/embodied/check \
      --api-key "$SHIELD_TENANT_KEY" --tenant doh

The endpoint contract this assumes (adjust --verdict-path / --rail-path if yours
differs): POST the `event` object, get back JSON containing a verdict of
"block" | "pass" | "require_approval" and optionally the rail that fired.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import urllib.error
import urllib.request
from collections import Counter, defaultdict

CORPUS = pathlib.Path(__file__).with_name("embodied_guardrail_bench.jsonl")
VERDICTS = {"block", "pass", "require_approval"}


def load(path: pathlib.Path) -> list[dict]:
    cases = []
    for n, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            cases.append(json.loads(line))
        except json.JSONDecodeError as e:
            sys.exit(f"{path}:{n}: invalid JSON: {e}")
    return cases


def validate(cases: list[dict]) -> list[str]:
    """Structural checks. A corpus that lies about itself is worse than none."""
    errs = []
    ids = Counter(c.get("id") for c in cases)
    for cid, n in ids.items():
        if n > 1:
            errs.append(f"duplicate id: {cid}")
    by_id = {c["id"]: c for c in cases}
    for c in cases:
        cid = c.get("id", "<no id>")
        for field in ("id", "class", "severity", "platform", "setting", "event", "expected"):
            if field not in c:
                errs.append(f"{cid}: missing field '{field}'")
        exp = c.get("expected", {})
        if exp.get("verdict") not in VERDICTS:
            errs.append(f"{cid}: verdict {exp.get('verdict')!r} not in {sorted(VERDICTS)}")
        if exp.get("verdict") != "pass" and not exp.get("rail"):
            errs.append(f"{cid}: non-pass case must name the rail expected to fire")
        if exp.get("verdict") == "pass" and exp.get("rail"):
            errs.append(f"{cid}: benign case must not name a rail")
        pair = c.get("pair")
        if pair:
            if pair not in by_id:
                errs.append(f"{cid}: pair {pair} not in corpus")
            elif by_id[pair].get("pair") != cid:
                errs.append(f"{cid}: pair {pair} does not point back")
    return errs


def call(endpoint: str, event: dict, headers: dict, timeout: float) -> dict:
    req = urllib.request.Request(
        endpoint,
        data=json.dumps(event).encode(),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def dig(obj, dotted: str):
    for part in dotted.split("."):
        if isinstance(obj, dict) and part in obj:
            obj = obj[part]
        else:
            return None
    return obj


def load_local(profile_path: pathlib.Path):
    """The Shield evaluator as a function of the event. Imported from the Shield
    checkout this corpus lives in; the evaluator is standard library only."""
    root = pathlib.Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from core.embodied.evaluator import evaluate
    from core.embodied.model import validate_profile
    profile = validate_profile(json.loads(profile_path.read_text()))
    return lambda event: evaluate(profile, event)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", type=pathlib.Path, default=CORPUS)
    ap.add_argument("--endpoint")
    ap.add_argument("--api-key")
    ap.add_argument("--tenant")
    ap.add_argument("--verdict-path", default="verdict",
                    help="dotted path to the verdict in the response (default: verdict)")
    ap.add_argument("--rail-path", default="rail",
                    help="dotted path to the rail name in the response (default: rail)")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--dry-run", action="store_true", help="validate only, call nothing")
    ap.add_argument("--local", type=pathlib.Path, metavar="PROFILE",
                    help="score the Shield evaluator in process with this action profile "
                         "(no server; run from a Shield checkout)")
    ap.add_argument("--filter-class", help="only run cases whose class contains this string")
    args = ap.parse_args()

    cases = load(args.corpus)
    errs = validate(cases)
    if errs:
        print("CORPUS INVALID")
        for e in errs:
            print("  -", e)
        return 2

    if args.filter_class:
        cases = [c for c in cases if args.filter_class in c["class"]]

    attack = [c for c in cases if c["expected"]["verdict"] != "pass"]
    benign = [c for c in cases if c["expected"]["verdict"] == "pass"]
    print(f"corpus ok: {len(cases)} cases  |  {len(attack)} attack/gated  "
          f"|  {len(benign)} benign controls")

    if args.dry_run or not (args.endpoint or args.local):
        if not args.endpoint and not args.dry_run:
            print("no --endpoint given; validated only. Pass --endpoint to score.")
        by_setting = Counter(c["setting"] for c in cases)
        by_platform = Counter(c["platform"] for c in cases)
        print("  settings :", dict(by_setting))
        print("  platforms:", dict(by_platform))
        return 0

    headers = {}
    if args.api_key:
        headers["X-API-Key"] = args.api_key
    if args.tenant:
        headers["X-Tenant-ID"] = args.tenant

    local = load_local(args.local) if args.local else None
    results, errors = [], []
    for c in cases:
        try:
            resp = (local(c["event"]) if args.local
                    else call(args.endpoint, c["event"], headers, args.timeout))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            errors.append((c["id"], repr(e)))
            continue
        got_verdict = dig(resp, args.verdict_path)
        got_rail = dig(resp, args.rail_path)
        exp = c["expected"]
        verdict_ok = got_verdict == exp["verdict"]
        # rail is scored separately: catching the right thing for the wrong reason
        # still leaves you blind when the scenario shifts.
        rail_ok = (exp["rail"] is None) or (got_rail == exp["rail"])
        results.append({"case": c, "verdict_ok": verdict_ok, "rail_ok": rail_ok,
                        "got_verdict": got_verdict, "got_rail": got_rail})

    scored = [r for r in results]
    a = [r for r in scored if r["case"]["expected"]["verdict"] != "pass"]
    b = [r for r in scored if r["case"]["expected"]["verdict"] == "pass"]

    caught = sum(1 for r in a if r["verdict_ok"])
    right_rail = sum(1 for r in a if r["verdict_ok"] and r["rail_ok"])
    fp = sum(1 for r in b if not r["verdict_ok"])

    print()
    print("=" * 62)
    print(f"  caught          {caught}/{len(a)}"
          f"   ({caught / len(a) * 100:.0f}%)" if a else "  caught          n/a")
    print(f"  correct rail    {right_rail}/{len(a)}" if a else "")
    print(f"  false positives {fp}/{len(b)}"
          f"   ({fp / len(b) * 100:.0f}%)" if b else "  false positives n/a")
    if errors:
        print(f"  endpoint errors {len(errors)}")
    print("=" * 62)

    misses = [r for r in scored if not r["verdict_ok"]]
    if misses:
        print("\nMISSES")
        for r in misses:
            c = r["case"]
            print(f"  {c['id']}  {c['class']}")
            print(f"      expected {c['expected']['verdict']}, got {r['got_verdict']}")
            if c["pair"]:
                print(f"      paired with {c['pair']}")

    wrong_rail = [r for r in scored if r["verdict_ok"] and not r["rail_ok"]]
    if wrong_rail:
        print("\nRIGHT VERDICT, WRONG RAIL")
        for r in wrong_rail:
            print(f"  {r['case']['id']}  expected {r['case']['expected']['rail']}, "
                  f"got {r['got_rail']}")

    if errors:
        print("\nENDPOINT ERRORS")
        for cid, e in errors:
            print(f"  {cid}: {e}")

    # per-class breakdown
    per = defaultdict(lambda: [0, 0])
    for r in scored:
        k = r["case"]["class"]
        per[k][1] += 1
        per[k][0] += int(r["verdict_ok"])
    print("\nPER CLASS")
    for k in sorted(per):
        ok, n = per[k]
        print(f"  {ok}/{n}  {k}")

    return 0 if (not misses and not errors) else 1


if __name__ == "__main__":
    raise SystemExit(main())
