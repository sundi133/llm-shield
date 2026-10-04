"""Convert the existing attack corpora into the red-team harness's JSONL format.

Spec: docs/specs/redteam-tenant-harness.md, section 3.

Sources:
  guardrails-red-team-suite/NN_<industry>.sh   run_test '<id>' '<name>' 'block|safe' '<json>'
  advbench.json, harmbench.json                 [{"id", "category", "bucket", "prompt"}]

Each suite payload carries an inline "input" block that turns guards on for that
one request. The server only honours it when the tenant has no config of its own,
so keeping it would make an unconfigured tenant look covered: the payload would
switch on the very guard whose absence the harness exists to find. Only the
message is kept; the guard names go into "guards_hint" for dormant labelling.

Usage:
  python redteam/convert_corpora.py [--suite-dir guardrails-red-team-suite]
      [--benchmark advbench.json] [--benchmark harmbench.json] [--out redteam/corpus]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# One single-quoted bash word; a quote inside is written '\'' by the generator.
_WORD = r"'((?:[^']|'\\'')*)'"
_RUN_TEST = re.compile(r"^run_test " + " ".join([_WORD] * 4), re.MULTILINE)
_SECTION = re.compile(r'^section "([^"]*)"', re.MULTILINE)
_VARIANT = re.compile(r"\s+variant\s+\d+\s*$", re.IGNORECASE)


def _unquote(word: str) -> str:
    return word.replace("'\\''", "'")


def _industry(path: str) -> str:
    base = os.path.splitext(os.path.basename(path))[0]
    return re.sub(r"^\d+_", "", base)


def convert_suite_file(path: str) -> list[dict]:
    """Every run_test in one suite script, in file order, as harness cases."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    industry = _industry(path)
    marks = [(m.start(), "section", m.group(1)) for m in _SECTION.finditer(text)]
    marks += [(m.start(), "test", m) for m in _RUN_TEST.finditer(text)]
    marks.sort(key=lambda x: x[0])

    cases, section = [], ""
    for _, kind, val in marks:
        if kind == "section":
            section = val
            continue
        case_id, name, expected, raw = (_unquote(g) for g in val.groups())
        try:
            body = json.loads(raw)
        except ValueError as e:
            raise ValueError(f"{path}: {case_id}: payload is not JSON ({e})") from None
        message = body.get("message")
        if not isinstance(message, str) or not message:
            raise ValueError(f"{path}: {case_id}: payload has no message")
        attack = expected == "block"
        cases.append({
            "id": case_id,
            "threat_class": "prompt-injection" if attack else "benign",
            "stage": "input",
            "payload": {"message": message},
            "expect": "block" if attack else "allow",
            "technique": _VARIANT.sub("", name),
            "section": section,
            "source": f"guardrails-red-team-suite/{industry}",
            "guards_hint": sorted((body.get("input") or {}).keys()),
        })
    return cases


def convert_benchmark_file(path: str) -> list[dict]:
    """advbench.json / harmbench.json: harmful requests that should be blocked."""
    with open(path, encoding="utf-8") as f:
        rows = json.load(f)
    name = os.path.splitext(os.path.basename(path))[0]
    cases = []
    for row in rows:
        if row.get("bucket") != "harmful":
            raise ValueError(f"{path}: {row.get('id')}: unexpected bucket {row.get('bucket')!r}")
        cases.append({
            "id": f"{name}:{row['id']}",
            "threat_class": "harmful-content",
            "stage": "input",
            "payload": {"message": row["prompt"]},
            "expect": "block",
            "technique": row.get("category", ""),
            "source": name,
        })
    return cases


def write_jsonl(path: str, cases: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for case in cases:
            f.write(json.dumps(case, ensure_ascii=False, sort_keys=True) + "\n")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--suite-dir", default=os.path.join(ROOT, "guardrails-red-team-suite"))
    ap.add_argument("--benchmark", action="append", default=[],
                    help="advbench.json / harmbench.json style file (repeatable)")
    ap.add_argument("--out", default=os.path.join(ROOT, "redteam", "corpus"))
    args = ap.parse_args(argv)

    os.makedirs(args.out, exist_ok=True)
    total = 0
    suite = sorted(f for f in os.listdir(args.suite_dir) if re.match(r"^\d+_.*\.sh$", f))
    for fname in suite:
        cases = convert_suite_file(os.path.join(args.suite_dir, fname))
        out = os.path.join(args.out, f"suite-{_industry(fname)}.jsonl")
        write_jsonl(out, cases)
        total += len(cases)
        print(f"{fname}: {len(cases)} cases -> {os.path.relpath(out, ROOT)}")
    for path in args.benchmark:
        cases = convert_benchmark_file(path)
        out = os.path.join(args.out, os.path.splitext(os.path.basename(path))[0] + ".jsonl")
        write_jsonl(out, cases)
        total += len(cases)
        print(f"{os.path.basename(path)}: {len(cases)} cases -> {os.path.relpath(out, ROOT)}")
    print(f"total: {total} cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
