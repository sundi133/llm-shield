#!/usr/bin/env python3
"""Quick validation: run_test lines are parseable."""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main() -> int:
    pat = re.compile(
        r"^run_test '([^']*)' '([^']*)' '([^']*)' '(.+)'$",
    )
    alt = re.compile(
        r"^run_test '((?:[^']|'\"'\"')*)' '((?:[^']|'\"'\"')*)' '((?:[^']|'\"'\"')*)' '(.+)'$",
    )
    for sh in sorted(ROOT.glob("*.sh")):
        if sh.name.startswith("generate"):
            continue
        lines = [ln for ln in sh.read_text(encoding="utf-8").splitlines() if ln.startswith("run_test ")]
        if len(lines) < 1000:
            print("FAIL", sh.name, "count", len(lines))
            return 1
        for i, line in enumerate(lines[:20]):
            m = pat.match(line)
            if not m:
                m = alt.match(line)
            if not m:
                print("FAIL parse", sh.name, i, line[:120])
                return 1
            try:
                json.loads(m.group(4))
            except json.JSONDecodeError as e:
                print("FAIL json", sh.name, i, e)
                return 1
        print("OK", sh.name, "lines", len(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
