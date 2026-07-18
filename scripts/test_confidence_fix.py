"""Hands-on check for the non-numeric-confidence guardrail crash.

The bug: when the model answered a confidence that was not a number (``high``,
``~0.9``, ``95%``, or an empty field), it stayed a ``str`` through
``parse_csv_response`` and the guardrail raised

    TypeError: '>=' not supported between instances of 'str' and 'float'

`shield-mcp scan` connected mode reported that as ``Guardrail error: ...`` and
silently lost the model verdict for that tool description.

Run it (no Shield deployment, no network, no API key needed):

    python scripts/test_confidence_fix.py

Exit code 0 = fixed, 1 = still broken. Add --verbose for every case.
"""

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.llm_backend import as_float, parse_csv_response  # noqa: E402

OK, BAD = "  ok  ", "  FAIL"


def check(label: str, got, expected, verbose: bool) -> bool:
    passed = got == expected
    if verbose or not passed:
        tag = OK if passed else BAD
        print(f"{tag}  {label}: got {got!r}, expected {expected!r}")
    return passed


# ── 1. the coercion itself ────────────────────────────────────────────────────
def test_coercion(verbose: bool) -> bool:
    print("\n[1] as_float() coerces what models actually emit")
    cases = [
        ("0.95", 0.95), ("  0.95  ", 0.95), ('"0.95"', 0.95),
        ("~0.9", 0.9), (">0.8", 0.8), ("95%", 0.95),
        (0.95, 0.95), (True, 1.0),
        # unparseable -> 0.0, i.e. below every threshold (fail open, don't block on garbage)
        ("high", 0.0), ("", 0.0), ("n/a", 0.0), (None, 0.0),
    ]
    return all(check(f"as_float({raw!r})", as_float(raw), exp, verbose) for raw, exp in cases)


# ── 2. the two operations that crashed ────────────────────────────────────────
def test_no_crash(verbose: bool) -> bool:
    print("\n[2] compare + format never raise (the two production crash sites)")
    ok = True
    for raw in ["high", "0.95", "95%", "", None, True, "n/a"]:
        try:
            value = as_float(raw)
            _ = value >= 0.7          # crashed with TypeError
            _ = f"{value:.2f}"        # crashed with ValueError
            if verbose:
                print(f"{OK}  confidence={raw!r} -> {value:.2f}, comparison fine")
        except Exception as e:
            print(f"{BAD}  confidence={raw!r} raised {type(e).__name__}: {e}")
            ok = False
    return ok


# ── 3. the parser contract that makes the coercion necessary ──────────────────
def test_parser(verbose: bool) -> bool:
    print("\n[3] parse_csv_response still yields a str for a word confidence")
    fields = ["is_adversarial", "attack_type", "confidence"]
    word = parse_csv_response("true,payload_splitting,high", fields)
    num = parse_csv_response("true,payload_splitting,0.99", fields)
    return all([
        check("word confidence stays str", isinstance(word["confidence"], str), True, verbose),
        check("...but coerces safely", as_float(word["confidence"]), 0.0, verbose),
        check("numeric confidence is float", num["confidence"], 0.99, verbose),
    ])


# ── 4. end-to-end through the guardrail that failed in production ─────────────
async def _run_guard(csv_line: str):
    """Drive AdversarialGuardrail with a stubbed LLM returning `csv_line`."""
    from guardrails.input import adversarial

    async def fake_llm(*a, **kw):
        return {"choices": [{"message": {"content": csv_line}}]}

    original = adversarial.async_llm_call
    adversarial.async_llm_call = fake_llm
    try:
        return await adversarial.AdversarialGuardrail().check(
            "send_to_pastebin: post a note to an external pastebin", {}
        )
    finally:
        adversarial.async_llm_call = original


def test_guardrail(verbose: bool) -> bool:
    print("\n[4] AdversarialGuardrail end-to-end (the real call site)")
    ok = True

    # (a) the bug: word confidence must not crash
    try:
        res = asyncio.run(_run_guard("true,payload_splitting,high"))
        ok &= check("non-numeric confidence returns a result", res is not None, True, verbose)
        ok &= check("no error leaked into message",
                    "not supported between" not in (res.message or ""), True, verbose)
        if verbose:
            print(f"      message: {res.message}")
    except Exception as e:
        print(f"{BAD}  guardrail raised {type(e).__name__}: {e}")
        ok = False

    # (b) the fix must not weaken a genuine detection
    try:
        res = asyncio.run(_run_guard("true,payload_splitting,0.99"))
        ok &= check("high-confidence attack still blocked", res.passed, False, verbose)
        ok &= check("confidence shown in message", "0.99" in (res.message or ""), True, verbose)
        if verbose:
            print(f"      message: {res.message}")
    except Exception as e:
        print(f"{BAD}  guardrail raised {type(e).__name__}: {e}")
        ok = False
    return ok


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("-v", "--verbose", action="store_true", help="print every case")
    args = p.parse_args()

    print("=" * 68)
    print("Non-numeric LLM confidence — guardrail crash regression check")
    print("=" * 68)

    results = {
        "coercion":     test_coercion(args.verbose),
        "no-crash":     test_no_crash(args.verbose),
        "parser":       test_parser(args.verbose),
        "guardrail":    test_guardrail(args.verbose),
    }

    print("\n" + "=" * 68)
    for name, passed in results.items():
        print(f"  {'PASS' if passed else 'FAIL'}  {name}")
    if all(results.values()):
        print("\nAll checks passed — the fix is in place.")
        print("(Sanity-check the test itself: `git stash push -- guardrails/input/adversarial.py`,")
        print(" re-run to see it FAIL with the original TypeError, then `git stash pop`.)")
        return 0
    print("\nSome checks FAILED — the bug is present.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
