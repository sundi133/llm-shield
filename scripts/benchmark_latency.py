"""
Votal Shield Latency Benchmark
===============================
Tests LLM latency directly at various input token sizes.
No Shield admin needed — hits LiteLLM/OpenAI endpoint directly.

Two test modes:
  1. LLM only        — direct /v1/chat/completions (no guardrails)
  2. LLM + guardrails — /v1/chat/completions with guardrails param (if supported)

Usage:
  export LLM_BASE_URL=https://litellm-guardrails-votal-ai-production.up.railway.app/v1
  export LLM_MASTER_KEY=sk-my-master-key-xxx
  export LLM_MODEL=moonshotai/kimi-k2.5

  .venv/bin/python scripts/benchmark_latency.py
"""

import json
import os
import sys
import time

import requests

# ── Config ────────────────────────────────────────────────────────
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://litellm-guardrails-votal-ai-production.up.railway.app/v1")
LLM_MASTER_KEY = os.getenv("LLM_MASTER_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "moonshotai/kimi-k2.5")

TOKEN_SIZES = [512, 1024, 4096, 8192, 32768, 65536]
RUNS_PER_SIZE = 3

HEADERS = {
    "Content-Type": "application/json",
}
if LLM_MASTER_KEY:
    HEADERS["Authorization"] = f"Bearer {LLM_MASTER_KEY}"


# ── Helpers ───────────────────────────────────────────────────────

def generate_text(approx_tokens: int) -> str:
    """Generate text of approximately the given token count (~4 chars/token)."""
    base = (
        "The customer has requested a review of their account details "
        "including transaction history, balance information, and recent "
        "wire transfers. Please look up the profile and provide a summary. "
    )
    chars_needed = approx_tokens * 4
    repeats = max(1, chars_needed // len(base))
    return (base * repeats)[:chars_needed]


def percentile(data, p):
    if not data:
        return 0
    s = sorted(data)
    k = (len(s) - 1) * (p / 100)
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (k - f) * (s[c] - s[f])


def call_llm(message: str, guardrails: list = None) -> dict:
    """Call LLM endpoint. Returns timing + usage info."""
    body = {
        "model": LLM_MODEL,
        "messages": [
            {"role": "user", "content": message},
        ],
        "max_tokens": 256,
        "temperature": 0.3,
    }
    if guardrails:
        body["guardrails"] = guardrails

    start = time.perf_counter()
    try:
        resp = requests.post(
            f"{LLM_BASE_URL}/chat/completions",
            headers=HEADERS,
            json=body,
            timeout=300,
        )
        ms = (time.perf_counter() - start) * 1000
        try:
            data = resp.json()
        except Exception:
            data = {"_raw": resp.text[:300]}

        usage = data.get("usage", {})
        return {
            "latency_ms": round(ms, 2),
            "status": resp.status_code,
            "prompt_tokens": usage.get("prompt_tokens", 0),
            "completion_tokens": usage.get("completion_tokens", 0),
            "total_tokens": usage.get("total_tokens", 0),
            "error": data.get("error", {}).get("message", "") if resp.status_code >= 400 else "",
        }
    except Exception as e:
        ms = (time.perf_counter() - start) * 1000
        return {"latency_ms": round(ms, 2), "status": "err", "error": str(e)}


# ── Main benchmark ────────────────────────────────────────────────

def run_benchmark():
    print("=" * 90)
    print("  Votal Shield Latency Benchmark — LLM Direct")
    print("=" * 90)
    print(f"  LLM Endpoint:    {LLM_BASE_URL}")
    print(f"  Model:           {LLM_MODEL}")
    print(f"  Auth:            {'Bearer ***' + LLM_MASTER_KEY[-4:] if LLM_MASTER_KEY else '(none)'}")
    print(f"  Runs per size:   {RUNS_PER_SIZE}")
    print(f"  Token sizes:     {TOKEN_SIZES}")
    print("=" * 90)

    # Health check
    print("  Checking connectivity...", end=" ", flush=True)
    test = call_llm("Hello", [])
    if test["status"] == 200:
        print(f"OK ({test['latency_ms']:.0f}ms)")
    else:
        print(f"WARNING: status={test['status']} error={test.get('error', '')[:100]}")
        print("  Continuing anyway...\n")

    all_results = []

    for token_size in TOKEN_SIZES:
        print(f"\n{'━' * 90}")
        print(f"  {token_size:,} tokens (~{token_size * 4 // 1024}KB)")
        print(f"{'━' * 90}")

        message = generate_text(token_size)

        no_guard_times = []
        with_guard_times = []

        for run in range(RUNS_PER_SIZE):
            print(f"  Run {run + 1}/{RUNS_PER_SIZE}:", end=" ", flush=True)

            # Test 1: LLM without guardrails
            r1 = call_llm(message)
            no_guard_times.append(r1["latency_ms"])
            status1 = f"tokens={r1.get('total_tokens', '?')}" if r1["status"] == 200 else f"err={r1.get('error', '')[:40]}"
            print(f"no_guard={r1['latency_ms']:.0f}ms({status1})", end="  ", flush=True)

            # Test 2: LLM with guardrails
            r2 = call_llm(message, guardrails=["votal-input-guard", "votal-output-guard"])
            with_guard_times.append(r2["latency_ms"])
            status2 = f"tokens={r2.get('total_tokens', '?')}" if r2["status"] == 200 else f"err={r2.get('error', '')[:40]}"
            overhead = r2["latency_ms"] - r1["latency_ms"]
            print(f"with_guard={r2['latency_ms']:.0f}ms({status2})  overhead={overhead:+.0f}ms")

        no_p50 = round(percentile(no_guard_times, 50))
        no_p95 = round(percentile(no_guard_times, 95))
        wd_p50 = round(percentile(with_guard_times, 50))
        wd_p95 = round(percentile(with_guard_times, 95))
        overhead_ms = wd_p50 - no_p50
        overhead_pct = round((overhead_ms / max(no_p50, 1)) * 100)

        row = {
            "tokens": token_size,
            "no_guard_p50": no_p50,
            "no_guard_p95": no_p95,
            "with_guard_p50": wd_p50,
            "with_guard_p95": wd_p95,
            "overhead_ms": overhead_ms,
            "overhead_pct": overhead_pct,
        }
        all_results.append(row)

    # ── Summary Table ─────────────────────────────────────────────
    print(f"\n{'=' * 90}")
    print("  RESULTS SUMMARY")
    print(f"{'=' * 90}")
    print(f"  {'Tokens':>8} │ {'Without Guardrails':>20}  │ {'With Guardrails':>20}  │ {'Overhead':>14}")
    print(f"  {'':>8} │ {'P50':>10} {'P95':>9} │ {'P50':>10} {'P95':>9} │ {'ms':>7} {'%':>5}")
    print(f"  {'─' * 8}─┼─{'─' * 20}──┼─{'─' * 20}──┼─{'─' * 14}")
    for r in all_results:
        print(
            f"  {r['tokens']:>8,} │ "
            f"{r['no_guard_p50']:>8}ms {r['no_guard_p95']:>7}ms │ "
            f"{r['with_guard_p50']:>8}ms {r['with_guard_p95']:>7}ms │ "
            f"{r['overhead_ms']:>+6}ms {r['overhead_pct']:>4}%"
        )

    # ── Overhead visual ───────────────────────────────────────────
    print(f"\n{'=' * 90}")
    print("  GUARDRAIL OVERHEAD")
    print(f"{'=' * 90}")
    for r in all_results:
        pct = r["overhead_pct"]
        bar_len = min(50, max(1, abs(pct) // 2))
        bar = "█" * bar_len if pct > 0 else "░" * bar_len
        print(f"  {r['tokens']:>8,} tokens: {bar} {pct:+d}% ({r['overhead_ms']:+d}ms)")

    # ── Save results ──────────────────────────────────────────────
    output_file = "benchmark_results.json"
    with open(output_file, "w") as f:
        json.dump({
            "config": {
                "llm_base_url": LLM_BASE_URL,
                "model": LLM_MODEL,
                "runs_per_size": RUNS_PER_SIZE,
                "token_sizes": TOKEN_SIZES,
            },
            "results": all_results,
        }, f, indent=2)
    print(f"\n  Results saved to {output_file}")


if __name__ == "__main__":
    run_benchmark()
