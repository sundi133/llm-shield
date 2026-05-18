"""
Votal Shield Latency Benchmark
===============================
Tests latency WITH and WITHOUT guardrails at various input token sizes.

Three test modes:
  1. Guardrails only     — /guardrails/input + /guardrails/output
  2. LLM only            — /v1/shield/chat/agent (no shield_endpoint)
  3. Full pipeline        — /v1/shield/chat/agent (with shield_endpoint)

Usage:
  export SHIELD_URL=http://localhost:8080
  export API_KEY=your-tenant-key
  export AGENT_KEY=customer-service-agent
  export USER_ROLE=branch_manager
  export LLM_BASE_URL=https://your-litellm-proxy/v1
  export LLM_MASTER_KEY=sk-xxx
  export LLM_MODEL=kimi-k2.5
  export SHIELD_ENDPOINT=http://172.148.110.30:8080  # guardrail server

  python scripts/benchmark_latency.py
"""

import json
import os
import sys
import time

import requests

# ── Config ────────────────────────────────────────────────────────
SHIELD_URL = os.getenv("SHIELD_URL", "http://localhost:8080")
API_KEY = os.getenv("API_KEY", "")
AGENT_KEY = os.getenv("AGENT_KEY", "customer-service-agent")
USER_ROLE = os.getenv("USER_ROLE", "branch_manager")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "")
LLM_MASTER_KEY = os.getenv("LLM_MASTER_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "")
SHIELD_ENDPOINT = os.getenv("SHIELD_ENDPOINT", "")
SHIELD_TOKEN = os.getenv("SHIELD_TOKEN", "")

TOKEN_SIZES = [512, 1024, 4096, 8192, 32768, 65536]
RUNS_PER_SIZE = 3

HEADERS = {
    "X-API-Key": API_KEY,
    "X-Agent-Key": AGENT_KEY,
    "X-User-Role": USER_ROLE,
    "Content-Type": "application/json",
}


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


def timed_post(url, json_body, timeout=300):
    """POST with timing. Returns (latency_ms, status, response_dict)."""
    start = time.perf_counter()
    try:
        resp = requests.post(url, headers=HEADERS, json=json_body, timeout=timeout)
        ms = (time.perf_counter() - start) * 1000
        try:
            data = resp.json()
        except Exception:
            data = {"_raw": resp.text[:200]}
        return round(ms, 2), resp.status_code, data
    except Exception as e:
        ms = (time.perf_counter() - start) * 1000
        return round(ms, 2), "err", {"error": str(e)}


# ── Test functions ────────────────────────────────────────────────

def test_guardrails_only(message: str) -> dict:
    """Test 1: Input + Output guardrails only (no LLM call)."""
    # Input guardrails
    in_ms, in_status, in_data = timed_post(
        f"{SHIELD_URL}/guardrails/input",
        {"message": message},
    )
    # Output guardrails (use same text as simulated output)
    out_text = message[:16000]  # cap output size
    out_ms, out_status, out_data = timed_post(
        f"{SHIELD_URL}/guardrails/output",
        {"output": out_text},
    )
    return {
        "input_ms": in_ms,
        "output_ms": out_ms,
        "total_ms": round(in_ms + out_ms, 2),
        "input_status": in_status,
        "output_status": out_status,
        "input_action": in_data.get("action", "?"),
        "output_action": out_data.get("action", "?"),
    }


def test_llm_only(message: str) -> dict:
    """Test 2: Agent chat WITHOUT guardrails (no shield_endpoint)."""
    body = {
        "messages": [{"role": "user", "content": message}],
        "agent_key": AGENT_KEY,
        "user_role": USER_ROLE,
    }
    if LLM_BASE_URL:
        body["llm_base_url"] = LLM_BASE_URL
        body["llm_model"] = LLM_MODEL
        if LLM_MASTER_KEY:
            body["llm_master_key"] = LLM_MASTER_KEY
    # No shield_endpoint = no guardrails
    ms, status, data = timed_post(f"{SHIELD_URL}/v1/shield/chat/agent", body)
    return {
        "total_ms": ms,
        "status": status,
        "tool_calls": len(data.get("tool_calls", [])),
        "server_ms": data.get("latency_ms", 0),
        "prompt_tokens": (data.get("usage") or {}).get("prompt_tokens", 0),
        "completion_tokens": (data.get("usage") or {}).get("completion_tokens", 0),
    }


def test_full_pipeline(message: str) -> dict:
    """Test 3: Agent chat WITH guardrails (shield_endpoint set)."""
    body = {
        "messages": [{"role": "user", "content": message}],
        "agent_key": AGENT_KEY,
        "user_role": USER_ROLE,
    }
    if LLM_BASE_URL:
        body["llm_base_url"] = LLM_BASE_URL
        body["llm_model"] = LLM_MODEL
        if LLM_MASTER_KEY:
            body["llm_master_key"] = LLM_MASTER_KEY
    if SHIELD_ENDPOINT:
        body["shield_endpoint"] = SHIELD_ENDPOINT
        if SHIELD_TOKEN:
            body["shield_token"] = SHIELD_TOKEN
    ms, status, data = timed_post(f"{SHIELD_URL}/v1/shield/chat/agent", body)
    return {
        "total_ms": ms,
        "status": status,
        "tool_calls": len(data.get("tool_calls", [])),
        "blocked": data.get("blocked", False) or data.get("has_blocked_tools", False),
        "server_ms": data.get("latency_ms", 0),
        "prompt_tokens": (data.get("usage") or {}).get("prompt_tokens", 0),
        "completion_tokens": (data.get("usage") or {}).get("completion_tokens", 0),
    }


# ── Main benchmark ────────────────────────────────────────────────

def run_benchmark():
    print("=" * 90)
    print("  Votal Shield Latency Benchmark — WITH vs WITHOUT Guardrails")
    print("=" * 90)
    print(f"  Shield Admin:    {SHIELD_URL}")
    print(f"  Shield Guard:    {SHIELD_ENDPOINT or '(not set — full pipeline test will skip guardrails)'}")
    print(f"  LLM:             {LLM_MODEL or 'server default'} @ {LLM_BASE_URL or 'server default'}")
    print(f"  Agent:           {AGENT_KEY} / {USER_ROLE}")
    print(f"  Runs per size:   {RUNS_PER_SIZE}")
    print(f"  Token sizes:     {TOKEN_SIZES}")
    print("=" * 90)

    # Health check
    try:
        r = requests.get(f"{SHIELD_URL}/health", timeout=5)
        print(f"  Health:          {r.status_code} OK")
    except Exception as e:
        print(f"  Health:          FAILED ({e})")
        sys.exit(1)

    all_results = []

    for token_size in TOKEN_SIZES:
        print(f"\n{'━' * 90}")
        print(f"  {token_size:,} tokens (~{token_size * 4 // 1024}KB)")
        print(f"{'━' * 90}")

        message = generate_text(token_size)

        guard_times = []
        llm_times = []
        full_times = []

        for run in range(RUNS_PER_SIZE):
            print(f"  Run {run + 1}/{RUNS_PER_SIZE}:", end=" ", flush=True)

            # Test 1: Guardrails only
            g = test_guardrails_only(message)
            guard_times.append(g["total_ms"])
            print(f"guard={g['total_ms']:.0f}ms(in={g['input_ms']:.0f}+out={g['output_ms']:.0f})", end="  ", flush=True)

            # Test 2: LLM only (no guardrails)
            l = test_llm_only(message)
            llm_times.append(l["total_ms"])
            print(f"llm_only={l['total_ms']:.0f}ms", end="  ", flush=True)

            # Test 3: Full pipeline (guardrails + LLM)
            f = test_full_pipeline(message)
            full_times.append(f["total_ms"])
            overhead = f["total_ms"] - l["total_ms"]
            print(f"full={f['total_ms']:.0f}ms  overhead={overhead:+.0f}ms")

        row = {
            "tokens": token_size,
            "guard_p50": round(percentile(guard_times, 50)),
            "guard_p95": round(percentile(guard_times, 95)),
            "llm_p50": round(percentile(llm_times, 50)),
            "llm_p95": round(percentile(llm_times, 95)),
            "full_p50": round(percentile(full_times, 50)),
            "full_p95": round(percentile(full_times, 95)),
            "overhead_p50": round(percentile(full_times, 50) - percentile(llm_times, 50)),
            "overhead_pct": round(
                ((percentile(full_times, 50) - percentile(llm_times, 50))
                 / max(percentile(llm_times, 50), 1)) * 100
            ),
        }
        all_results.append(row)

    # ── Summary Table ─────────────────────────────────────────────
    print("\n" + "=" * 90)
    print("  RESULTS SUMMARY")
    print("=" * 90)
    print(f"  {'Tokens':>8} │ {'Guardrails':>12} {'':>6} │ {'LLM Only':>12} {'':>6} │ {'Full Pipeline':>12} {'':>6} │ {'Overhead':>10}")
    print(f"  {'':>8} │ {'P50':>12} {'P95':>6} │ {'P50':>12} {'P95':>6} │ {'P50':>12} {'P95':>6} │ {'ms':>6} {'%':>4}")
    print(f"  {'─' * 8}─┼─{'─' * 12}─{'─' * 6}─┼─{'─' * 12}─{'─' * 6}─┼─{'─' * 12}─{'─' * 6}─┼─{'─' * 6}─{'─' * 4}")
    for r in all_results:
        print(
            f"  {r['tokens']:>8,} │ "
            f"{r['guard_p50']:>10}ms {r['guard_p95']:>5}ms │ "
            f"{r['llm_p50']:>10}ms {r['llm_p95']:>5}ms │ "
            f"{r['full_p50']:>10}ms {r['full_p95']:>5}ms │ "
            f"{r['overhead_p50']:>+5}ms {r['overhead_pct']:>3}%"
        )

    # ── Guardrail overhead analysis ───────────────────────────────
    print(f"\n{'=' * 90}")
    print("  GUARDRAIL OVERHEAD ANALYSIS")
    print(f"{'=' * 90}")
    for r in all_results:
        bar_len = min(50, max(1, r["overhead_pct"] // 2))
        bar = "█" * bar_len
        print(f"  {r['tokens']:>8,} tokens: {bar} {r['overhead_pct']}% (+{r['overhead_p50']}ms)")

    # ── vLLM Recommendations ──────────────────────────────────────
    max_tested = max(r["tokens"] for r in all_results if r["full_p50"] > 0)
    print(f"\n{'=' * 90}")
    print("  vLLM OPTIMIZATION RECOMMENDATIONS (Qwen3-8B, single GPU)")
    print(f"{'=' * 90}")
    print(f"""
  Current settings:
    --max-model-len 8196          ← limits input to ~8K tokens
    --max-num-batched-tokens 8196
    --gpu-memory-utilization 0.85
    --enable-chunked-prefill      ← NOT SET (add this!)
    --performance-mode throughput  ← optimizes batch, not latency

  For latency-sensitive workloads:

  1. Add --enable-chunked-prefill
     Splits long prefills into chunks. Critical for >4K inputs.
     Without this, one 8K request blocks all other requests.

  2. Change --performance-mode latency (instead of throughput)
     Prioritizes individual request latency over batch throughput.

  3. Increase --gpu-memory-utilization 0.95
     More VRAM for KV cache. Safe with fp8 quantization.

  4. For >8K inputs: increase --max-model-len
     --max-model-len 32768 for 32K support
     --max-model-len 65536 for 64K (needs ~40GB+ VRAM)

  5. Reduce --max-num-seqs for lower latency
     --max-num-seqs 8 (instead of 24) reduces queue contention.

  Recommended launch command:
    python -m vllm.entrypoints.openai.api_server \\
      --model Qwen/Qwen3-8B \\
      --dtype bfloat16 \\
      --quantization fp8 \\
      --kv-cache-dtype fp8 \\
      --max-model-len 32768 \\
      --max-num-batched-tokens 8192 \\
      --max-num-seqs 12 \\
      --gpu-memory-utilization 0.95 \\
      --enable-prefix-caching \\
      --enable-chunked-prefill \\
      --performance-mode latency
""")

    # ── Save results ──────────────────────────────────────────────
    output_file = "benchmark_results.json"
    with open(output_file, "w") as f:
        json.dump({
            "config": {
                "shield_url": SHIELD_URL,
                "shield_endpoint": SHIELD_ENDPOINT,
                "agent_key": AGENT_KEY,
                "user_role": USER_ROLE,
                "llm_model": LLM_MODEL,
                "llm_base_url": LLM_BASE_URL,
                "runs_per_size": RUNS_PER_SIZE,
                "token_sizes": TOKEN_SIZES,
            },
            "results": all_results,
        }, f, indent=2)
    print(f"  Results saved to {output_file}")


if __name__ == "__main__":
    run_benchmark()
