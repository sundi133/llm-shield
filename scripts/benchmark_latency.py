"""
Votal Shield Latency Benchmark
===============================
Tests guardrail + LLM latency at various input token sizes.

Usage:
  export SHIELD_URL=http://localhost:8080
  export API_KEY=your-tenant-key
  export AGENT_KEY=customer-service-agent
  export USER_ROLE=branch_manager

  # Optional: override LLM settings
  export LLM_BASE_URL=https://your-litellm-proxy/v1
  export LLM_MASTER_KEY=sk-xxx
  export LLM_MODEL=moonshotai/kimi-k2.5

  python scripts/benchmark_latency.py
"""

import json
import os
import statistics
import sys
import time

import requests

# Config
SHIELD_URL = os.getenv("SHIELD_URL", "http://localhost:8080")
API_KEY = os.getenv("API_KEY", "")
AGENT_KEY = os.getenv("AGENT_KEY", "customer-service-agent")
USER_ROLE = os.getenv("USER_ROLE", "branch_manager")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "")
LLM_MASTER_KEY = os.getenv("LLM_MASTER_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "")
SHIELD_ENDPOINT = os.getenv("SHIELD_ENDPOINT", "")
SHIELD_TOKEN = os.getenv("SHIELD_TOKEN", "")

# Token sizes to test
TOKEN_SIZES = [512, 1024, 4096, 8192, 32768, 65536, 200000]
RUNS_PER_SIZE = 3  # Number of runs per token size for averaging

HEADERS = {
    "X-API-Key": API_KEY,
    "X-Agent-Key": AGENT_KEY,
    "X-User-Role": USER_ROLE,
    "Content-Type": "application/json",
}


def generate_text(approx_tokens: int) -> str:
    """Generate text of approximately the given token count.
    ~1 token ≈ 4 chars for English text."""
    base = (
        "The customer has requested a review of their account details "
        "including transaction history, balance information, and recent "
        "wire transfers. Please look up the profile and provide a summary. "
    )
    chars_needed = approx_tokens * 4
    repeats = max(1, chars_needed // len(base))
    text = (base * repeats)[:chars_needed]
    return text


def benchmark_input_guardrails(message: str) -> dict:
    """Test input guardrails latency."""
    start = time.perf_counter()
    try:
        resp = requests.post(
            f"{SHIELD_URL}/guardrails/input",
            headers=HEADERS,
            json={"message": message},
            timeout=120,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000
        data = resp.json()
        return {
            "latency_ms": round(elapsed_ms, 2),
            "status": resp.status_code,
            "action": data.get("action", "unknown"),
            "guardrail_count": len(data.get("guardrail_results", [])),
            "inference_time_ms": data.get("inference_time_ms", 0),
        }
    except Exception as e:
        elapsed_ms = (time.perf_counter() - start) * 1000
        return {"latency_ms": round(elapsed_ms, 2), "status": "error", "error": str(e)}


def benchmark_agent_chat(message: str) -> dict:
    """Test full agent chat (guardrails + LLM + RBAC + data policy)."""
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

    start = time.perf_counter()
    try:
        resp = requests.post(
            f"{SHIELD_URL}/v1/shield/chat/agent",
            headers=HEADERS,
            json=body,
            timeout=300,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000
        data = resp.json()
        return {
            "latency_ms": round(elapsed_ms, 2),
            "status": resp.status_code,
            "tool_calls": len(data.get("tool_calls", [])),
            "blocked": data.get("has_blocked_tools", False),
            "usage": data.get("usage", {}),
            "server_latency_ms": data.get("latency_ms", 0),
        }
    except Exception as e:
        elapsed_ms = (time.perf_counter() - start) * 1000
        return {"latency_ms": round(elapsed_ms, 2), "status": "error", "error": str(e)}


def benchmark_output_guardrails(text: str) -> dict:
    """Test output guardrails latency."""
    start = time.perf_counter()
    try:
        resp = requests.post(
            f"{SHIELD_URL}/guardrails/output",
            headers=HEADERS,
            json={"output": text},
            timeout=120,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000
        data = resp.json()
        return {
            "latency_ms": round(elapsed_ms, 2),
            "status": resp.status_code,
            "action": data.get("action", "unknown"),
        }
    except Exception as e:
        elapsed_ms = (time.perf_counter() - start) * 1000
        return {"latency_ms": round(elapsed_ms, 2), "status": "error", "error": str(e)}


def percentile(data, p):
    """Calculate percentile."""
    if not data:
        return 0
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * (p / 100)
    f = int(k)
    c = f + 1
    if c >= len(sorted_data):
        return sorted_data[f]
    return sorted_data[f] + (k - f) * (sorted_data[c] - sorted_data[f])


def run_benchmark():
    print("=" * 80)
    print("Votal Shield Latency Benchmark")
    print("=" * 80)
    print(f"Shield URL:      {SHIELD_URL}")
    print(f"Agent:           {AGENT_KEY}")
    print(f"Role:            {USER_ROLE}")
    print(f"LLM:             {LLM_MODEL or 'server default'}")
    print(f"Runs per size:   {RUNS_PER_SIZE}")
    print(f"Token sizes:     {TOKEN_SIZES}")
    print("=" * 80)

    # Check connectivity
    try:
        resp = requests.get(f"{SHIELD_URL}/health", timeout=5)
        print(f"Health check:    {resp.status_code}")
    except Exception as e:
        print(f"Health check:    FAILED ({e})")
        print("Cannot reach Shield server. Check SHIELD_URL.")
        sys.exit(1)

    results = []

    for token_size in TOKEN_SIZES:
        print(f"\n{'─' * 60}")
        print(f"Testing {token_size:,} tokens ({token_size * 4 / 1024:.0f} KB text)")
        print(f"{'─' * 60}")

        message = generate_text(token_size)
        actual_chars = len(message)
        approx_tokens = actual_chars // 4

        input_latencies = []
        chat_latencies = []
        output_latencies = []

        for run in range(RUNS_PER_SIZE):
            print(f"  Run {run + 1}/{RUNS_PER_SIZE}...", end=" ", flush=True)

            # Input guardrails
            ig = benchmark_input_guardrails(message)
            input_latencies.append(ig["latency_ms"])
            print(f"input={ig['latency_ms']:.0f}ms", end=" ", flush=True)

            # Agent chat (full pipeline)
            ac = benchmark_agent_chat(message)
            chat_latencies.append(ac["latency_ms"])
            print(f"chat={ac['latency_ms']:.0f}ms", end=" ", flush=True)

            # Output guardrails
            og = benchmark_output_guardrails(message[:min(len(message), 16000)])
            output_latencies.append(og["latency_ms"])
            print(f"output={og['latency_ms']:.0f}ms")

            if ig.get("error") or ac.get("error"):
                print(f"    errors: input={ig.get('error', 'ok')} chat={ac.get('error', 'ok')}")

        row = {
            "tokens": token_size,
            "chars": actual_chars,
            "input_p50": round(percentile(input_latencies, 50), 1),
            "input_p95": round(percentile(input_latencies, 95), 1),
            "input_p99": round(percentile(input_latencies, 99), 1),
            "chat_p50": round(percentile(chat_latencies, 50), 1),
            "chat_p95": round(percentile(chat_latencies, 95), 1),
            "chat_p99": round(percentile(chat_latencies, 99), 1),
            "output_p50": round(percentile(output_latencies, 50), 1),
            "output_p95": round(percentile(output_latencies, 95), 1),
            "output_p99": round(percentile(output_latencies, 99), 1),
        }
        results.append(row)

    # Print summary table
    print("\n" + "=" * 80)
    print("RESULTS SUMMARY")
    print("=" * 80)
    print(f"{'Tokens':>8} | {'Input P50':>10} {'P95':>8} {'P99':>8} | {'Chat P50':>10} {'P95':>8} {'P99':>8} | {'Output P50':>10} {'P95':>8} {'P99':>8}")
    print("-" * 100)
    for r in results:
        print(
            f"{r['tokens']:>8,} | "
            f"{r['input_p50']:>9.0f}ms {r['input_p95']:>7.0f}ms {r['input_p99']:>7.0f}ms | "
            f"{r['chat_p50']:>9.0f}ms {r['chat_p95']:>7.0f}ms {r['chat_p99']:>7.0f}ms | "
            f"{r['output_p50']:>9.0f}ms {r['output_p95']:>7.0f}ms {r['output_p99']:>7.0f}ms"
        )

    # vLLM optimization recommendations
    print("\n" + "=" * 80)
    print("vLLM OPTIMIZATION RECOMMENDATIONS (Qwen3-8B, single GPU)")
    print("=" * 80)
    print("""
1. --max-model-len
   Set to max input size you need. Default 32K for Qwen3-8B.
   Higher = more KV cache memory. Don't set higher than needed.
   For 200K: needs >80GB VRAM, likely need multi-GPU.

2. --enable-chunked-prefill
   CRITICAL for inputs >4K tokens. Splits prefill into chunks
   so it doesn't block decode of other requests.

3. --max-num-batched-tokens
   Controls max tokens processed in one batch step.
   Default: max-model-len. Set lower for better latency at
   cost of throughput. Try 4096 or 8192 for latency-sensitive.

4. --gpu-memory-utilization 0.95
   Use 95% of VRAM for KV cache. Default 0.9.

5. --enforce-eager
   Disable CUDA graph for long sequences. Saves memory,
   slight latency increase for short sequences.

6. --kv-cache-dtype fp8
   Half the KV cache memory. Allows 2x longer sequences.
   Needs GPU with fp8 support (H100, L40S, Ada).

Example vLLM launch for balanced latency/throughput:
  python -m vllm.entrypoints.openai.api_server \\
    --model Qwen/Qwen3-8B \\
    --max-model-len 32768 \\
    --enable-chunked-prefill \\
    --max-num-batched-tokens 8192 \\
    --gpu-memory-utilization 0.95 \\
    --tensor-parallel-size 1
""")

    # Save results to JSON
    output_file = "benchmark_results.json"
    with open(output_file, "w") as f:
        json.dump({
            "config": {
                "shield_url": SHIELD_URL,
                "agent_key": AGENT_KEY,
                "user_role": USER_ROLE,
                "llm_model": LLM_MODEL,
                "runs_per_size": RUNS_PER_SIZE,
            },
            "results": results,
        }, f, indent=2)
    print(f"Results saved to {output_file}")


if __name__ == "__main__":
    run_benchmark()
