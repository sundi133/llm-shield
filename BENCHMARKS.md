# LLM Shield — Guardrail Performance Benchmarks

## Infrastructure

| Component | Specification |
|-----------|--------------|
| **GPU** | NVIDIA H100 80GB HBM3 |
| **Model** | votal-ai/vai35-9B (9B parameters) |
| **Precision** | FP8 weights + FP8 KV cache |
| **Serving** | vLLM with prefix caching + chunked prefill |
| **Context** | 8,192 tokens max sequence length |
| **Batch** | Up to 128 concurrent sequences |

## Architecture

Each API call runs **3 LLM-powered guardrails in parallel** on a single GPU:

```
Client Request ─────────────────────────────────────────────────────
   │
   ▼
┌─────────────────────────────────────────────────────────────────┐
│                    /guardrails/input                            │
│                                                                 │
│   ┌───────────────────┐                                        │
│   │ Topic Restriction  │  Strict allowlist topic classifier     │
│   └───────────────────┘                                        │
│   ┌───────────────────┐     All three run                      │
│   │  PII Detection     │     IN PARALLEL                       │
│   └───────────────────┘     on the GPU                         │
│   ┌───────────────────┐                                        │
│   │   Adversarial      │  16 attack categories                 │
│   │   Detection        │  (OWASP LLM Top 10 coverage)         │
│   └───────────────────┘                                        │
│                                                                 │
│   Total latency = max(topic, pii, adversarial)                 │
│   NOT sum — parallel execution                                  │
└─────────────────────────────────────────────────────────────────┘
   │
   ▼
Response (JSON) ── safe/block + per-guardrail results + latency
```

## Latency Results

### Summary

| Metric | c=1 | c=5 | c=10 |
|--------|-----|-----|------|
| **Server p50** | **181 ms** | **342 ms** | **657 ms** |
| **Server p95** | 375 ms | 657 ms | 1,195 ms |
| **Server p99** | 397 ms | 768 ms | 1,270 ms |
| **End-to-end p50** | 251 ms | 552 ms | 1,016 ms |
| **Throughput** | — | 8.9 req/s | 9.2 req/s |

> **Server latency** = GPU inference time (inference_time_ms).
> **End-to-end** = full client round-trip including network, middleware, and tenant policy resolution.

### Scaling Behavior

Latency scales sub-linearly with concurrency:

```
Concurrency     Server p50      Multiplier
─────────────────────────────────────────
    1×            181 ms          1.0×
    5×            342 ms          1.9×    (5× users, <2× latency)
   10×            657 ms          3.6×    (10× users, <4× latency)
```

Throughput remains stable at ~9 req/s across concurrency levels, indicating the GPU is efficiently batching requests without saturation.

### Per-Guardrail Latency (c=1)

| Guardrail | p50 | p95 | max | Blocks |
|-----------|-----|-----|-----|--------|
| Topic Restriction | 116 ms | 203 ms | 400 ms | 188/197 |
| PII Detection | 120 ms | 373 ms | 399 ms | 28/197 |
| Adversarial Detection | 169 ms | 264 ms | 298 ms | 133/197 |

### Per-Guardrail Latency (c=5)

| Guardrail | p50 | p95 | max | Blocks |
|-----------|-----|-----|-----|--------|
| Topic Restriction | 209 ms | 426 ms | 573 ms | 185/197 |
| PII Detection | 242 ms | 615 ms | 852 ms | 28/197 |
| Adversarial Detection | 315 ms | 555 ms | 659 ms | 133/197 |

### Per-Guardrail Latency (c=10)

| Guardrail | p50 | p95 | max | Blocks |
|-----------|-----|-----|-----|--------|
| Topic Restriction | 389 ms | 748 ms | 1,266 ms | 185/197 |
| PII Detection | 486 ms | 1,157 ms | 1,368 ms | 28/197 |
| Adversarial Detection | 555 ms | 977 ms | 1,192 ms | 131/197 |

## Detection Performance

### By Attack Category (c=1, 200 requests)

| Category | Requests | p50 | p95 | Detection |
|----------|----------|-----|-----|-----------|
| Prompt Injection | 25 | 184 ms | 399 ms | 25/25 blocked |
| Harmful Content | 25 | 355 ms | 394 ms | 25/25 blocked |
| Toxic Content | 14 | 157 ms | 178 ms | 14/14 blocked |
| PII | 17 | 207 ms | 284 ms | 17/17 blocked |
| Unicode Obfuscation | 22 | 135 ms | 201 ms | 22/22 blocked |
| Off-Topic | 18 | 150 ms | 185 ms | 18/18 blocked |
| Mixed Noise | 15 | 202 ms | 290 ms | 15/15 blocked |
| Benign (on-topic) | 15 | 171 ms | 193 ms | 4/15 allowed |

> Benign messages show 11/15 blocked because the test tenant uses a strict healthcare topic allowlist — harmless but off-scope requests (recipes, poems, coding help) are correctly rejected per policy.

### Adversarial Attack Coverage

The adversarial detection guardrail covers 16 attack families:

| Family | Attack Types |
|--------|-------------|
| **Injection** | Prompt injection, indirect injection, recursive injection, code injection |
| **Jailbreak** | DAN/STAN, persona hijack, refusal suppression, virtualization, alignment hacking |
| **Evasion** | Obfuscation, payload splitting, encoding attacks (ROT13, Base64, hex), token smuggling |
| **Manipulation** | Social engineering, context switching, task deflection, few-shot poisoning |
| **Exfiltration** | Data exfiltration, RBAC bypass, authorized user impersonation |
| **Content Safety** | Harmful content, self-harm, sexual content, privacy violation, misinformation |
| **Compound** | Bad chain attacks, compound instruction attacks |

## Cost Analysis

| Metric | Value |
|--------|-------|
| **GPU cost** | ~$2–3/hr (H100 on cloud) |
| **Throughput** | ~9 req/s sustained |
| **Requests per hour** | ~32,400 |
| **Cost per guardrail check** | **$0.00006 – $0.00009** |

Comparison with API-based guardrail services:

| Provider | Cost per check | Latency | Data residency |
|----------|---------------|---------|----------------|
| LLM Shield (self-hosted) | **$0.00008** | **181 ms** | **Your infrastructure** |
| API-based services | $0.001 – $0.01 | 500 – 2,000 ms | Third-party cloud |

> **10–100× cheaper**, **3–10× faster**, and **zero data leaves your infrastructure**.

## Hardware Selection Guide

### GPU Comparison for vai35-9B (FP8)

| GPU | VRAM | FP8 TFLOPS | Memory BW | Best For | Est. Price |
|-----|------|-----------|-----------|----------|------------|
| **NVIDIA H100 SXM** | 80 GB | 3,958 | 3.35 TB/s | Production — maximum throughput | $2.50–3.50/hr |
| **NVIDIA A100 80GB** | 80 GB | — (FP8 N/A) | 2.0 TB/s | Production — BF16/FP16 only, no FP8 | $1.50–2.50/hr |
| **NVIDIA L40S** | 48 GB | 733 | 864 GB/s | Cost-optimized production | $1.00–1.80/hr |
| **NVIDIA A10G** | 24 GB | — (FP8 N/A) | 600 GB/s | Dev/staging — tight VRAM, BF16 only | $0.50–1.00/hr |
| **NVIDIA T4** | 16 GB | — | 320 GB/s | Not recommended — insufficient VRAM | $0.30–0.50/hr |

> **FP8 quantization requires Ada Lovelace (L40S) or Hopper (H100) architecture.** Ampere GPUs (A100, A10G) must use BF16/FP16 with ~2× memory footprint.

### VRAM Requirements

```
Model Size (FP8):   ~9 GB   (weights only)
KV Cache (FP8):     ~2–5 GB (depends on max-num-seqs × max-model-len)
Overhead:           ~1–2 GB (activations, CUDA context)
────────────────────────────────────
Minimum:            ~14 GB  (batch=16, ctx=4096)
Recommended:        ~24 GB+ (batch=64, ctx=8192)
Benchmarked (H100): ~68 GB  (batch=128, ctx=8192, 85% util)
```

### Estimated Performance by GPU

| GPU | Precision | Max Batch | Est. p50 (c=1) | Est. Throughput | Notes |
|-----|-----------|-----------|-----------------|-----------------|-------|
| H100 80GB | FP8 | 128 | **~180 ms** | **~9 req/s** | Benchmarked — see above |
| L40S 48GB | FP8 | 64 | ~250–350 ms | ~5–6 req/s | Lower memory BW → higher decode latency |
| A100 80GB | BF16 | 128 | ~300–450 ms | ~5–7 req/s | No FP8; 2× weight memory, but large VRAM |
| A10G 24GB | BF16 | 16–32 | ~500–800 ms | ~2–3 req/s | Limited VRAM constrains batch size |

> These are estimates. Actual performance depends on input length distribution, number of active guardrails, and vLLM version. Always benchmark on your target hardware.

---

## Scaling Guide

### Vertical Scaling (Single GPU)

Tune these vLLM parameters to match your concurrency requirements:

| Parameter | Effect | Guidance |
|-----------|--------|----------|
| `--max-num-seqs` | Max concurrent sequences batched on GPU | Increase for higher concurrency. Each guardrail call = 1 sequence; 3 guardrails × N concurrent requests = 3N sequences needed. |
| `--max-num-batched-tokens` | Max tokens in a single batch step | Set ≥ `max-model-len` for chunked prefill. Increase if prefill throughput is the bottleneck. |
| `--max-model-len` | Max context window per sequence | 8192 is sufficient for guardrails (short prompts + user message). Reducing saves KV cache memory. |
| `--gpu-memory-utilization` | Fraction of VRAM allocated to vLLM | 0.85–0.95. Higher = more KV cache slots = higher batch capacity. |
| `--enable-prefix-caching` | Cache system prompt KV across requests | **Critical for guardrails** — all requests share the same system prompts. Saves ~60% prefill compute. |
| `--enable-chunked-prefill` | Interleave prefill and decode | Reduces head-of-line blocking. Keeps decode latency low even under load. |

**Capacity planning formula:**

```
Max concurrent API requests = floor(max-num-seqs / guardrails_per_request)

Example: max-num-seqs=128, 3 guardrails/request → 42 concurrent API requests
```

### Horizontal Scaling (Multiple GPUs / Nodes)

#### Option 1: Replicated Instances (Recommended)

Deploy multiple independent vLLM instances behind a load balancer. Each instance runs on a single GPU with the full 9B model.

```
                    ┌─────────────────┐
                    │  Load Balancer   │
                    │  (round-robin)   │
                    └────────┬────────┘
               ┌─────────────┼─────────────┐
               ▼             ▼             ▼
        ┌────────────┐ ┌────────────┐ ┌────────────┐
        │  vLLM + GPU │ │  vLLM + GPU │ │  vLLM + GPU │
        │  Instance 1 │ │  Instance 2 │ │  Instance 3 │
        │  (H100)     │ │  (H100)     │ │  (H100)     │
        └────────────┘ └────────────┘ └────────────┘
```

| Replicas | Est. Throughput | Est. p50 (c=30) | Monthly Cost (H100) |
|----------|----------------|-----------------|---------------------|
| 1× H100 | ~9 req/s | ~2,000 ms | ~$2,200 |
| 2× H100 | ~18 req/s | ~1,000 ms | ~$4,400 |
| 4× H100 | ~36 req/s | ~500 ms | ~$8,800 |

**Throughput scales linearly. Latency at high concurrency drops proportionally.**

**When to use:** Most deployments. Simple to operate, fault-tolerant (one GPU fails, others continue), and each instance is stateless.

#### Option 2: Tensor Parallelism (TP)

Split the model across multiple GPUs on a single node. Reduces per-request latency but does **not** increase throughput proportionally.

```bash
vllm serve votal-ai/vai35-9B \
  --tensor-parallel-size 2 \
  --dtype bfloat16 \
  --quantization fp8 \
  --kv-cache-dtype fp8 \
  --max-model-len 8196 \
  --max-num-batched-tokens 8196 \
  --max-num-seqs 256 \
  --gpu-memory-utilization 0.85 \
  --enable-prefix-caching \
  --enable-chunked-prefill \
  --language-model-only
```

| TP Config | GPUs | Latency Impact | Throughput Impact | Use Case |
|-----------|------|----------------|-------------------|----------|
| TP=1 | 1 | Baseline | Baseline | Default — 9B fits on 1 GPU |
| TP=2 | 2 | ~30–40% lower | ~1.5× (more KV cache) | When p95 latency SLA < 300ms at c=10 |
| TP=4 | 4 | ~50–60% lower | ~2× (more KV cache) | Rarely needed for 9B model |

**When to use:** Only when you need **lower latency per request** and have multi-GPU nodes (e.g., 8×H100 DGX). For a 9B model, TP=2 is the practical maximum — beyond that, inter-GPU communication overhead exceeds the compute savings.

> **Recommendation for 9B model:** Prefer replicated instances (Option 1) over TP. The model fits comfortably on a single GPU, so replication gives better throughput-per-dollar. Use TP only for strict sub-500ms p95 SLAs under high load.

#### Option 3: Hybrid (TP + Replication)

For large-scale deployments with strict latency requirements:

```
                    ┌──────────────────┐
                    │  Load Balancer    │
                    └────────┬─────────┘
               ┌─────────────┼─────────────┐
               ▼             ▼             ▼
        ┌────────────┐ ┌────────────┐ ┌────────────┐
        │  TP=2      │ │  TP=2      │ │  TP=2      │
        │  2× H100   │ │  2× H100   │ │  2× H100   │
        │  Instance 1 │ │  Instance 2 │ │  Instance 3 │
        └────────────┘ └────────────┘ └────────────┘
                    6× H100 total
```

This gives both low latency (TP) and high throughput (replication).

### Scaling Decision Matrix

| Requirement | Solution | Hardware |
|-------------|----------|----------|
| < 5 req/s, budget-friendly | 1× L40S or A100 | Single GPU |
| 5–10 req/s, low latency | 1× H100 | Single GPU |
| 10–20 req/s | 2× H100 replicated | 2 GPUs, load balanced |
| 20–50 req/s | 4–6× H100 replicated | Multi-GPU, load balanced |
| 50+ req/s | 6+ H100 replicated | Multi-node cluster |
| Strict SLA (p95 < 300ms at c=10) | TP=2 + replication | Multi-GPU nodes |

### Kubernetes / Container Orchestration

```yaml
# Example: Kubernetes deployment for horizontal scaling
apiVersion: apps/v1
kind: Deployment
metadata:
  name: llm-shield-guardrail
spec:
  replicas: 3    # Scale this up/down
  selector:
    matchLabels:
      app: llm-shield-guardrail
  template:
    spec:
      containers:
      - name: vllm
        image: vllm/vllm-openai:latest
        args:
        - "votal-ai/vai35-9B"
        - "--dtype=bfloat16"
        - "--quantization=fp8"
        - "--kv-cache-dtype=fp8"
        - "--max-model-len=8196"
        - "--max-num-batched-tokens=8196"
        - "--max-num-seqs=128"
        - "--gpu-memory-utilization=0.85"
        - "--enable-prefix-caching"
        - "--enable-chunked-prefill"
        - "--language-model-only"
        resources:
          limits:
            nvidia.com/gpu: 1
      - name: shield-api
        image: llm-shield:latest
        ports:
        - containerPort: 8080
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: llm-shield-hpa
spec:
  scaleRef:
    apiVersion: apps/v1
    kind: Deployment
    name: llm-shield-guardrail
  minReplicas: 2
  maxReplicas: 8
  metrics:
  - type: Pods
    pods:
      metric:
        name: vllm_num_requests_running
      target:
        type: AverageValue
        averageValue: "80"    # Scale up when avg running requests > 80
```

### Auto-Scaling Signals

| Metric | Source | Scale-Up Threshold | Why |
|--------|--------|--------------------|-----|
| `vllm_num_requests_running` | vLLM Prometheus | > 60–80% of `max-num-seqs` | GPU batch is near capacity |
| `vllm_avg_generation_throughput_toks_per_s` | vLLM Prometheus | Declining under load | Decode throughput saturated |
| Server p95 latency | Application metrics | > target SLA | User-facing latency too high |
| GPU utilization | DCGM / nvidia-smi | > 90% sustained | Compute-bound |

---

## Methodology

- **Test tool**: `stress_test_guardrails.py` with mixed attack categories
- **Requests**: 200 per concurrency level
- **Categories**: prompt injection, harmful content, toxic, PII, unicode obfuscation, off-topic, mixed noise, benign, edge cases (with long-input variants)
- **Tenant config**: Healthcare tenant with topic restriction (6 allowed topics), PII detection, and adversarial detection enabled
- **Thinking disabled**: `chat_template_kwargs: {"enable_thinking": false}` — all decode tokens are answer tokens, zero wasted on chain-of-thought

## Configuration

```bash
vllm serve votal-ai/vai35-9B \
  --host 0.0.0.0 \
  --port 8000 \
  --dtype bfloat16 \
  --quantization fp8 \
  --kv-cache-dtype fp8 \
  --max-model-len 8196 \
  --max-num-batched-tokens 8196 \
  --max-num-seqs 128 \
  --gpu-memory-utilization 0.85 \
  --enable-prefix-caching \
  --enable-chunked-prefill \
  --language-model-only
```
