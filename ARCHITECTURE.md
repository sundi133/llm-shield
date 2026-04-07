# Votal AI Guardrails — Architecture

## 1. Runtime Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CLIENT APPLICATION                            │
│         (LiteLLM Proxy / Direct API / Chat UI / Agent)              │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      VOTAL AI GUARDRAILS                             │
│                    (FastAPI on GPU Server)                            │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    TIER 1: FAST (~0ms)                        │   │
│  │  ┌──────────┐ ┌──────────┐ ┌─────────┐ ┌────────────────┐   │   │
│  │  │ Keyword  │ │  Regex   │ │   PII   │ │ Rate Limiter   │   │   │
│  │  │ Blocklist│ │ Pattern  │ │Detection│ │ Language Det.  │   │   │
│  │  └──────────┘ └──────────┘ └─────────┘ │ Sys Prompt Leak│   │   │
│  │                                         └────────────────┘   │   │
│  │  ┌──────────────────────────────────────────────────────┐    │   │
│  │  │          PROBE CLASSIFIER (~18ms)                     │    │   │
│  │  │  Linear probe on 1.7B hidden states                   │    │   │
│  │  │  Score > 0.92 → BLOCK | < 0.60 → ALLOW | else → DEEP │    │   │
│  │  └──────────────────────────────────────────────────────┘    │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                          │ BLOCK? → STOP                             │
│                          │ ALLOW? → SKIP TIER 2                      │
│                          ▼ DEEP?  → CONTINUE                         │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                TIER 2: DEEP LLM (~500-800ms)                  │   │
│  │         Qwen3.5-9B on llama-server (8 parallel slots)        │   │
│  │                                                               │   │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐     │   │
│  │  │ Adversarial  │ │   Topic      │ │  Safety Check    │     │   │
│  │  │ Detection    │ │ Restriction  │ │  + Toxicity      │     │   │
│  │  │ (40 attack   │ │ (whitelist/  │ │  + PII Detection │     │   │
│  │  │  types)      │ │  blacklist)  │ │                  │     │   │
│  │  └──────────────┘ └──────────────┘ └──────────────────┘     │   │
│  │          ▲ All run in PARALLEL via asyncio.gather             │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                          │                                           │
│                          ▼                                           │
│              ┌─────────────────────┐                                 │
│              │   BLOCK or ALLOW    │                                 │
│              └─────────┬───────────┘                                 │
│                        │ If allowed, proxy to LLM                    │
└────────────────────────┼────────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     UPSTREAM LLM                                     │
│            (OpenAI / Anthropic / Self-hosted)                        │
└────────────────────────┬────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   OUTPUT GUARDRAILS                                   │
│  ┌──────────────┐ ┌──────────┐ ┌─────────┐ ┌──────────────────┐    │
│  │    Tone      │ │   Bias   │ │   PII   │ │   Competitor     │    │
│  │ Enforcement  │ │Detection │ │ Leakage │ │   Mention Filter │    │
│  └──────────────┘ └──────────┘ └─────────┘ └──────────────────┘    │
└────────────────────────┬────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│              AUDIT LOG (SQLite / External)                            │
│         Every request logged with guardrail results                  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. LiteLLM Integration

```
┌───────────────────────────────────────────────────────────┐
│                    YOUR APPLICATION                        │
│              (Any LLM-powered app/agent)                   │
└──────────────────────┬────────────────────────────────────┘
                       │
                       ▼
┌───────────────────────────────────────────────────────────┐
│                   LiteLLM PROXY                            │
│              (Unified LLM Gateway)                         │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐ │
│  │  litellm_settings:                                    │ │
│  │    callbacks:                                         │ │
│  │      - votal_guardrails                               │ │
│  │                                                       │ │
│  │  Pre-call hook:                                       │ │
│  │    POST /guardrails/input → Votal AI Guardrails       │ │
│  │    If blocked → return 403, never reach LLM           │ │
│  │                                                       │ │
│  │  Post-call hook:                                      │ │
│  │    POST /guardrails/output → Votal AI Guardrails      │ │
│  │    If blocked → redact/block response                 │ │
│  └──────────────────────────────────────────────────────┘ │
│                                                            │
│  Routes to any LLM:                                        │
│  ┌──────────┐ ┌───────────┐ ┌──────────┐ ┌────────────┐  │
│  │ OpenAI   │ │ Anthropic │ │  Llama   │ │ Self-hosted│  │
│  │ GPT-4o   │ │ Claude    │ │  3.3     │ │  Qwen/etc  │  │
│  └──────────┘ └───────────┘ └──────────┘ └────────────┘  │
└───────────────────────────────────────────────────────────┘
                       │
                       ▼
┌───────────────────────────────────────────────────────────┐
│              VOTAL AI GUARDRAILS API                       │
│                                                            │
│  Input:   POST /guardrails/input                           │
│           POST /v1/shield/chat/completions                 │
│                                                            │
│  Output:  POST /guardrails/output                          │
│                                                            │
│  Config:  GET/PUT /v1/shield/config                        │
│  Audit:   GET /v1/shield/audit                             │
│  Stats:   GET /v1/shield/stats                             │
└───────────────────────────────────────────────────────────┘
```

**LiteLLM config.yaml:**
```yaml
model_list:
  - model_name: gpt-4o
    litellm_params:
      model: openai/gpt-4o
      api_key: sk-...

litellm_settings:
  callbacks:
    - votal_guardrails

votal_guardrails:
  api_url: "https://your-votal-endpoint/guardrails/input"
  api_key: "your-votal-key"
  input_guardrails:
    topic-restriction:
      enabled: true
      action: block
      customRules:
        mode: whitelist
        topics: ["insurance", "billing", "claims"]
    adversarial-prompt-detection:
      enabled: true
      action: block
      threshold: 0.8
  output_guardrails:
    pii-leakage:
      enabled: true
      action: block
    tone-enforcement:
      enabled: true
      action: warn
```

---

## 3. Model Retraining — Active Defense Loop

```
 PRODUCTION                          RETRAINING PIPELINE
 ──────────                          ────────────────────

 ┌─────────────┐    Every request
 │   Users /   │────────────────┐
 │   Agents    │                │
 └─────────────┘                ▼
                    ┌───────────────────────┐
                    │   VOTAL GUARDRAILS    │
                    │   (Qwen3.5-9B)       │
                    │                       │
                    │  Blocked? ──────────────────┐
                    │  Allowed? ──────────────┐   │
                    │  Low confidence? ────┐  │   │
                    └──────────────────────┼──┼───┼──┘
                                           │  │   │
                    ┌──────────────────────┘  │   │
                    ▼                         ▼   ▼
            ┌──────────────┐         ┌──────────────────┐
            │  REVIEW QUEUE │         │   AUDIT LOG      │
            │  (confidence  │         │  (all requests   │
            │   0.60-0.80)  │         │   + results)     │
            └──────┬───────┘         └────────┬─────────┘
                   │                           │
                   ▼                           ▼
         ┌──────────────────┐      ┌───────────────────────┐
         │  HUMAN REVIEW    │      │  ATTACK PATTERN       │
         │  (Security team  │      │  EXTRACTION           │
         │   labels edge    │      │                       │
         │   cases)         │      │  • New attack types   │
         │                  │      │  • Failed blocks      │
         │  Labels:         │      │  • False positives    │
         │  ✓ safe          │      │  • Evasion patterns   │
         │  ✗ adversarial   │      │                       │
         │  ? needs context │      └───────────┬───────────┘
         └──────┬───────────┘                  │
                │                               │
                ▼                               ▼
     ┌─────────────────────────────────────────────────────┐
     │              TRAINING DATASET BUILDER                 │
     │                                                       │
     │  Sources:                                             │
     │  ├─ Audit log (production attacks)                    │
     │  ├─ Human-labeled edge cases                          │
     │  ├─ Public adversarial datasets (HarmBench, etc.)     │
     │  ├─ Synthetic attacks (generated by red-team LLM)     │
     │  └─ False positive corrections                        │
     │                                                       │
     │  Format per sample:                                   │
     │  {                                                    │
     │    "message": "user input",                           │
     │    "label": "adversarial" | "safe",                   │
     │    "attack_type": "sandwich_attack",                  │
     │    "source": "production" | "synthetic" | "human"     │
     │  }                                                    │
     └──────────────────────┬──────────────────────────────┘
                            │
                            ▼
     ┌─────────────────────────────────────────────────────┐
     │              FINE-TUNING PIPELINE                     │
     │                                                       │
     │  Base model: Qwen3.5-9B (or latest open source)      │
     │                                                       │
     │  Step 1: LoRA Fine-tune                               │
     │  • Unsloth/PEFT for efficient training                │
     │  • 4-bit QLoRA on single GPU                          │
     │  • Training data: labeled attacks + safe              │
     │  • Loss: binary classification (safe/unsafe)          │
     │                                                       │
     │  Step 2: Linear Probe Training                        │
     │  • Extract hidden states from layer N                 │
     │  • Train direction vector (safe vs unsafe)            │
     │  • Output: probe_config.json                          │
     │    {                                                  │
     │      "best_layer": 15,                                │
     │      "direction": [0.023, -0.041, ...],               │
     │      "threshold_block": 0.92,                         │
     │      "threshold_needs_deep": 0.60                     │
     │    }                                                  │
     │                                                       │
     │  Step 3: Evaluation                                   │
     │  • Run test_votal.sh (57+ tests)                      │
     │  • Compare: new model vs current production           │
     │  • Must pass >= current pass rate to deploy           │
     │  • Check false positive rate on safe messages         │
     │                                                       │
     │  Step 4: Quantize & Export                            │
     │  • GGUF Q4_K_M quantization                           │
     │  • Upload to HuggingFace (votal-ai/vai-*)             │
     │  • Update Dockerfile + config                         │
     └──────────────────────┬──────────────────────────────┘
                            │
                            ▼
     ┌─────────────────────────────────────────────────────┐
     │              DEPLOYMENT                               │
     │                                                       │
     │  1. Docker build (pulls new model from HuggingFace)  │
     │  2. Push to registry                                  │
     │  3. RunPod auto-deploys new workers                   │
     │  4. handler.py auto-syncs llm_backend config          │
     │  5. Run test_votal.sh to verify                       │
     │                                                       │
     │  Rollback: revert model path in config if tests fail  │
     └─────────────────────────────────────────────────────┘

                    ┌─────────────────┐
                    │  CYCLE REPEATS  │
                    │  Weekly or on   │
                    │  new attack     │
                    │  discovery      │
                    └─────────────────┘
```

### Retraining Triggers

- New attack type discovered in audit logs
- Pass rate drops below threshold (e.g., < 90%)
- False positive rate exceeds threshold (e.g., > 5%)
- New public adversarial dataset released
- Customer reports missed attack
- Scheduled weekly retraining cycle

---

## 4. Red Team → Retrain Loop

```
  ┌──────────────┐
  │  Red Team    │  Uses a strong LLM (Claude/GPT-4) to
  │  LLM         │  generate novel attacks against the
  │  (Attacker)  │  guardrail model
  └──────┬───────┘
         │ Generates attack variants:
         │ • Paraphrase existing attacks
         │ • Combine attack techniques
         │ • Domain-specific attacks (insurance fraud)
         │ • New obfuscation methods
         ▼
  ┌──────────────────────────────────────┐
  │  ATTACK GENERATOR                     │
  │                                       │
  │  For each known attack type:          │
  │  1. Generate 100 variants             │
  │  2. Test against current model        │
  │  3. Keep attacks that bypass model    │
  │  4. Label as "adversarial"            │
  │                                       │
  │  Also generate safe variants:         │
  │  1. Legitimate messages that look     │
  │     similar to attacks                │
  │  2. Edge cases (angry but legitimate) │
  │  3. Label as "safe"                   │
  └──────────────────┬───────────────────┘
                     │
                     ▼
  ┌──────────────────────────────────────┐
  │  TRAINING DATA                        │
  │                                       │
  │  Balanced dataset:                    │
  │  • 50% adversarial (attacks)          │
  │  • 50% safe (legitimate messages)     │
  │  • Covers all 40+ attack types        │
  │  • Domain-specific (insurance, etc.)  │
  │                                       │
  │  Size: 10K-50K samples per retrain    │
  └──────────────────┬───────────────────┘
                     │
                     ▼
  ┌──────────────────────────────────────┐
  │  FINE-TUNE (QLoRA)                    │
  │                                       │
  │  unsloth + PEFT:                      │
  │  • Base: Qwen3.5-9B                   │
  │  • LoRA rank: 16-64                   │
  │  • Learning rate: 2e-5                │
  │  • Epochs: 3-5                        │
  │  • GPU: single RTX 4090 (24GB)        │
  │  • Time: ~2-4 hours                   │
  └──────────────────┬───────────────────┘
                     │
                     ▼
  ┌──────────────────────────────────────┐
  │  TRAIN PROBE                          │
  │                                       │
  │  find_directions.py:                  │
  │  • Forward pass on labeled data       │
  │  • Extract hidden states per layer    │
  │  • Find best separating direction     │
  │  • Output: probe_config.json          │
  │  • Time: ~25 minutes                  │
  └──────────────────┬───────────────────┘
                     │
                     ▼
  ┌──────────────────────────────────────┐
  │  EVALUATE                             │
  │                                       │
  │  test_votal.sh (57 tests):            │
  │  ┌────────────────────────────────┐  │
  │  │ Current model:  50/57 (88%)    │  │
  │  │ New model:      54/57 (95%)    │  │
  │  │ Improvement:    +4 tests       │  │
  │  │ No regressions: confirmed      │  │
  │  │ Decision: DEPLOY               │  │
  │  └────────────────────────────────┘  │
  └──────────────────┬───────────────────┘
                     │
                     ▼
  ┌──────────────────────────────────────┐
  │  EXPORT & DEPLOY                      │
  │                                       │
  │  1. Merge LoRA into base model        │
  │  2. Quantize to GGUF Q4_K_M           │
  │  3. Push to HuggingFace               │
  │     votal-ai/vai-9b-guardrailed-v3    │
  │  4. Update Dockerfile                 │
  │  5. Docker build + push               │
  │  6. RunPod auto-deploys               │
  └──────────────────────────────────────┘
```

---

## 5. Model Evolution

```
v1 (Day 1)     Qwen3-8B (generic)             → 93% pass rate
v2 (Day 2)     Qwen3.5-4B (generic)           → 79% pass rate
v3 (Day 2)     Qwen3.5-9B (generic)           → 88% pass rate
v4 (Today)     vai-9b-guardrailed (fine-tuned) → target 95%+
v5 (Week 2)    + probe classifier              → 95%+ at 18ms
v6 (Month 2)   + red team retrained            → 98%+ at 18ms
                                                  ▲
                                                  │
                                       Continuous improvement
                                       from production attacks
```

---

## 6. Multi-GPU Scaling

```
Single GPU (default):
  1x RTX 4090 → 8 slots → ~7 req/s → ~700ms latency

Multi-GPU (config-driven, no code changes):
  3x RTX 4090 → 24 slots → ~34 req/s → ~700ms latency

  GPU 0: adversarial_detection, tone_enforcement, bias_detection
  GPU 1: topic_restriction, topic_enforcement, hallucinated_links
  GPU 2: safety_check, toxicity, pii_detection, pii_leakage

Faster GPU:
  1x A100 80GB → 8 slots → ~16 req/s → ~350ms latency
  1x H100      → 8 slots → ~23 req/s → ~200ms latency
```
