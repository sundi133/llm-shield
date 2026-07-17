# Spec: Nemotron Content Safety as an env-switchable guardrail model option

## 1. Problem & outcome
- Allow a deployment to serve `nvidia/Nemotron-3.5-Content-Safety` (Gemma-3-4B
  based moderator) from Hugging Face via the existing single vLLM server,
  instead of the default `votal-ai/vai35-4B-v2`, using environment variables
  only. One model, one vLLM instance, one GPU. No prompt changes.
- Observable success: with the documented env block set on a RunPod endpoint,
  vLLM downloads and serves Nemotron; `/guardrails/*` return the existing
  response schemas; with no vars set, behavior is byte-identical to today.
- Non-goals:
  - Changing the default model (votal stays the default).
  - Using Nemotron's native moderation template (`request_categories`) or its
    native "User Safety: unsafe" output format. Nemotron is used as the base
    classifier behind the existing guardrail prompts and JSON guided decoding.
    A native-output parser is a separate future spec.
  - Any change to guardrail prompts, schemas, or the Ollama / OpenRouter /
    LiteLLM backend paths.
  - Multimodal (image) moderation.
  - Terraform/Kubernetes parity (secondary deploy path; follow-up if needed).

## 2. Plane & latency contract
- Plane: data plane only (`scripts/start_vllm.sh`, `core/llm_backend.py`,
  `Dockerfile`). Admin plane untouched.
- Guard path: the only guard-path code change is one env read
  (`VLLM_NOTHINK_SUFFIX`) in `_build_payload`, equivalent in cost to the
  existing `ENABLE_LITELLM` getenv on the same path. No added I/O, no added
  latency.

## 3. Data model
- None. No Redis keys, no tenant state.

## 4. API / interface
- No endpoint changes. New/changed environment variables (all optional):
  - `VLLM_QUANTIZATION` (default `fp8`; `none` omits the flag)
  - `VLLM_KV_CACHE_DTYPE` (default `fp8`; `none` omits the flag)
  - `VLLM_DTYPE` (default `bfloat16`)
  - `VLLM_LANGUAGE_MODEL_ONLY` (default `true`)
  - `VLLM_PERFORMANCE_MODE` (default `throughput`; `none` omits the flag)
  - `SERVED_MODEL_NAME` (default unset; adds `--served-model-name`)
  - `VLLM_NOTHINK_SUFFIX` (default `true`; `false` stops injecting the
    Qwen-only `/no_think /set nothink` suffix into system prompts)
  - `VLLM_DRY_RUN` (test hook: print resolved vLLM args and exit)
  - Docker build arg `VLLM_BASE_IMAGE` (default `vllm/vllm-openai:latest`)
    to pin the vLLM version (Nemotron documents `vllm>=0.11.0,<=0.20.2`).

## 5. Security & backward compatibility
- With no new vars set, the launched vLLM command line and the request
  payloads are identical to before (regression-tested).
- The switch is opt-in per deployment; rollback is env-only (unset the vars).
- `HF_TOKEN`/`HUGGING_FACE_HUB_TOKEN` are read by vLLM/huggingface_hub
  directly; never baked into the image (RunPod secrets as documented in the
  Dockerfile comments). `RUNPOD_TOKEN` is never used as an HF token.
- The app still does not send a `model` field on the vLLM path, so no
  coordination between app and server naming is required.

## 6. Packaging & deploy
- No new pip deps. No admin-plane modules touched (Dockerfile.admin
  unchanged).
- Images: only the data-plane `Dockerfile` gains a build arg; rebuild the
  RunPod image as usual.
- RunPod env block for the Nemotron option (see `.env.example`):
  `MODEL_NAME=nvidia/Nemotron-3.5-Content-Safety`, `VLLM_NOTHINK_SUFFIX=false`,
  `VLLM_QUANTIZATION=none`, `VLLM_KV_CACHE_DTYPE=none`,
  `VLLM_PERFORMANCE_MODE=none`, optional `SERVED_MODEL_NAME` and `HF_TOKEN`.
- First boot lazily downloads weights into `HF_HOME=/tmp/cache/huggingface`
  (existing behavior). If RunPod ephemeral disk causes re-downloads, mount a
  volume at `/tmp/cache`.

## 7. Failure modes & edge cases
- Unsupported flag/model combo (e.g. fp8 on an unsupported GPU): vLLM exits,
  the startup wait loop detects the dead PID and fails the boot loudly
  (existing behavior). Fix is env-only.
- Gated HF repo without token: vLLM download fails at boot, same loud path.
- `VLLM_NOTHINK_SUFFIX` unset/garbage values: treated as `true` (fail to the
  historical behavior).
- Cold start slower than votal: the boot wait loop is unbounded while the
  vLLM process is alive, so a long download does not kill the pod.
- Classification quality is the real risk: Nemotron is a moderation
  fine-tune driving generic JSON classifier prompts. Gate any production
  flip on the red-team suite and FP evals (`scripts/eval_adversarial_fp.py`,
  `scripts/eval_agentic_fp_holdout.py`) against a staging endpoint.

## 8. Test plan (Definition of Done)
- `tests/test_vllm_model_option.py`:
  - default vLLM payload still carries the Qwen suffix and
    `chat_template_kwargs={"enable_thinking": false}`;
  - `VLLM_NOTHINK_SUFFIX=false` leaves prompts untouched and changes nothing
    else (no `model` field, response_format intact);
  - flag values other than false/0/no keep the suffix (fail-to-historical);
  - Ollama path unaffected;
  - `start_vllm.sh` dry run: defaults reproduce the historical votal flags;
    `none` overrides omit fp8/performance flags; `--language-model-only`
    toggleable; `--served-model-name` appears only when set.
- Existing suites (`test_llm_backend_ollama.py`, `test_openrouter_backend.py`,
  `test_custom_policy_multiturn.py`) stay green unchanged, proving the
  default path is untouched.
- Full suite green in a clean venv; CI pytest gate passes.
