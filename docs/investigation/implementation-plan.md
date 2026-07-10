# Implementation Plan — Guard Model Mode (Votal / Nemotron / Both)

Companion to `nemo-guardrails-task-brief.md` and `open-questions.md`. Documents
the decisions made when implementing the three-mode design, including the two
items `open-questions.md` explicitly said needed a decision rather than a
silent assumption (#3 and #4).

## What was built

`SHIELD_GUARD_MODEL_MODE` (`votal` default | `nemotron` | `both`) selects the
guard model at **two layers**:

1. **Serving (`scripts/start_vllm.sh`)** — launches the model(s) vLLM actually
   loads: votal → Votal on `VLLM_PORT`; nemotron → Nemotron on `VLLM_PORT`;
   both → Votal on `VLLM_PORT` + Nemotron on `NEMOTRON_VLLM_PORT`. In
   nemotron/both it exports `NEMOTRON_BACKEND_URL` / `NEMOTRON_MODEL_NAME` for
   the app. (An earlier revision changed only the client URL and never the
   served model — Sundi flagged that; the real replacement lives here.)
2. **Client (`core/llm_backend.py`)** — routes guard calls to the served
   instance(s) at the transport layer, so every existing guardrail file works
   unchanged; in `both` it fans out to both and merges verdicts.

This section records the decisions, not the mechanics.

## Decision: three-mode design (open question #3)

Kept as originally proposed — env-var-switchable Votal-only / Nemotron-only /
both — since it's the only framing that satisfies all three signals in the
transcript (Sundi's "alongside", Rakesh's "replace", Sundi's later "which is
better?"). Restating per the brief: **this is still a synthesis decision, not
something Rakesh or Sundi explicitly signed off on in this form** — flag it to
Rakesh before treating it as final, same as the brief already says.

## Decision: combine policy for "both" mode (open question #4)

**Chosen policy: OR-logic** — block if either model flags content unsafe —
applied only for guardrails whose verdict shape AND polarity are explicitly
registered; everything else falls back to shadow-logging (no enforcement
change). Reasoning:

- OR-logic is the conservative choice for a *security* guardrail: a
  false-negative from one model is exactly what "using both" is meant to
  catch, and the brief's own accuracy target (95%+) argues for erring toward
  catching more, not fewer, unsafe cases.
- It's implemented **at the transport layer** (`core/llm_backend.py`), not
  per-guardrail, so no individual guardrail file needed changes.
- Merging requires knowing each guardrail's verdict **polarity**, so the
  merge is driven by an explicit registry (`_GUARD_VERDICT_REGISTRY`), not a
  generic "first boolean = flagged" heuristic. Security review of the first
  draft caught that four guardrails use true=SAFE semantics
  (`tone_enforcement` 'compliant', `topic_restriction` 'related',
  `topic_enforcement` 'overall_allowed', `factual_grounding` 'grounded') — a
  naive OR-merge would have let a permissive secondary verdict MASK a
  primary violation for those. Guardrails not in the registry (multi-line
  shapes like `hallucinated_links`, free-text like `language_detection`,
  unknown future names) are shadow-logged: the secondary's output is
  attached (`_secondary_model`) for comparison but never changes the
  decision. A regression test asserts every registry entry corresponds to a
  real discovered guardrail name.
- On a tie (both flag, or neither flags), `SHIELD_GUARD_MODEL_PRIMARY`
  (default `votal`) breaks the tie — keeps a single, predictable model's
  reasoning/confidence/type fields in the result when both models agree.

Two further hardening decisions from the same review:

- **Scope**: the mode applies only to guard-classification calls (those that
  pass a `guardrail_name`). The gateway's proxied user chat completions
  (`api/routes_gateway.py`) pass none and therefore always stay on the
  original votal path — `nemotron` mode must not route user chat to a
  content-safety classifier, and `both` mode must not duplicate user
  conversations to a second backend the tenant never opted into.
- **Fail-fast config validation**: every LLM guardrail fails open on call
  errors, so a typo'd `SHIELD_GUARD_MODEL_MODE` or missing
  `NEMOTRON_BACKEND_URL` caught only at call time would have silently
  disabled ALL LLM guardrails. `validate_guard_model_config()` runs at
  data-plane startup (`create_app`) and crashes the boot loudly instead.

**This is a real decision, not a placeholder** — per your instruction to
decide rather than re-raise the open question. Flag it to Rakesh alongside the
three-mode design itself before it's presented to Sundi, since it changes
prod-path *behavior* (when opted in) more than the mode switch alone does.

## Decision: model ID / hosting (open questions #1 / #2) — RESOLVED

- **Model:** `nvidia/Nemotron-3.5-Content-Safety` (confirmed by Sundi; verified
  on HuggingFace). A Gemma-3-4B-it-based multilingual/multimodal content-safety
  classifier, served under `--served-model-name nemotron_moderator`, vLLM
  ≥ 0.11.0. Set as `NEMOTRON_MODEL` in `start_vllm.sh` / Dockerfile.
- **Hosting:** self-hosted via vLLM in the same image (`start_vllm.sh`), same
  pattern as the Votal model. An external NIM endpoint still works by setting
  `SKIP_VLLM=true` + `NEMOTRON_BACKEND_URL` manually.
- **Verified** with a stubbed vLLM: `start_vllm.sh` launches the right model(s)
  per mode and hands the client the right URL (`tests/test_start_vllm_modes.py`);
  client routing/merge covered by `tests/test_guard_model_mode.py`.

### Still to validate on real GPU (follow-up, needs weights + hardware)
Nemotron Content Safety is a *classifier* with its own I/O contract
(`chat_template_kwargs` request_categories / custom_policy; output like
`"User Safety: unsafe, ..."`), **not** the CSV/JSON format the current guardrail
prompts emit/parse. The serving + routing is done and tested; adapting each
guardrail's prompt + response parsing to Nemotron's format (and measuring
accuracy vs. the 95% target) is the next step and can't be done without the
real model on GPU. Until then, `nemotron`/`both` modes route correctly but the
classification accuracy is unverified — hence `votal` remains the default.

## Not touched

- The production pipeline / `shield.votal.ai` tenant — nothing here changes
  behavior unless `SHIELD_GUARD_MODEL_MODE` is explicitly set; default
  (unset) is byte-identical to the pre-existing code path (regression-tested).
- No LangChain — direct HTTP calls only, consistent with Rakesh's
  confirmation.
- No admin-plane / `Dockerfile.admin` changes — this is data-plane only.

## Still open / deferred (per the brief's own non-requirements)

- Benchmarks (HarmBench, agents, IO guardrails, custom policies) — later
  stage per the brief; not started here.
- Web extension scope confirmation — see `extension-testing-report.md` for
  the testing done; separate from this guard-model-mode work.
- Getting Rakesh's validation of the approach, then Sundi's final approval,
  per the brief's explicit process gate — still your and Rakesh's step, not
  something implementation can substitute for.
