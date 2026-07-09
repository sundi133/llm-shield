# Implementation Plan — Guard Model Mode (Votal / Nemotron / Both)

Companion to `nemo-guardrails-task-brief.md` and `open-questions.md`. Documents
the decisions made when implementing the three-mode design, including the two
items `open-questions.md` explicitly said needed a decision rather than a
silent assumption (#3 and #4).

## What was built

`core/llm_backend.py` now supports `SHIELD_GUARD_MODEL_MODE` (`votal` default |
`nemotron` | `both`), applied at the transport layer so every existing
guardrail file works unchanged regardless of mode — see the module for the
full mechanism. This section only records the decisions, not the mechanics.

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

## Decision: model ID / hosting (open questions #1 / #2) — still not resolved, and this doesn't need them to be

The implementation deliberately does not assume either open question is
resolved:
- `NEMOTRON_BACKEND_URL` / `NEMOTRON_MODEL_NAME` / `NEMOTRON_BACKEND_API_KEY`
  are plain env vars pointing at *any* OpenAI-chat-compatible endpoint — a
  self-hosted vLLM instance serving the HF weights, or an NVIDIA NIM endpoint,
  both work without a code change, since the payload
  (`_build_nemotron_payload`) deliberately targets only the lowest common
  denominator of that contract (no vLLM-specific extras).
- Verified end-to-end with a stubbed second backend (see
  `tests/test_guard_model_mode.py`) rather than the real model, since the
  model ID itself is still unconfirmed. Once Rakesh/Sundi confirm which model
  + hosting, this is a config change (set the env vars), not a code change.

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
