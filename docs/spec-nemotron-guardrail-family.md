---
title: "Spec: Nemotron guardrail family"
layout: default
permalink: /spec-nemotron-guardrail-family/
description: Run the whole guardrail suite on nvidia/Nemotron-3.5-Content-Safety instead of votal-ai/vai35, on one GPU, by swapping a per-guardrail prompt and verdict-parser pack rather than duplicating the guardrail classes.
---

# Spec: Nemotron guardrail family

Status: **draft, pending approval**. Branch: `feat/nemo-guardrail-family`.
Predecessor: [spec-nemotron-model-option.md](spec-nemotron-model-option.md),
which made Nemotron servable by env var and explicitly deferred "a native-output
parser" to this spec.

## 1. Problem & outcome

Nemotron is fine-tuned to emit its own moderation format:

```
User Safety: unsafe
Safety Categories: Harassment, Hate
```

Every LLM-backed guardrail here parses a single CSV line through
`parse_csv_response` with its own field list. The predecessor spec serves
Nemotron *behind the existing CSV prompts*, which fights the fine-tuning. This
spec adds a **guardrail family**: one env var selects which prompt and which
verdict parser each guardrail uses, so a deployment runs `vai35` **or**
Nemotron on a single GPU with no second model resident.

**Outcome.** With `SHIELD_GUARDRAIL_FAMILY=nemo` and Nemotron served, all 20
LLM-backed guardrails return the same `GuardrailResult` shapes they do today,
driven by Nemotron's native output. With the var unset, every byte of the
current path is unchanged.

### Scope: 20 files, not 56

Of 56 guardrail modules, **20 call the model**. The other 36 are deterministic
and are explicitly out of scope:

> `rbac_guard`, `tool_allowlist`, `tool_use_control`, `tool_call_validation`,
> `action_classification`, `delegation_control`, `data_access_guard`,
> `mcp_guard`, `sensitive_action_confirmation`, `taint_tracking`,
> `budget_controls`, `scope_boundaries`, `loop_detection`, `memory_*`,
> `keyword_blocklist`, `regex_pattern`, `length_limit`, `rate_limiter`,
> `pii_leakage`, `competitor_mention`, `role_redaction`, `system_prompt_leak`,
> `payload_risk` (input), `context_window_guardrails`, `cert_identity`, …

Agentic RBAC and tool authorization live here, plus `cap/mint`. **They must not
become custom policies.** "Is this agent allowed to call this tool" is an exact
question answered from config; re-expressing it as model adjudication would
convert a deterministic allow/deny into a confidence score. That is a
regression, not a port.

### The 20 in scope, and their 11 verdict schemas

| Schema | Guardrails |
|---|---|
| `is_toxic, toxicity_score, category, severity` | toxicity |
| `biased, bias_score, bias_type, severity` | bias_detection |
| `violates_policy, confidence, violation_type, reasoning` | custom_policy in/out |
| `violates_policy, confidence, risk_type, severity, reason` | payload_risk (agentic), role_based_policy |
| `is_injection, attack_type, confidence` | indirect_injection_detection, memory_injection_detection |
| `is_adversarial, attack_type, confidence` | adversarial |
| `is_unsafe, category, confidence` | topic_restriction |
| `is_drifting, category, confidence` | goal_drift_detection |
| `has_sensitive, action, confidence, findings` | tool_output_sanitization |
| `grounded, confidence, unsupported_claim` | factual_grounding |
| `compliant, detected_tone, severity` | tone_enforcement |

Plus `language_detection`, `topic_enforcement`, `hallucinated_links`,
`chain_of_thought_monitoring`, `role_based_policy` (output) on variants of the
above.

### Non-goals

- Changing the default family. `vai` stays default; `nemo` is opt-in.
- Running both families at once. Per-tenant and per-guardrail routing are
  explicitly rejected: both would need both models resident, which is the GPU
  cost this spec exists to avoid.
- Multimodal moderation. Nemotron accepts images; `--language-model-only` stays
  on. Image moderation is a separate spec.
- Porting the 36 deterministic guardrails.

## 2. Plane & latency contract

**Data plane only.** ON THE GUARD PATH (`/guardrails/input`,
`/guardrails/output`, `/tool/check`, `/tool/output`). `cap/mint` is untouched.

- **`family == "vai"` (default): zero added work.** The dispatch is one
  module-level cached env read; when it resolves to `vai` the guardrail takes
  its existing inline prompt and `parse_csv_response` call with no indirection.
  Target: < 0.05 ms, no new allocation on the hot path.
- **`family == "nemo"`:** one dict lookup plus the adapter's own prompt build
  and parse. Parsing Nemotron's line format is comparable in cost to
  `parse_csv_response`; the `<think>` strip is one `str.partition`.
- **Reasoning traces raise `max_tokens` for custom policies only** (approved:
  on for custom policy, off elsewhere). `custom_policy_*` goes 200 → 512
  `max_tokens`. That is a real latency increase on the slow tier and must be
  measured before enabling, not assumed. Every other adapter keeps its current
  budget (toxicity stays at 20).
- No added LLM calls, no added Redis reads, no added network.

## 3. Data model

**No new Redis keys. No new tenant config.** Family selection is a process-level
env var, deliberately not per-tenant (see non-goals).

The adapter contract, in `guardrails/nemo/`:

```python
class NemoAdapter(Protocol):
    max_tokens: int
    reasoning: bool                                  # <think> traces
    def build_messages(self, content: str, context: dict,
                       settings: dict) -> list[dict]: ...
    def parse(self, raw: str) -> dict: ...           # native guardrail schema
```

**`parse()` returns the exact dict the guardrail already expects.** Toxicity's
adapter returns `{"is_toxic": bool, "toxicity_score": float, "category": str,
"severity": str}`. Nothing downstream changes: thresholds, the
`suppressed_by_threshold` reporting shipped in #379, aggregation, actions,
monitor mode. This is the load-bearing decision that makes the port tractable.

### The score problem

Nemotron emits **labels**, not scores. `Safety Categories: Hate` has no
numeric confidence. Every threshold in this repo is numeric
(`toxicity.threshold: 0.7`, `bias_detection.threshold: 0.60`,
`confidence_threshold: 0.8`).

Adapters derive a score from severity via a fixed table:

| Nemotron signal | Derived score |
|---|---|
| `User Safety: safe` | 0.0 |
| unsafe, severity absent | 0.85 |
| unsafe + low / medium / high / critical | 0.4 / 0.65 / 0.85 / 0.95 |

**The derived score is stamped `details.score_source: "derived"`.** An operator
reading a `0.85` must be able to tell it came from a label mapping, not from the
model, or they will tune a threshold against a number that has only four
possible values. Given that today's two shipped bugs were both "a response that
misrepresented what the detector actually said", this is non-negotiable.

**The threshold structure is unchanged** (decided). `threshold`,
`confidence_threshold`, `bias_score` and friends keep the same names, the same
numeric type, and the same comparison semantics in both families. No tenant
config migration, no new config surface, and the `suppressed_by_threshold`
reporting from #379 works identically under `nemo`.

Consequence to accept up front: the *structure* carries over, the *calibration*
does not. A tenant on `threshold: 0.75` sees different behaviour under `nemo`,
because the score space collapses from continuous to four points — 0.75 sits
between the `medium` (0.65) and `high` (0.85) rungs, so it behaves exactly like
0.70 or 0.80 would. This is a migration note, not a bug, and §5 covers it.

## 4. API / interface

No new endpoints. No response-schema changes.

New env vars:

| Var | Default | Effect |
|---|---|---|
| `SHIELD_GUARDRAIL_FAMILY` | `vai` | `vai` \| `nemo`. Anything else fails closed to `vai` with a startup WARN. |
| `SHIELD_NEMO_REASONING` | `1` | `<think>` traces on custom-policy adapters. `0` disables. |
| `SHIELD_NEMO_STRICT` | `0` | `1` makes an unparseable Nemotron verdict raise instead of falling through. See §7. |

Every response gains `details.guardrail_family` when family is `nemo`, so a
support ticket carries which model produced the verdict.

New module layout:

```
guardrails/nemo/
  __init__.py        # active_family(), adapter_for(name)
  base.py            # NemoAdapter protocol, <think> strip, label→score table
  safety_head.py     # toxicity, bias_detection — native moderation output
  policy_mode.py     # the other 18 — Nemotron custom-policy mode
  prompts.py         # per-guardrail policy text
```

**These are not `BaseGuardrail` subclasses.** `guardrails/registry.py`
auto-discovers subclasses across `guardrails.input/output/agentic`; a class in
`guardrails/nemo/` named `toxicity` would collide on the registry key if that
package were ever added to the scan list. The adapters are plain objects, and a
test asserts `guardrails.nemo` is absent from `_discover_guardrails`' package
list.

Approved shape, per guardrail:

- **toxicity → `safety_head.py`.** Native moderation output, what the model was
  fine-tuned to produce, best accuracy.
- **bias_detection → `policy_mode.py`** (decided). Nemotron's safety taxonomy is
  not built to express the `Gender / Racial / Age / Political / Religious /
  Disability / Socioeconomic / Sexual orientation / Nationality /
  Neurodiversity / Name-based` categories in `config/default.yaml:155`, and
  today's prod evidence supports that: asked to classify *"John is the better
  fit because john is american"*, the current stack returned
  `bias_type: socioeconomic` for what is plainly nationality bias. Category
  fidelity is the whole point of this guardrail, so bias goes through
  policy mode where the taxonomy is stated explicitly in the policy text.
- **the other 18 → `policy_mode.py`.** The existing prompt becomes the policy
  text; the verdict maps back to that guardrail's schema.

## 5. Security & backward compatibility

- **Opt-in.** Unset var means today's exact behaviour. No tenant changes on
  upgrade.
- **Escape hatch.** `SHIELD_GUARDRAIL_FAMILY=vai` is the instant rollback, no
  redeploy of code, and it is the documented lever if `nemo` misbehaves.
- **Migration note required.** Thresholds do not transfer (see §3). The
  release note must say so and give the mapping table, or tenants will read
  their unchanged `threshold: 0.75` as unchanged behaviour.
- **The silent-pass hazard is the main security risk.** On a format mismatch,
  `result.get("is_toxic", False)` → `False` → "No toxic content detected" →
  pass, and `custom_policy` raises → fail open. A wrong adapter therefore
  degrades to allow-everything with clean 200s. Mitigations, all required:
  - `SHIELD_NEMO_STRICT=1` in staging so mismatches are loud.
  - A parse-failure counter emitted to telemetry per guardrail, so a silent
    regression is visible in the portal rather than only in a curl.
  - The parity harness in §8 fails the build on any verdict-shape mismatch.
- **Authz unchanged.** No new endpoints, no new tenant-facing surface.

## 6. Packaging & deploy

- **New modules:** all under `guardrails/nemo/`, imported only by the 20
  LLM-backed guardrails. **None are imported by `admin_app.py`**, so no
  `Dockerfile.admin` COPY changes. Verified: `admin_app.py` imports no
  `guardrails.*` module, and `Dockerfile.admin` copies only `base.py`,
  `registry.py` and `rbac_guard.py`, none of which gain a `guardrails.nemo`
  import in this change. `tests/test_admin_dockerfile_imports.py` remains the
  guard.
- **Dependencies:** none new. Parsing is stdlib string handling.
- **Serving env:** unchanged from the predecessor spec, already tested in
  `tests/test_vllm_model_option.py`:
  `MODEL_NAME=nvidia/Nemotron-3.5-Content-Safety VLLM_QUANTIZATION=none
  VLLM_KV_CACHE_DTYPE=none VLLM_PERFORMANCE_MODE=none VLLM_NOTHINK_SUFFIX=false`

### `Dockerfile.nemo` (decided)

A sixth image, alongside `Dockerfile`, `.litellm`, `.admin`, `.cloud`,
`.gateway`, `.dev`. It exists because the dependency floor genuinely differs,
not just the env block:

| | data-plane `Dockerfile` | `Dockerfile.nemo` |
|---|---|---|
| `ARG VLLM_BASE_IMAGE` | `vllm/vllm-openai:latest` | pinned inside Nemotron's documented `vllm>=0.11.0,<=0.20.2` |
| pip requirements | `requirements.txt` | `requirements.txt` + `requirements-nemo.txt` |
| `ENV MODEL_NAME` | `votal-ai/vai35-4B-v2` | `nvidia/Nemotron-3.5-Content-Safety` |
| `ENV SHIELD_GUARDRAIL_FAMILY` | unset (`vai`) | `nemo` |
| vLLM flag defaults | fp8 quant + fp8 KV | `VLLM_QUANTIZATION=none`, `VLLM_KV_CACHE_DTYPE=none`, `VLLM_PERFORMANCE_MODE=none`, `VLLM_NOTHINK_SUFFIX=false` |

The point of the image is that **none of those five env vars has to be
remembered at deploy time**. A RunPod endpoint pointed at
`llm-shield-nemo:latest` is correct by construction; today it is correct only if
the operator sets every var by hand, and a single missed
`VLLM_NOTHINK_SUFFIX=false` silently injects Qwen thinking tokens into every
Nemotron prompt.

**`requirements-nemo.txt`** carries the model card's floor:
`transformers>=4.57.1,<=4.57.6`, `torch==2.8.0`, `pillow>=12.0.0,<=12.2.0`.
None of these is pinned in any current `requirements*.txt`; the base image
supplies them today. Task 1 must confirm whether the pinned vLLM base already
satisfies the window, in which case this file states the constraint rather than
changing the install. Either way the constraint becomes explicit instead of
inherited by luck.

**Drift guard.** The data-plane Dockerfile copies whole directories
(`COPY core/ core/`, `COPY guardrails/ guardrails/`, …), not the per-file
allowlist that makes `Dockerfile.admin` fragile, so the duplication risk is
eight lines rather than a hundred. `tests/test_nemo_dockerfile.py` asserts the
two files copy the same set of source directories, so a new top-level package
added to one fails the build until it is added to the other. This is the
analogue of `tests/test_admin_dockerfile_imports.py`.

**CI.** One entry in the `.github/workflows/build.yml` matrix
(`name: nemo, dockerfile: Dockerfile.nemo, image: llm-shield-nemo`), plus the
`free-disk-space` conditional extended from `matrix.name == 'vllm'` to also
cover `nemo` — it is the same ~10 GB vLLM base and will exhaust the runner's
disk without it. Per the self-contained-PRs invariant this lands in the same PR
as the Dockerfile, not after.

- **Rebuild:** data-plane image (for the family seam, which ships inert) and the
  new nemo image.

## 7. Failure modes & edge cases

| Case | Behaviour |
|---|---|
| `SHIELD_GUARDRAIL_FAMILY` set to garbage | Fall back to `vai`, WARN at startup. Fail-safe, since `vai` is the known-good path. |
| Family is `nemo` but a `vai` model is actually served | Every verdict fails to parse. With `SHIELD_NEMO_STRICT=0` (default) each guardrail takes its existing error path, which is fail-open, and the parse-failure counter spikes. With `=1` the guardrail raises and its configured action applies. **Fail-open is the default only because it matches every guardrail's current error behaviour**; the counter is what makes it detectable. |
| `<think>` trace present but unterminated (hit `max_tokens`) | Treated as unparseable. Counter increments. Argues for generous `max_tokens` on reasoning adapters. |
| Nemotron returns a safety category not in the mapping table | Verdict is still `unsafe`; category passes through verbatim, score uses the severity-absent default (0.85). Never silently downgraded to safe. |
| `Safety Categories` absent on an `unsafe` verdict | `category: "unspecified"`, still unsafe. |
| Empty or whitespace content | Unchanged: guardrails short-circuit before the model call. |
| Nemotron slow / unavailable | Unchanged. Same error paths as today. |
| A guardrail has no adapter registered | Falls back to the `vai` prompt against whatever model is served, and logs once per process. Prevents a half-finished port from taking the suite down, but is visible. |

## 8. Test plan (Definition of Done)

New: `tests/test_nemo_adapters.py`, `tests/test_guardrail_family_parity.py`.

Unit:
1. `active_family()` defaults to `vai`; garbage falls back to `vai`; `nemo` resolves.
2. With family `vai`, no adapter is consulted — patch `adapter_for` and assert not called. This is the zero-cost latency claim.
3. Each of the 11 schemas: adapter `parse()` returns exactly the field names and types the guardrail reads, asserted against the real `_CSV_FIELDS` constants so a rename in either place fails the test.
4. `<think>...</think>` traces are stripped before parsing; an unterminated trace is unparseable.
5. Label→score table, all five rows, and `details.score_source == "derived"` on every derived verdict.
6. `Safety Categories` absent, unknown category, `safe` verdict, malformed line.
7. `SHIELD_NEMO_STRICT=1` raises on unparseable; `=0` takes the existing error path and increments the counter.
8. `guardrails.nemo` is not in the registry's discovery package list, and no adapter subclasses `BaseGuardrail`.
9. A guardrail with no registered adapter falls back to `vai` and logs once.

Parity harness (the important one):
10. A golden set of ~40 inputs per guardrail (clean, clearly-violating, borderline) is run through both families with the model call stubbed at the transport layer. Assert both produce the same `GuardrailResult` **shape**, the same field names, and the same allow/block decision on the clean and clearly-violating cases. Borderline cases are recorded, not asserted — the two models will disagree there and that is expected.
11. Regression: the dilution case from #378 and the `is_toxic: true` suppression case from #379 both behave correctly under `nemo`.

Live (manual, documented, not in CI): serve Nemotron on a RunPod endpoint, run the parity set for real, record per-guardrail accuracy and p50/p95 latency against the current `vai35-4B-v2` numbers. **BENCHMARKS.md is currently measured on `vai35-9B`, so it is not a valid baseline for this comparison and must be re-run on the shipped 4B first.**

Done means: full suite green via `python -m pytest tests -q` in a clean venv, CI `pytest` gate passing, and the live parity numbers recorded in the PR.

## 9. Task breakdown

One branch, `feat/nemo-guardrail-family`, commits in order.

| # | Commit | Scope |
|---|---|---|
| 1 | Probe | Serve Nemotron on a scratch endpoint, drive toxicity and a policy-mode case by hand, capture the exact native output strings (including a `<think>` sample), and confirm whether the pinned vLLM base already satisfies `transformers 4.57.1–4.57.6` / `torch 2.8.0`. **Findings pasted into this spec before task 2 starts.** No product code. |
| 2 | Seam, inert | `active_family()`, `adapter_for()`, dispatch in the 20 guardrails, `guardrails.nemo` package with zero adapters registered. Family `nemo` falls back to `vai` everywhere. Tests 1, 2, 8, 9. Provably no behaviour change on either family. |
| 3 | Safety head | toxicity adapter, label→score table, `score_source: "derived"`. Tests 3 (toxicity), 5, 6. |
| 4 | Policy mode | The other 19 adapters including bias, `<think>` handling, reasoning flag, `max_tokens` 200 → 512 for custom policies. Tests 3 (rest), 4, 7. |
| 5 | `Dockerfile.nemo` | The image, `requirements-nemo.txt`, the `build.yml` matrix entry, the `free-disk-space` conditional, and `tests/test_nemo_dockerfile.py`. Self-contained: image, deps, CI and drift guard together. |
| 6 | Parity harness + docs | Tests 10, 11; the threshold-calibration migration note; family table in the guardrails doc. |

## 10. Decisions taken

| Question | Decision |
|---|---|
| Structure of `guardrails/nemo/` | Adapter pack: prompt + verdict parser per guardrail, the 20 guardrail classes stay single-source. |
| Family selection | Global env var `SHIELD_GUARDRAIL_FAMILY`, one model per deployment. Per-tenant and per-guardrail routing rejected — both need two models resident. |
| How Nemotron is driven | Native safety head for toxicity; custom-policy mode for the other 19. |
| Reasoning traces | On for custom-policy adapters, off elsewhere. |
| Does the taxonomy cover bias | No. `bias_detection` goes through policy mode, where the category list is stated explicitly. |
| Threshold structure | Unchanged from `vai`. Same names, same numeric semantics, no config migration. Calibration differs; that is a release note. |
| Separate image | Yes, `Dockerfile.nemo` + `requirements-nemo.txt` + a CI matrix entry + a drift guard. |

### Still open

1. **Does the pinned vLLM base already satisfy `transformers 4.57.1–4.57.6` and `torch 2.8.0`?** Task 1 answers it. If it does, `requirements-nemo.txt` states the constraint; if not, it changes the install and the image gets meaningfully heavier.
2. **`vai35-4B-v2` has no published benchmark.** BENCHMARKS.md is measured on `vai35-9B`, so there is no valid baseline for the accuracy or latency comparison in task 6. Re-running it on the shipped 4B is a prerequisite for any "Nemotron is faster/slower/better" claim, and is not scoped in this spec.
