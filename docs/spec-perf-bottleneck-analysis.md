# Spec: GPU throughput bottleneck analysis for the vLLM guardrail data plane

## 1. Problem & outcome

We cannot currently state the maximum sustainable throughput of the guardrail data
plane, nor which resource caps it. Two concrete gaps:

1. **No instrument.** Nothing in the repo reads vLLM's Prometheus `/metrics`
   endpoint. Nothing reads `usage.prompt_tokens` or prefix-cache statistics off an
   LLM response; the only token figures anywhere are the `len(text)/3.5` heuristic in
   `core/text_utils.py:18-20`. Without `num_requests_waiting`,
   `gpu_cache_usage_perc`, and prefix-cache hit rate there is no evidence-based way
   to say whether the GPU is the bottleneck.
2. **No saturating load generator.** `scripts/stress_test_guardrails.py` is
   closed-loop only: `asyncio.Semaphore(concurrency)` with every task created upfront
   (`:466-481`), no arrival-rate pacing, no warmup, no steady-state window. Its req/s
   (`:536-539`) is `total/wall`, which includes ramp-up and drain. A closed-loop
   harness cannot distinguish "9 req/s is the ceiling" from "9 req/s is what 10
   clients happen to produce".

The specific claim under test: `BENCHMARKS.md:71` states "~9 req/s across concurrency
levels, indicating the GPU is efficiently batching requests without saturation".
Flat throughput from c=5 to c=10 while p50 grows 1.9x to 3.6x is the signature of a
system that is already saturated, not one with headroom. Throughput stopped scaling
and only queue depth grew.

**Observable success condition.** Running the two new scripts inside a RunPod pod
yields a JSON artifact from which we can state, with the supporting timeseries:

- max sustainable req/s at a named p95 SLA, for a named payload shape;
- which resource binds (prefill token budget, KV cache, sequence slots, or the app
  process itself);
- a ranked list of knobs with expected effect.

**Non-goals (explicitly out of scope):**

- Any change to guard-path code. `api/routes_classify.py`, `storage/guardrail_metrics.py`,
  `core/llm_backend.py`, `core/pipeline.py`, and every module under `guardrails/`
  are untouched by this PR.
- Any change to `scripts/start_vllm.sh` or `tf/vllm.tf`. The playbook recommends
  flags to expose; a follow-up PR exposes them.
- Fixing the prefix-cache losses caused by message ordering (see §7). This PR
  measures them only.
- Making `record_results_batch` non-blocking. Diagnosed here, fixed in a follow-up
  spec written once the measurement lands.
- Kubernetes / `tf/` topology tuning. Target topology is the single RunPod pod.
- Any new endpoint, any Redis key, any admin-plane change.
- Committing measured numbers. The scripts and the playbook structure land here; the
  numbers land after a run on the GPU box.

## 2. Plane & latency contract

- **Plane: data plane, observationally only.** The deliverables are two standalone
  scripts under `scripts/` and one doc under `docs/`. No module in `core/`, `api/`,
  `guardrails/`, or `storage/` is modified. Admin plane untouched; `admin_app.py`
  imports nothing under `scripts/`.
- **Guard path: off hot path, no guarded-traffic impact.** `/guardrails/*`,
  `cap/mint`, and `tools/call` are not modified. The scripts are external clients
  that generate load against those endpoints from outside the process, exactly as
  `scripts/stress_test_guardrails.py` does today. Zero lines of request-handling
  code change, so there is no latency budget to justify.
- One deliberate consequence of the "diagnose only" scope: the app-side attribution
  is obtained from **already-emitted** signals rather than new instrumentation.
  `inference_time_ms` is computed inside `_build_response`
  (`api/routes_classify.py:581-594`), which runs *before* the synchronous
  `resolve_request_tenant_id` + `record_results_batch` block at `:258-261`, while
  `x-latency-ms` is set by the outer telemetry middleware
  (`core/telemetry_middleware.py:215`). Their difference already exposes the blocking
  tail without touching the hot path.

## 3. Data model

- **None.** No Redis keys, no TTLs, no tenant state written or read by the new code.
- Tenant scoping: the load scripts authenticate with an operator-supplied
  `--api-key` and therefore act as an ordinary tenant client. They gain no
  visibility they did not already have. `vllm_metrics_probe.py` reads a
  process-local Prometheus endpoint that is not tenant-scoped and contains no tenant
  data, only aggregate scheduler counters.
- Output artifacts are JSON files written to an operator-chosen `--out` path. They
  contain latencies, counters, and the operator's own synthetic payload shape. See
  §5 for what must not end up in them.

## 4. API / interface

No endpoint changes. Three new files plus two edits.

### `scripts/_perf_common.py` (new)

```python
def parse_prom_text(text: str) -> dict
def histogram_quantile(buckets: dict, q: float) -> float | None
def percentiles(values: list[float], qs=(50, 90, 95, 99)) -> dict
def build_guardrail_payload(chars: int, unique_tail: str) -> dict
def extract_response_timings(body: dict, headers) -> dict
```

`parse_prom_text` handles the Prometheus text exposition format directly: `# HELP` /
`# TYPE` comment lines, `name{labels} value` samples, and `_bucket` / `_sum` /
`_count` histogram families. No `prometheus-client` dependency.

`extract_response_timings` returns `inference_time_ms`, `x_latency_ms`, and
`chunks_checked`, reusing the `details.chunks_checked` extraction pattern already in
`scripts/benchmark_latency_runpod.py:149-152` so chunk fan-out is recorded next to
every latency sample.

### `scripts/vllm_metrics_probe.py` (new)

```
--url http://127.0.0.1:8000/metrics
--interval 1.0          # sampling interval, seconds
--duration 0            # 0 = run until SIGINT
--out metrics.json
--label <string>        # stamped into the artifact for correlation
```

Sampled metrics and why each one matters for this workload:

| Metric | Reads as |
|---|---|
| `vllm:num_requests_waiting` | The saturation signal. Sustained above zero means saturated. Settles the `BENCHMARKS.md:71` claim on its own. |
| `vllm:num_requests_running` | Actual batch occupancy, compared against `MAX_NUM_SEQS=48`. |
| `vllm:prompt_tokens_total` | Differentiated to give prefill tokens/sec, the real throughput unit here. |
| `vllm:generation_tokens_total` | Expected tiny; confirms decode is not the constraint. |
| `vllm:gpu_cache_usage_perc` | KV pressure. Expected low given short sequences, which would rule out KV as the bottleneck. |
| `vllm:gpu_prefix_cache_hit_rate`, or `vllm:gpu_prefix_cache_queries_total` + `vllm:gpu_prefix_cache_hits_total` | Quantifies the prompt-assembly losses in §7. Ratio computed locally when only counters are exposed. |
| `vllm:num_preemptions_total` | Non-zero means KV thrashing, which would flip the diagnosis to KV-bound. |
| `vllm:request_queue_time_seconds` | GPU-side queue wait, directly comparable against client wall time. |
| `vllm:request_prefill_time_seconds`, `vllm:request_decode_time_seconds` | Splits prefill from decode inside the server. |
| `vllm:time_to_first_token_seconds` | For this workload TTFT is essentially the whole request. |
| `vllm:iteration_tokens_total` | Tokens per scheduler step versus `MAX_BATCHED_TOKENS`; tests the core hypothesis in §7 head-on. |
| `vllm:e2e_request_latency_seconds`, `vllm:request_success_total` | Sanity and error accounting. |

Output: `{"label":…, "url":…, "interval":…, "samples":[{"t": <unix>, …}], "summary":{…}, "missing":[…]}`.

### `scripts/saturation_sweep.py` (new)

```
--target guardrails|vllm-direct
--url / --api-key
--rates 2,5,10,15,20,30,50
--warmup 20  --steady 60
--payload-mode fixed-short|mixed  --payload-chars 400
--arrival poisson|uniform  --seed 42
--sla-p95-ms 1000
--max-inflight 2000
--probe-metrics-url <url>
--out sweep.json
```

`--target vllm-direct` posts to `:8000/v1/chat/completions` using the real
adversarial system prompt via `guardrails.input.adversarial._active_system_prompt()`
with `max_tokens=20, temperature=0`, so the synthetic load is exactly prompt-shaped
rather than a guess. This is a read-only import of an existing module; it does not
modify it.

Per-level output includes `offered_rate`, `achieved_rate`, latency percentiles, a
per-second throughput timeseries inside the steady window, `chunks_checked`
distribution, and a `feasible` boolean. Top-level output includes the detected knee
and plateau.

### Edits

- `requirements-test.txt`: add `aiohttp`. `scripts/stress_test_guardrails.py:34`
  imports it today and it is declared in neither `requirements.txt` nor
  `requirements-test.txt`. This is a live violation of the declare-dependencies
  invariant discovered while inventorying the load tooling, and per the
  don't-strand-companion-fixes rule it belongs in this PR.
- `scripts/README.md`: one short entry per new script.

Auth: the load scripts send `X-API-Key` exactly as `stress_test_guardrails.py` does.
No router is mounted, so no plane mounts anything new.

## 5. Security & backward compatibility

- **Default behavior: unchanged.** These are new, separately-invoked scripts. No
  existing code path is modified, so there is nothing to opt into and no migration
  note. Adding `aiohttp` to `requirements-test.txt` only makes an existing implicit
  dependency explicit; it cannot change runtime behavior because it is not in
  `requirements.txt`.
- **No escape-hatch flag needed** because no default changes.
- **Authz.** The scripts are operator tools run by whoever already holds a tenant API
  key and shell access to the pod. They grant no new capability: the load path is
  the same public `/guardrails/input` any key holder can call, and `/metrics` is
  bound to `127.0.0.1:8000` inside the pod, reachable only by someone who already
  has code execution there. A malicious caller gains nothing, because nothing new is
  exposed over the network.
- **Artifacts must not carry secrets.** The JSON output records the payload *shape*
  (length, category, chunk count), never the API key and never response bodies. The
  `--api-key` value is read from the flag or environment and must not be echoed into
  the artifact or into any log line. This is asserted in tests.
- **Load generation is destructive to a shared environment.** The playbook must state
  that a saturation sweep deliberately drives the data plane past its knee and must
  only be run against a dedicated benchmark pod, never a tenant-serving deployment.

## 6. Packaging & deploy

- **`Dockerfile.admin`: no change required.** `admin_app.py` imports nothing under
  `scripts/`, so the curated COPY allowlist is unaffected.
  `tests/test_admin_dockerfile_imports.py` continues to pass unchanged.
- **New pip deps: none.** Both new scripts use `httpx`, already a runtime dependency
  and already the transport in `core/llm_backend.py:167`. Prometheus text is parsed
  with the standard library, so `prometheus-client` is not added. The only
  requirements change is declaring the pre-existing `aiohttp` import in
  `requirements-test.txt`.
- **`requirements-admin.txt`: no change.** The admin plane does not use any of this.
- **Env flags: none introduced.** All configuration is CLI flags on the new scripts.
- **Images to rebuild: none required for correctness.** The scripts ship in the repo
  and are run inside the existing data-plane container. To use them in an already
  built image, rebuild the data-plane `Dockerfile` so the new files under `scripts/`
  are present, or copy them in ad hoc for a one-off run.
- **Rollout: no deploy step.** Nothing in the serving path changes.

## 7. Failure modes & edge cases

**Analytical premises this design rests on** (verified by static reading; the
measurement is what confirms them):

- The workload is prefill-dominated with negligible decode. `max_tokens` per call is
  20 for adversarial and toxicity, 40 for topic_enforcement, 60 for topic_restriction
  and pii, 5 for language_detection. All `temperature=0`, thinking disabled via
  `chat_template_kwargs` and a `/no_think` suffix (`core/llm_backend.py:597`,
  `:467-479`). Static prompts run roughly 1030 tokens plus a 360-token user prefix
  for adversarial, down to 175 tokens for pii.
- Therefore the throughput unit is prefill tokens/sec, and
  `MAX_BATCHED_TOKENS=8196` is the likely binding vLLM constraint rather than
  `MAX_NUM_SEQS=48`: at roughly 1600 static tokens per request under the default
  two-guardrail config (`config/default.yaml:62-63,74-75`), the token budget admits
  only about five uncached prefills per scheduler step, while 48 sequence slots bind
  only during a decode phase that is 20 to 60 tokens long. This contradicts the
  capacity formula at `BENCHMARKS.md:200-206`.
- Prefix-cache hit rate multiplies throughput, because cached prefix tokens do not
  consume the prefill token budget. `--enable-prefix-caching` is on
  (`scripts/start_vllm.sh:64`), but the hit rate is partially defeated:
  `adversarial.py:410-412` and `toxicity.py:61-63` order messages as
  `[system] + [history...] + [static prefix + content]`, so on multi-turn requests
  about 360 tokens of static few-shot text sits after variable history and falls
  outside the cacheable prefix; `topic_enforcement.py:90-131` injects `{rules}` at
  `:33` leaving roughly 540 tokens of static text after the variable region;
  `custom_policy.py:94-119` and `role_based_policy.py:163-198` build a single user
  message with no system role and embed user text before a per-request `session_id`,
  leaving a shared prefix of about 106 characters.

**Failure modes and how each is handled:**

| Case | Handling |
|---|---|
| **Missing or renamed vLLM metrics.** The base image is pinnable (`Dockerfile:1-6`) so the vLLM version, and therefore V0 vs V1 metric naming, is effectively unknown. | Hard requirement: the probe samples whatever is present, resolves names through an alias table (for example `gpu_cache_usage_perc` vs `kv_cache_usage_perc`), records absent names in a `missing[]` list, and never raises. Fail-open. |
| **`/metrics` unreachable or non-200.** | Record the error in the sample with a null value and continue sampling. A dead endpoint must not abort a load run that is already in flight. Fail-open. |
| **Malformed Prometheus line.** | Skip the line, count it in a `parse_errors` counter, continue. Fail-open. |
| **Histogram present but all buckets empty** (no requests yet). | `histogram_quantile` returns `None`, not a division-by-zero or a fabricated 0.0. |
| **Counter reset** (vLLM restarts mid-run). | A negative delta between samples is reported as `None` for that interval rather than a negative rate, and flagged in the summary. |
| **Offered rate is infeasible.** The system cannot keep up and the in-flight set grows without bound. | Track in-flight count; when it exceeds `--max-inflight` (default 2000) mark the level `feasible: false`, stop issuing, drain, and continue to the next level. Always report `offered_rate` alongside `achieved_rate`; their divergence is the finding, not an error. |
| **Coordinated omission.** A naive "sleep 1/lambda after the previous response" loop silently converts overload into a lower offered rate and hides the ceiling entirely. | Request *i* is scheduled at `t0 + i/lambda`, computed upfront. If the harness is late it fires immediately and records latency from the **scheduled** time, not the send time. Asserted in tests under simulated lateness. |
| **Chunk fan-out confounds req/s.** Every guardrail `asyncio.gather`s over chunks (`adversarial.py:519-524`, `pii_detection.py:178-183`, `toxicity.py:144-149`, `topic_restriction.py:242-247`) with budgets from `core/text_utils.py:9-15,30-34`. A 120K-character input becomes about 17 chunks, so one API request can be 3x17 = 51 vLLM sequences against 48 sequence slots. | Default `--payload-mode fixed-short` pins input length so chunk count is 1. `chunks_checked` is recorded on every sample so any fan-out is visible rather than silent. The playbook states plainly that a req/s figure measured without pinning input length is meaningless. |
| **A single byte-identical payload would be fully prefix-cached**, including the user content, producing an unrealistically high ceiling. | `build_guardrail_payload` emits a fixed *length* with a randomized unique tail, so only the static prompt caches. This is the realistic steady state. Asserted in tests. |
| **Huge or empty `--payload-chars`.** | Validate at parse time: reject values below a floor that would produce an empty message, and warn above the single-chunk threshold derived from `core/text_utils.py` budgets. |
| **Redis down during a run.** | Not the scripts' concern, but it changes what is being measured. The playbook's E5 experiment makes the Redis dependency an explicit variable rather than an uncontrolled one. |
| **`--target vllm-direct` when `guardrails.input.adversarial` cannot be imported** (run from outside the repo root). | Fail fast with an actionable message naming the required working directory. Fail-closed: silently substituting a fabricated prompt would invalidate the entire measurement. |
| **SIGINT mid-run.** | Both scripts flush the artifact written so far before exiting, so a long sweep interrupted at level 5 of 7 still yields usable data. |

**Fail-open vs fail-closed, stated explicitly.** Metrics collection fails **open**:
a missing or broken counter degrades the artifact but never aborts a run, because
losing a whole GPU-box run to one absent gauge is the worse outcome. Measurement
*validity* fails **closed**: anything that would silently produce a wrong number
(unimportable real prompt, unvalidated payload size) aborts with a clear error.

## 8. Test plan (Definition of Done)

All tests run without a GPU and without a network.

| File | Covers |
|---|---|
| `tests/test_perf_prom_parse.py` | `parse_prom_text` against V0 and V1 fixtures; histogram families (`_bucket`/`_sum`/`_count`); `histogram_quantile` including the all-empty-buckets case returning `None`; graceful degradation against a minimal fixture where most metrics are absent, asserting a populated `missing[]` and no exception; malformed-line skip with `parse_errors` incremented; counter-reset producing `None` rather than a negative rate. |
| `tests/test_perf_knee_detection.py` | Knee and plateau math over synthetic level results: normal saturating curve, never-saturates curve, all-levels-infeasible, single level, and a curve where the SLA breaks before the plateau. |
| `tests/test_perf_pacing.py` | Absolute schedule generation for both `uniform` and seeded `poisson`; latency measured from scheduled time under simulated lateness (the coordinated-omission guard); `--max-inflight` abort marking the level infeasible and still emitting a record. |
| `tests/test_perf_payload_builder.py` | Fixed-length payload stays within one chunk given the `core/text_utils` budgets; the unique tail differs across calls; the static prefix is byte-identical across calls; out-of-range `chars` is rejected. |
| `tests/test_perf_artifact_no_secrets.py` | The API key never appears in the serialized artifact or in any emitted log line. |

Fixtures: `tests/fixtures/vllm_metrics_v0.txt`, `tests/fixtures/vllm_metrics_v1.txt`,
`tests/fixtures/vllm_metrics_minimal.txt`.

**Regression guards for drift-prone couplings:**

- `tests/test_vllm_model_option.py` must still pass unchanged, confirming
  `scripts/start_vllm.sh` was not touched. Its `VLLM_DRY_RUN` harness asserts the
  seven pinned default flag substrings, the absence of `--served-model-name`, and
  exactly one `DRY_RUN_ARGS:` line.
- `tests/test_admin_dockerfile_imports.py` must still pass, confirming the admin
  COPY allowlist is unaffected.
- A test asserting the new scripts import successfully with only
  `requirements-test.txt` installed, so an undeclared dependency cannot creep in
  unnoticed the way `aiohttp` did.

**Definition of done:**

- `python -m pytest tests -q` green from the repo root.
- Green in a **clean venv**:
  `python -m venv /tmp/x && /tmp/x/bin/pip install -r requirements-test.txt`.
- The CI `pytest` gate passes.
- `docs/performance-bottleneck-analysis.md` exists with the experiment matrix and
  bottleneck decision tree, and explicitly reconciles the five `BENCHMARKS.md`
  discrepancies: model 9B versus the shipped 4B-v2 (`:8` vs `Dockerfile:45`),
  `max-num-seqs` 128 versus the actual 48 (`:12` vs `start_vllm.sh:40`), chunked
  prefill claimed (`:10,198,391`) but passed by neither launcher, the capacity
  formula ignoring chunk fan-out (`:200-206`), and the "without saturation" claim
  (`:71`).
- Measured numbers are explicitly **not** part of this Definition of Done. They
  arrive from a run on the GPU box, after which `BENCHMARKS.md` is corrected and a
  follow-up spec is written for whatever the verdict points at.
