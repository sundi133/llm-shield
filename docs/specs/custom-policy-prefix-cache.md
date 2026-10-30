# Spec: custom-policy prompts laid out for prefix caching

Status: **approved 2026-10-30.** Implemented on branch
`feat/custom-policy-prefix-layout` with **`cached` as the default**: at the
user's request (2026-10-30) task 3 (switch the default) ships with task 1,
ahead of the task 2 accuracy run. Prefix caching is enabled on both the
on-prem vLLM and the Together AI deployment of the same model. `legacy`
restores the old prompt byte for byte. Task 2 (eval set and measurement) is
still to do and is now the check after the switch rather than the gate
before it.

## 1. Problem & outcome

Each enabled natural-language custom policy is one guardrail-model call per
request, and the calls run concurrently (`asyncio.gather` in
`guardrails/input/custom_policy.py` and `guardrails/output/custom_policy.py`).
They all judge the same text, so a model server with prefix caching (vLLM is
started with `--enable-prefix-caching`, `scripts/start_vllm.sh`) should process
that text once. It doesn't, because of how the prompt is laid out:

1. "You are a content policy evaluator..." (same for every policy)
2. **policy name, description, criteria** (different per policy)
3. the text to judge (same for every policy, but after part 2)
4. context, scan instruction, answer format (same for every policy)

A prefix cache reuses only the start of a prompt up to the first difference,
which is part 2. Measured on the shipped template with a 400-token text: 652
prompt tokens per policy, **25 shared (4%)**. With the cap now 25 policies
(PR #536), one request can prefill the same text 25 times.

**Outcome:** everything that is the same for every policy of a request comes
first, the policy comes last, so the shared prefix is the whole prompt except
the policy section. Verdicts stay as good or better, measured before the
switch. Observable success:
- every policy's prompt for one request is byte-identical up to the policy
  section (tested), about 90% of the tokens for a 400-token text;
- on vLLM, the prefix-cache hit rate for custom-policy calls goes up and
  prefill time per request goes down (measured, section 8);
- block/pass decisions on the evaluation set agree with the labels at least as
  often as today, with no new parse errors.

**Non-goals:**
- one call evaluating all policies at once (different semantics and failure
  modes; separate spec if wanted);
- the redaction prompt in `guardrails/output/custom_policy.py` (one call per
  request, not one per policy);
- Sigma policies (no model call);
- warming or staggering calls to force cache hits (section 2.3 explains why
  not now);
- other guardrails' prompts.

## 2. Plane & latency contract

- **Data plane, guard path:** `/guardrails/input`, `/guardrails/output`, the
  chat proxies and the LiteLLM route all run custom policies. No admin-plane
  change. `Dockerfile.admin` unaffected (no new module).
- **Budget:** no added work. The prompt is the same length (plus a one-line
  reminder, section 4) and built the same way. Expected effect is a latency
  *reduction* where the server caches prefixes; on servers that don't, latency
  is unchanged within noise. The task measures both (section 8) and the spec
  is not done until the numbers are in.

### 2.1 Where it helps

| Deployment | Effect |
|---|---|
| vLLM (RunPod, on-prem), `--enable-prefix-caching` | Main benefit: the text is prefilled about once per request instead of once per policy. |
| Ollama (Railway) | Little: parallel requests run in separate slots that don't share a cache. Not measured; keep `legacy` there. |
| Cloud model behind an OpenAI-compatible API | Provider-dependent. Automatic caching often needs prompts over about 1,024 tokens; most of these are shorter. Unchanged, not worse. |

### 2.2 What must stay true for caching
Anything before the policy section must be identical for every policy of one
request, and anything before the text should be identical across requests:
- no per-policy value (name, id, priority, threshold) before the policy section;
- no timestamp, nonce, random id or per-call value anywhere before it;
- per-request values (user role, session id, the text) after the static
  instructions, so the static header is cached across requests too;
- multi-turn history (`build_policy_messages`) stays as earlier messages, the
  same for every policy (it already is, when every policy has the same
  `multi_turn` setting; policies with `multi_turn` off share a prefix with each
  other, as do those with it on);
- `core/llm_backend.py` adds nothing per policy: `_ensure_no_think` edits only
  a system message, the same for all (checked).

### 2.3 Concurrency caveat
All policy calls of one request are sent at the same moment. vLLM can only
reuse a prefix block once it has been computed, so calls scheduled in the very
same step may each compute it. The saving is real but partial and grows with
text length and policy count. Staggering calls (send one, then the rest) would
force hits but adds a round trip of latency; out of scope until the
measurement says it's worth it.

## 3. Data model

None. No stored data, settings or API change. One new environment variable
(section 4).

## 4. Interface

New prompt layout, the same for input and output (`Stage:` and the noun differ
as today):

```
You are a content policy evaluator. You will be given a text and then ONE
policy. Decide whether the text violates that policy.

{POLICY_SCAN_INSTRUCTION}

Respond with ONLY one CSV line: violates_policy,confidence,violation_type,reasoning
Use "none" for violation_type when there is no violation. Do not quote fields;
reasoning is last so a comma inside it is harmless.
Example: true,0.95,pii_disclosure,message shares a full name and card number
Example: false,0.90,none,no policy violation found

CONTEXT:
- User Role: {user_role}
- Session ID: {session_id}
- Stage: Input validation

INPUT TEXT TO ANALYZE (everything between the markers):
<<<BEGIN TEXT
{text, end marker neutralised}
END TEXT>>>

POLICY INFORMATION:
- Name: {name}
- Description: {description}

EVALUATION CRITERIA:
{criteria}

Judge the text above against this policy only. Answer with the one CSV line.
```

- Static instructions first (cached across requests), then per-request values
  and the text (cached across the policies of a request), then the policy, then
  a one-line reminder so the format instruction is also the last thing the
  model reads.
- **End marker neutralised:** a literal `END TEXT>>>` inside the text is
  rewritten (`END TEXT>>>` becomes `END TEXT>>&gt;`) before insertion, so text
  can't close the fence early and append fake criteria. Today the criteria come
  before the text so this mattered less; with the policy last it must hold.
  Applied in `cached` only, so `legacy` stays byte for byte (decided
  2026-10-30: change only the order).
- The response parser is unchanged (same CSV line).
- **Escape hatch:** `SHIELD_CUSTOM_POLICY_PROMPT_LAYOUT=legacy` restores
  today's prompt byte for byte, read per call. Default `cached`.

## 5. Security & backward compatibility

- **Prompt injection:** the text now precedes the criteria. Mitigated by the
  neutralised end marker and by the criteria plus the reminder being the last
  thing the model reads. The evaluation set includes injection cases (section
  8) and the switch is blocked if any of them flips from block to pass.
- **Verdict drift:** reordering can change what a model decides. Section 8 is
  the gate: the new layout ships as default only if it is at least as accurate
  as the old on the same model, with no new parse errors. If it is worse on a
  model, that model's deployments keep `legacy` and the doc says so.
- **Behaviour-changing default with escape hatch:** `legacy` reproduces the old
  prompt exactly (tested). Migration note in the custom-policy docs.
- No credential, tenant or isolation change.

## 6. Packaging & deploy

Two files change (`guardrails/input/custom_policy.py`,
`guardrails/output/custom_policy.py`), plus a shared prompt builder in
`core/text_utils.py` next to `build_policy_messages`. No dependency, no
Dockerfile change. The env var is documented with the custom-policy settings.

## 7. Failure modes & edge cases

| Case | Result |
|---|---|
| Text contains `END TEXT>>>` | Rewritten; the fence still ends where Shield put it (tested) |
| Text contains `POLICY INFORMATION:` / `EVALUATION CRITERIA:` | Inside the fence; the real policy section follows the fence (injection cases in the eval set) |
| Policies of one request with different `multi_turn` settings | Two prefix groups (with and without history); each shares within itself |
| Very long text, trimmed by the existing budget | Trimmed the same way for every policy, so still identical |
| Model returns prose instead of CSV | Same parser and same failure handling as today; parse-error rate is a gate metric |
| `SHIELD_CUSTOM_POLICY_PROMPT_LAYOUT=legacy` | Today's prompt byte for byte |

## 8. Test plan (Definition of Done)

### Automated (no model needed)
1. **Identical prefix:** for one request and 25 different policies, every
   prompt is byte-identical up to `POLICY INFORMATION:`, input and output.
2. **No variable data before the policy section:** two calls with the same
   request and different policy ids, priorities and thresholds share the
   prefix; nothing time- or call-dependent appears in it.
3. **Token share:** with `cl100k_base` as a proxy tokenizer, a 400-token text
   gives at least 85% shared prefix tokens (today 4%).
4. **Multi-turn:** history messages are identical across policies with the
   same `multi_turn` setting.
5. **End marker:** text containing `END TEXT>>>` yields exactly one end marker
   in the prompt, after the text.
6. **Legacy:** `legacy` yields today's prompt byte for byte (golden string
   captured from current code before the change), end marker included.
7. **Parser unchanged:** existing custom-policy tests pass
   (`test_custom_policy_dilution.py`, `test_custom_policy_multiturn.py`,
   `test_custom_policy_csv.py`). Three CSV tests read the guardrail modules'
   source for the prompt; they now read the built prompt for both stages and
   both layouts instead (the prompt moved to `core/text_utils.py`).
8. Full suite green in a clean venv.

### Accuracy gate (real model; must pass before `cached` is the default)
A labelled set, checked into `tests/data/custom_policy_eval.jsonl`, of about
200 (policy, text, expected verdict) rows:
- policies modelled on real ones (PII, pricing, defamation, weapons, coding
  agents, email, financials);
- clear violations, clear passes, borderline cases;
- the existing dilution cases (violation buried in a long multi-topic text);
- multi-turn cases;
- injection cases (text that closes the fence, restates criteria, or tells the
  evaluator to answer false).

A script, `scripts/eval_custom_policy_layout.py`, runs every row with both
layouts against a given model endpoint and reports, per layout: accuracy,
false-block and missed-violation counts, parse errors, and every row whose
verdict differs between layouts. Run on the RunPod vLLM model and on the cloud
model the hosted service uses. **Gate:** for each model, `cached` accuracy is
at least `legacy`'s, no injection case flips from block to pass, parse errors
do not increase. Results go in this spec.

### Caching and latency (real vLLM)
- Before/after on RunPod with 10 and 25 enabled policies and 400 and 2,000-token
  texts: p50/p99 of the custom-policy guardrail latency, and vLLM's
  prefix-cache counters (`/metrics`, prefix cache queries and hits) over a
  burst of 100 requests. Recorded here.
- No Ollama run (decided 2026-10-30): the layout targets vLLM; Ollama deployments can keep `legacy`.

## 9. Tasks

1. **Prompt builder and tests** (one PR): shared builder in
   `core/text_utils.py`; both stages use it; `SHIELD_CUSTOM_POLICY_PROMPT_LAYOUT`
   (shipped with `cached` as the default, see Status);
   end-marker fix in `cached`; automated tests 1 to 8. Scope kept to the
   order only (decided 2026-10-30): no usage reporting or server-flag change.
2. **Evaluation set and script** (one PR): `tests/data/custom_policy_eval.jsonl`,
   `scripts/eval_custom_policy_layout.py`; run on both models; results and the
   caching/latency numbers recorded in this spec.
3. **Switch the default to `cached`** (one small PR), only if task 2 passes the
   gate on that model family; docs and migration note.
