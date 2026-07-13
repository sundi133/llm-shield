# Spec: Multi-turn conversation awareness for custom-policy input guardrail

## 1. Problem & outcome

**Problem.** The `custom_policy_input` guardrail evaluates only the *current*
message in isolation. Its LLM prompt is built from `text` + `policy` fields only
([custom_policy.py:87-133](../guardrails/input/custom_policy.py)); it never reads
`context["conversation_history"]`, even though the `/guardrails/input` route
already populates it from the request `messages` array
([routes_classify.py:231-235](../api/routes_classify.py)).

Result: multi-turn escalation is invisible to custom policies. Observed live —
prompt "and how would I actually do it?" following a prior turn about explosives
passed all 3 of a tenant's custom policies, because each policy saw only the
meaningless final fragment. `adversarial_detection` and `toxicity` already get
history via `build_history_messages`; custom policies are the gap.

**Outcome.** A tenant can mark an individual custom policy as multi-turn aware.
When set, that policy's LLM evaluation receives the last N prior turns (same
mechanism `adversarial` uses) so it can judge the current message in context.
Observable success: a policy with `multi_turn: true` flags the escalation
example above; the same policy with the flag off (or absent) behaves exactly as
today.

**Scope: both stages.** Input (`custom_policy_input`) and output
(`custom_policy_output`) custom policies. `guardrails/output/custom_policy.py`
has the identical single-user-message shape
([output/custom_policy.py:87-120](../guardrails/output/custom_policy.py)), so the
guardrail change is symmetric. **Caveat:** the output route
(`/guardrails/output`) does *not* currently lift request `messages` into
`context["conversation_history"]` the way the input route does — so the output
task must add that same lift to `api/routes_classify_output.py`, else opted-in
output policies never receive history.

**Non-goals.**
- Changing default behavior for existing policies (must stay single-turn).
- Any new persistence, endpoint, or portal UI beyond accepting one new optional
  field on the existing policy CRUD.
- Cross-request / server-side conversation memory. History comes only from the
  caller-supplied `messages`/`conversation_history` in the request, as today.

## 2. Plane & latency contract

- **Plane:** data plane (GPU/vLLM guardrail server, `core/app.py`). The guardrail
  runs in the input pipeline.
- **Touches the GUARD PATH?** **Yes** — `/guardrails/input` and
  `/guardrails/output`. This is the sensitive invariant for this spec. The output
  route also gains a `messages`→`conversation_history` dict lift (no LLM, no I/O).
  - **Justification / budget:** No extra LLM round-trip. `custom_policy` is
    already `tier="slow"` and already makes one LLM call per enabled policy. The
    change only *prepends history turns to the messages* of that same call, so the
    added cost is input tokens (bounded, see below), not a new request.
  - **Bounded by opt-in + token budget:** history is attached *only* for policies
    with `multi_turn: true`. Turns are capped by `max_turns` (default 6) and then
    `trim_history_to_budget(...)` — the exact bounding `adversarial` already uses.
    Policies without the flag build the identical single-user-message prompt as
    today → **zero added latency for existing traffic**.

## 3. Data model

No new Redis keys. One new **optional field on the existing custom-policy dict**,
which lives inside the tenant config already persisted by
`storage/custom_policies.py` (`set_tenant_policies` →
`tenant_config[{stage}_guardrails][custom_policy_{stage}][settings][policies]`).

- New field: `multi_turn: bool` (default `false`).
- Tenant scoping: unchanged — policies are stored per `tenant_id` in tenant
  config; no cross-tenant surface is added. History is per-request, supplied by
  the caller; it is never persisted by this feature.
- `save_custom_policy` sets it via `policy_data.get("multi_turn", False)`
  (mirrors the other optional fields at
  [custom_policies.py:95-110](../storage/custom_policies.py)).
- `update_custom_policy` needs no change — it applies `policy.update(updates)`
  generically ([custom_policies.py:230](../storage/custom_policies.py)).

## 4. API / interface

No new endpoints. The existing custom-policy create/update paths accept one more
optional field.

- **Create** (`save_custom_policy` / whatever route calls it): request may include
  `"multi_turn": true`. Absent → `false`. Required fields unchanged
  (`name, description, prompt, action`).
- **Update** (`update_custom_policy`): `{"multi_turn": true|false}` flows through
  the generic update.
- `/guardrails/input` request shape is **unchanged**. Callers already pass
  `messages` (or `context.conversation_history`); the route already lifts it into
  `context`. No auth change — same `X-API-Key` tenant resolution.
- Router/plane: data plane already mounts the classify router; no admin-plane
  change, **no `Dockerfile.admin` COPY change** (no new module imported by
  `admin_app.py`).

## 5. Security & backward compatibility

- **Default behavior:** opt-in. `multi_turn` defaults to `false`; every existing
  stored policy lacks the field → treated as `false` → byte-identical prompt and
  latency to today. Satisfies "secure-by-default but non-breaking."
- **Escape hatch (global kill-switch):** env `SHIELD_CUSTOM_POLICY_HISTORY_TURNS`
  (int, default `6`). Sets the `max_turns` cap for opted-in policies; **`0`
  disables history injection entirely** even for policies that opted in — an
  operator-level off switch with no redeploy of policy data. Matches the repo's
  env-flag pattern (`SHIELD_ADVERSARIAL_BLOCK_ON_UNTYPED`, etc.).
- **Authz:** unchanged. A caller can already supply arbitrary `messages`; this
  feature only means an opted-in policy's own LLM sees them. No privilege change.
- **Injection consideration:** prior turns are attacker-influenced text fed to
  the evaluator LLM. This is already true for `adversarial`/`toxicity`; we reuse
  the same `build_history_messages` shaping (structured role/content turns, not
  string-concatenated into the instruction) so history is data, not instructions.
  The policy instruction stays in the system/leading content, current message
  last — same layering as `adversarial._check_single`.

## 6. Packaging & deploy

- **New deps:** none. `build_history_messages` / `trim_history_to_budget` /
  `estimate_tokens` already exist in `core/text_utils.py` and are already imported
  by other input guardrails.
- **Dockerfile.admin:** no change (data-plane-only guardrail; admin doesn't import
  it).
- **requirements*.txt:** no change.
- **Env flags:** `SHIELD_CUSTOM_POLICY_HISTORY_TURNS` (optional; default 6).
- **Image(s) to rebuild:** data plane only — `Dockerfile` (vLLM) and
  `Dockerfile.cloud` (hosted/OpenRouter/Ollama) carry the guardrail code. Admin
  image unaffected.

## 7. Failure modes & edge cases

- **No history in request** (`messages` absent / `conversation_history` empty):
  `build_history_messages` returns `[]` → prompt identical to single-turn. No-op.
- **Flag off / absent:** single-user-message prompt exactly as today (regression
  guard test).
- **`SHIELD_CUSTOM_POLICY_HISTORY_TURNS=0`:** history skipped even when
  `multi_turn: true`.
- **Huge history:** capped to `max_turns`, then `trim_history_to_budget` drops
  oldest turns to fit the token budget (reuse adversarial's budget math). The
  current message is always included.
- **Malformed turn** (missing `role`/`content`): `build_history_messages` already
  defaults `role→"user"`, `content→""`; no crash.
- **null content from the model** (reasoning-model / OpenRouter): already handled
  upstream by `parse_llm_json(None)` raising a clear error, caught by the policy
  loop's `except` → **fail-open** (existing behavior, unchanged).
- **Model slow:** no new round-trip; only a larger prompt. Bounded by the token
  budget above.
- **Fail-open vs fail-closed:** unchanged — custom_policy fails open on any
  evaluation error ([custom_policy.py:76-85,163-175](../guardrails/input/custom_policy.py)).
  History injection does not alter this.

## 8. Test plan (Definition of Done)

New unit tests in `tests/` (mock `async_llm_call`, assert the messages built):

1. **Opt-in on, history present** → the LLM `messages` include the prior turns
   (assert history content appears; current message is last).
2. **Flag off / absent** → single-turn prompt; **no** history in the messages
   (regression guard that default traffic is byte-identical).
3. **Opt-in on, no history in context** → no-op, single-turn prompt.
4. **`SHIELD_CUSTOM_POLICY_HISTORY_TURNS=0`** → history skipped despite
   `multi_turn: true`.
5. **`max_turns` cap** → with N>6 prior turns, only the last 6 (default) are sent.
6. **`save_custom_policy`** persists `multi_turn` (True when supplied, False by
   default); **`update_custom_policy`** toggles it.
7. **Escalation behavior test** (mock LLM): a `multi_turn: true` policy receives
   history and the aggregated verdict reflects a violation; same policy flag-off
   passes on the fragment alone.
- Full suite green in a **clean venv** (`python -m venv /tmp/x && ...`); CI
  `pytest` gate passes. No Dockerfile/requirements drift (no new imports/deps).

## Task breakdown (one PR each, in order)

1. **Storage: accept `multi_turn` on policies (both stages).** Add
   `multi_turn: policy_data.get("multi_turn", False)` in `save_custom_policy`
   (stage-agnostic, so it covers input and output); confirm `update_custom_policy`
   passes it through. Tests: create default False, create True, update toggles.
   *(Small, off guard path.)*

2. **Shared helper + input guardrail.** Add a small shared builder (e.g.
   `_history_turns()` reading `SHIELD_CUSTOM_POLICY_HISTORY_TURNS` default 6, and a
   messages-assembly helper) usable by both stages. Refactor input
   `_evaluate_policy_with_llm` to build a `messages` list (policy instruction +
   `build_history_messages(context, max_turns=_history_turns())` +
   `trim_history_to_budget` + current message) **only when `policy.get("multi_turn")`
   and `_history_turns() > 0`**; otherwise the current single-message path
   verbatim. Tests: §8.1–5, 7 (input). *(Guard path — sensitive; opt-in branch
   keeps default traffic byte-identical.)*

3. **Output guardrail + route lift.** Apply the same opt-in history injection to
   `guardrails/output/custom_policy.py`, **and** add the `messages` →
   `context["conversation_history"]` lift to `api/routes_classify_output.py`
   (mirroring [routes_classify.py:231-235](../api/routes_classify.py)) so output
   policies actually receive history. Tests: §8.1–5, 7 (output) + a route test that
   `messages` reaches `context.conversation_history`. *(Guard path —
   `/guardrails/output`; route lift is a dict read, no LLM.)*

All PRs on a feature branch off `main`; **not** on `feat/openrouter-backend`
(that branch is about the OpenRouter backend — keep this workstream separate).
