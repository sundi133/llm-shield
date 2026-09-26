---
title: "Spec: Sigma policies at scale"
layout: default
nav_exclude: true
permalink: /specs/sigma-at-scale/
description: Make Sigma custom policies trustworthy and fast with hundreds of rules - reject rules that can never fire, translate common field names, normalize text against evasion, evaluate rules compiled-once in one prefiltered pass, raise the Sigma-only cap, and prove every shipped rule with tests.
---

# Spec: Sigma policies at scale

> Status: **APPROVED (product owner: "write the spec, build")**. Builds on
> [sigma-policy-asim-telemetry](/specs/sigma-policy-asim-telemetry/).

## 1. Problem & outcome

Sigma custom policies shipped in #437. An audit found four problems that block
real use with more than a handful of rules:

1. **Rules that can never fire are accepted silently.** Validation checks
   syntax only. Public rules (SigmaHQ: 3,783 rules, 2,410 for Windows) read
   fields such as `CommandLine`/`EventID`; community AI packs use their own
   names (`prompt`, `tool_args`). They import "successfully" and never match.
2. **Cap of 10 per stage**, shared with natural-language (NL) policies. The cap
   exists because each NL policy is an LLM call; a Sigma rule costs microseconds.
3. **Raw-text matching is easy to evade** (zero-width characters, fullwidth
   digits, compatibility forms).
4. **The engine does per-request work that does not scale**: the condition is
   re-parsed per request and each rule gets its own worker-thread hop (measured:
   100 rules = 0.82 ms sequential vs 3.88 ms with a hop per rule).

Plus a verification gap: there is no way to show a rule matches what it should.

**Outcome.**
- A rule that references a field Shield never provides is rejected with a
  message naming the field; common aliases (`prompt` -> `message`, `tool_args` ->
  `tool_input`, ...) are translated automatically; import accepts a `field_map`.
- Hundreds of Sigma rules per stage evaluate in about a millisecond.
- Text is normalized (NFKC, invisible format characters removed) before
  matching, with an escape-hatch flag.
- `validate-sigma` accepts sample texts and reports which match; the portal's
  Sigma editor can test a sample.
- A starter rule pack ships in `config/sigma/`, every rule with should-match and
  should-not-match samples, all run in CI.

**Non-goals:** Sigma on tool calls / MCP gateway / A2A (separate spec; guard
path); dedicated storage for thousands of rules (follow-up past the new cap);
new modifiers (`base64`, `lt/gt`, `cidr`); cross-request correlation (SIEM job).

## 2. Plane & latency contract

- **Data plane:** evaluation (`guardrails/*/custom_policy.py`, `core/sigma.py`).
- **Admin + data plane:** validation, translation, import, sample testing
  (`storage/custom_policies.py`, `core/sigma_io.py`, both custom-policy routers).
- **Guard path (`/guardrails/*`): touched, only for tenants with Sigma
  policies.** NL policies take the identical path. Budget: **<= 1 ms p95 for 100
  rules on a 2 KB prompt** (today: 0.82 ms without prefilter). Work per request:
  one normalization, one Aho-Corasick scan (measured 0.012 ms / 2 KB), then full
  evaluation of only the rules the scan leaves possible, all in **one** worker
  thread. A per-stage budget (`SHIELD_SIGMA_STAGE_BUDGET_MS`, default 500)
  bounds the pathological case; rules not reached are evaluation errors and
  follow `SHIELD_CUSTOM_POLICY_FAIL_OPEN`, as today.
- `cap/mint` and `tools/call` untouched.

## 3. Data model

No new Redis keys. Policies stay inside the tenant config. Per Sigma policy:
`sigma_rule` (stored **after** alias translation) and `sigma_source` (the YAML as
written). Caps: NL `MAX_POLICIES_PER_STAGE = 10` (unchanged, counts NL only);
Sigma `SHIELD_SIGMA_MAX_POLICIES_PER_STAGE` (default **100**). At 100 rules the
stage config grows by roughly 100-200 KB; beyond that, dedicated storage is the
follow-up.

Compiled rules are cached in-process: LRU keyed by a hash of the rule's
canonical JSON (content-addressed, so edits through the raw JSON editor, which
do not bump `version`, can never serve a stale compile).

## 4. API / interface

| Change | Where |
|---|---|
| Unknown fields -> 400 naming them (create, update, import per rule) | both custom-policy APIs |
| `field_map: {external: shield}` on import | `.../import/sigma` |
| `samples: [text or {message, user_role, tool_name, tool_input, ...}]` (max 20) on validate; response adds `samples: [{index, matched, selections}]` | `.../validate-sigma` |
| `limits` reports `max_sigma_policies_per_stage` | both `limits` endpoints |
| Portal Sigma editor: optional sample text, tested by **Test policy** | `static/tenant.html` |

Shield fields: `message`, `stage`, `user_role`, `session_id`, `agent_id`,
`tool_name`, `tool_input`. Default aliases: `prompt`, `input`, `user_input`,
`text`, `content`, `query`, `output`, `response`, `completion` -> `message`;
`role`, `user.role` -> `user_role`; `agent`, `agent_name`, `agent.id`,
`agent.name`, `agent_key` -> `agent_id`; `tool`, `tool.name`, `tool_call.name`,
`function`, `function_name` -> `tool_name`; `tool_args`, `tool_arguments`,
`arguments`, `tool.input`, `tool_call.arguments`, `params`, `parameters` ->
`tool_input`; `session`, `session.id`, `conversation_id` -> `session_id`.

## 5. Security & backward compatibility

- **Field check** applies on write only; stored rules keep evaluating. A rule
  it rejects could never have matched, so no traffic changes.
- **Normalization changes matching** (more evasions caught). Escape hatch
  `SHIELD_SIGMA_NORMALIZE=0` restores raw-text matching. NFKC does not map
  cross-script look-alikes (Cyrillic "a" vs Latin "a"): documented residual.
- **Prefilter is sound by construction:** it only skips a rule when the rule
  provably cannot match (see §6). Any construct it cannot reason about (regex,
  `exists`, `null`, non-`message` fields, no literal) keeps the rule in the
  always-evaluate set. A differential test asserts identical verdicts with and
  without the prefilter.
- Aho-Corasick is imported lazily; where `pyahocorasick` is absent (admin and
  gateway images) the engine evaluates every rule: same verdicts, no speed-up.

## 6. Design notes

**Compile once.** `compile_rule(rule)` parses the condition to an AST once and
derives per-identifier literal sets. Cached by content hash.

**Prefilter (necessary-literal analysis).** For a search identifier, `L(id)` is a
set of casefolded literals such that the identifier can only be true if the
normalized, casefolded message contains at least one of them; `None` means
unknown. Keyword list: union of each keyword's longest wildcard-free piece.
Field map (AND): the literal set of any one `message` field. Value list (OR):
union; with `|all`: one value's literal. `re`, `exists`, `null`, other fields:
`None`. The condition is evaluated in "possible" semantics: `id` = `L is None
or L & present`; `and`/`or`/`1 of`/`all of` combine normally; `not x` =
possible. If the result is false the rule is skipped (it cannot match).

**Single pass.** Each guardrail splits its enabled policies into Sigma and NL;
all Sigma policies are evaluated in one `asyncio.to_thread` call (normalize
once, scan once) while NL policies run concurrently as before. Per-policy
result shapes are unchanged, so aggregation, action escalation, redaction,
monitor mode and fail-open behave exactly as today.

## 7. Failure modes & edge cases

| Case | Behavior |
|---|---|
| Rule uses `CommandLine` / `event_type` | 400 / import error: "fields Shield does not provide: ..." |
| `pyahocorasick` missing | Evaluate all rules (no prefilter) |
| Pathological regex | Per-rule timeout + stage budget; error -> fail-open flag |
| Stage budget exhausted | Remaining rules reported as errors, never silently passed |
| Sigma cap reached | 400 naming the Sigma cap (NL cap message unchanged) |
| Normalization disabled | Raw-text matching, as before |
| Rule edited via raw JSON (no version bump) | Content-hash cache recompiles |

## 8. Test plan (Definition of Done)

- Field check + aliases + `field_map` (create, update, import; legacy stored
  rule still evaluates).
- Normalization catches zero-width and fullwidth evasions; flag off restores raw.
- **Differential test:** randomized rules x texts, verdicts identical with and
  without prefilter (soundness).
- Single pass: one thread hop per stage; results identical to per-rule
  evaluation; stage budget converts overflow to errors.
- Caps: 11th NL rejected, 100 Sigma accepted, 101st rejected.
- `validate-sigma` samples on both APIs.
- **Rule pack CI:** every rule in `config/sigma/` validates, uses only Shield
  fields, has >= 1 match and >= 1 no-match sample, all behave as declared.
- Latency guard: 100 rules on a 2 KB prompt well under budget (loose CI bound
  plus measured numbers in the PR).
- Full suite green in a clean venv.

## 9. Task breakdown (one branch)

1. Spec (this document).
2. Field compatibility, aliases, `field_map`.
3. Engine: compile-once cache, normalization, prefilter, single pass, stage budget, split caps.
4. Sample testing (API + portal).
5. Starter rule pack + CI harness.
6. Customer doc update.
