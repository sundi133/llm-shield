# Spec: read labeled model verdicts by name

Status: approved by the user in chat on 2026-11-06 ("go ahead do the fix, i will test it after").

## 1. Problem & outcome

Guardrails that ask the model for a bare CSV line (`is_adversarial,attack_type,confidence`)
read the answer with `core.llm_backend.parse_csv_response`, which keeps only the last line
and maps values to fields by position.

`qwen/qwen3.5-9b` on OpenRouter (provider PrimeIntellect) labels its answer instead,
deterministically at temperature 0:

```
is_adversarial,true
attack_type,harmful_content
confidence,0.99
```

The parser kept `confidence,0.99`, read `is_adversarial="confidence"`, `attack_type=0.99`,
`confidence=""` (0.0), and `adversarial_detection` passed a 0.99-confidence harmful_content
verdict on prod (`api.guardrails.votal.ai`). A second shape,
`is_adversarial,true,attack_type:harmful_content,...`, shifted every value one slot the same way.

Outcome:
- A labeled answer (`field,value`, `field: value`, `field=value`, on one line or one per line,
  optionally fenced or JSON-ish) is read by name. The two captured shapes block.
- An answer whose verdict (`fields[0]`) still is not true/false carries `parse_error` in the
  result, so it shows in the guardrail's `details`. `adversarial_detection` and `toxicity`
  then say "Model verdict could not be read, allowing by default" instead of "No ... detected".

Non-goals: changing prompts, the format instruction, `max_tokens`, provider routing, or any
fail-open/fail-closed decision.

## 2. Plane & latency contract

Data plane only (`core/llm_backend.py`, guardrails). It is on the guard path; the change is a
string scan of a sub-200-character model answer per call: no I/O, no model call, microseconds.

## 3. Data model

None. No Redis keys.

## 4. API / interface

- `parse_csv_response(raw, fields)`: same signature and return keys. Adds one optional key,
  `parse_error` (`core.llm_backend.PARSE_ERROR_KEY`), only when `fields[0]` is not a bool.
- Labeled mode is used only when the verdict field itself is labeled, so a positional line
  whose free-text last field starts `reasoning: ...` stays positional.
- `guardrails/output/custom_policy._parse_policy_csv` reads a labeled multi-line answer
  whole before its per-line search (which would otherwise see only the verdict line).

## 5. Security & backward compatibility

- Positional answers, header echo and quoted lines parse exactly as before (tests pin this).
- Behavior change: labeled answers now produce the model's real verdict, so some prompts that
  passed will block. That is the fix. Escape hatch: `SHIELD_VERDICT_LABELS=0` restores the
  positional-only parser and drops `parse_error`.
- `parse_error` changes no decision: the verdict value is left as the old parser read it.

## 6. Packaging & deploy

No new modules or dependencies; `Dockerfile.admin` unchanged. Railway redeploys `main`.
RunPod / on-prem pick it up on the next image build; the parser is backend-independent.

## 7. Failure modes & edge cases

- Empty answer: positional path, `parse_error` set, verdict "" (falsy), as before. A `None`
  answer now reads as empty instead of raising `AttributeError`.
- Labeled answer missing some fields: those read as "" (the positional default).
- Value equal to another field name: not taken as a value (`field,field2` is a header echo).
- Fail-open stays fail-open: an unreadable verdict passes, now with a visible reason.

## 8. Test plan (Definition of Done)

`tests/test_llm_verdict_parsing.py`: both captured shapes, colon/equals/JSON/fenced shapes,
positional and header-echo regressions, labeled-reasoning-stays-positional, `parse_error`,
escape hatch, adversarial and toxicity end to end with the captured answer, custom policy
labeled multi-line. Full suite green; CI `pytest` gate passes.
