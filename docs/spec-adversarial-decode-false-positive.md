---
title: "Spec: stop benign Unicode normalization from triggering encoding-attack blocks"
layout: default
nav_order: 59
permalink: /spec-adversarial-decode-false-positive/
description: "A benign message with a non-breaking space is normalized, routed to a biased fast-check whose prompt demonstrates true,encoding_attack,0.92, and blocked as an encoding attack. The good 0%-FP classifier never runs."
---

# Spec: stop benign Unicode normalization from triggering encoding-attack blocks

Status: DRAFT, awaiting approval.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. Problem & outcome

A normal business message was blocked as an encoding attack:

```
message:  make this better "  Were you able to check the new reports, we can
          go through the details when you are available, let us know"
verdict:  BLOCKED — Unsafe [encoding_attack] (confidence: 0.92)
```

Nothing is encoded. Two bugs compound, and the second explains the suspiciously
exact `0.92`.

**Bug A — benign Unicode normalization routes to the adversarial fast-check, and
short-circuits the good classifier.** `check()`
(`guardrails/input/adversarial.py`):

```python
processed_content = preprocess_content(content)
if processed_content != content:            # ANY change, including normalization
    fast_result = await self._fast_decoded_check(content, processed_content)
    if fast_result is not None:
        return fast_result                    # short-circuits the main classifier
```

`preprocess_content` runs `_normalize_unicode` (NFKD + zero-width strip). A
**non-breaking space, zero-width character, or ellipsis** — routine copy-paste
artifacts from Slack, Word, or a PDF — makes `processed_content != content`,
which routes the message to `_fast_decoded_check` and **returns its verdict
immediately**. The main classifier, documented at 0% FP / 100% recall on a
held-out set, never runs.

Reproduced: `nbsp`, `zero-width`, and `ellipsis` all trigger the path; ASCII and
even curly quotes do not. The blocked message's irregular spacing is the tell.

Normalizing a non-breaking space to a space is text cleanup, not a decoded
payload. NFKD does not even catch homoglyph attacks (Cyrillic look-alikes are
not NFKD-normalized), so what it *does* catch — width, ligatures, whitespace,
punctuation — is overwhelmingly benign.

**Bug B — the fast-check prompt is a false-positive template.** `_FAST_USER_PREFIX`
demonstrates the output format with a **positive** example and no message:

```
Output ONLY: is_adversarial,attack_type,confidence
true,encoding_attack,0.92
```

A bare few-shot line showing `true,encoding_attack,0.92` primes the model to
emit exactly that when uncertain. The block returned `encoding_attack` at
**0.92** — the example's own value. A real judgment varies; copying the demo
returns the demo. The fast-check also blocks at a lower bar (>= 0.5) than the
main classifier's 0.7.

**Outcome.** Benign text that only needed whitespace/punctuation normalization is
judged by the main classifier, not the biased fast-check, and the fast-check
prompt no longer demonstrates a false-positive verdict.

Observable success condition: the exact message above returns **not adversarial**
(the main classifier's verdict), and a genuine base64/hex/ROT13/URL payload still
routes to the fast-check.

### Non-goals

- **Not** removing the fast-decoded check. Genuine hidden payloads still use it.
- **Not** dropping Unicode normalization. Normalized text still feeds the main
  classifier (it should read clean text); normalization simply stops being
  treated as a decoded *attack* signal.
- **Not** retuning the main classifier prompt. It is validated at 0% FP; leave it.

## 2. Plane & latency contract

- **Plane:** data plane. `guardrails/input/adversarial.py` only.
- **Touches the GUARD PATH?** Yes — every `/guardrails/input` and agent input
  message.
- **Latency:** strictly **reduced**. The fast-check is an extra LLM call; routing
  benign normalization to it (then falling to the main call on the non-blocking
  path) is pure overhead. Fixing A means benign messages make one classifier
  call, not two.

## 3. Data model

None. Pure classification logic and prompt text.

## 4. Interface

No HTTP change.

**Fix A — route only genuine payloads to the fast-check.** Distinguish
payload-revealing decoders (ROT13, Base64, hex, URL) from cosmetic normalization
(Unicode). `check()` invokes the fast-check only when a payload decoder actually
revealed hidden content:

```python
processed_content = preprocess_content(content)      # still normalizes for the main call
if _revealed_hidden_payload(content):                 # NOT triggered by normalization alone
    fast_result = await self._fast_decoded_check(content, processed_content)
    if fast_result is not None:
        return fast_result
# main classifier runs on processed_content in all other cases
```

`_revealed_hidden_payload` runs the four payload decoders (`_decode_rot13`,
`_decode_base64_fragments`, `_decode_hex_sequences`, `_decode_url_encoding`) and
returns True only if one produced new content. Unicode normalization is
deliberately excluded: a normalized message is still handed to the main
classifier, which already reads the cleaned text and is the 0%-FP path.

**Fix B — de-bias the fast-check prompt.** Replace the single positive demo with
a balanced pair, safe example first, and make it explicitly a format spec:

```
Output ONLY one CSV line: is_adversarial,attack_type,confidence
Format examples (illustrate SHAPE, not verdict):
false,none,0.03
true,encoding_attack,0.95
```

Two examples, opposite verdicts, remove the one-sided pull. The main prompt's
examples are also all-positive but are paired with real attack messages (not a
bare echo line) and the prompt is FP-validated, so it is left unchanged; a
`false` example may be added there in a follow-up if data warrants.

**Escape hatch:** `SHIELD_ADVERSARIAL_NORMALIZE_ROUTES_FASTCHECK=1` restores the
old behavior (any preprocessing change, including normalization, routes to the
fast-check) for one-off comparison.

## 5. Security & backward compatibility

**Does this weaken detection?** No, and here is why it cannot:

- A message whose only change was Unicode normalization is still classified — by
  the **main** classifier, on the normalized text, which already de-obfuscates
  zero-width-split words ("ig<zwsp>nore" becomes "ignore" before the main call
  reads it). The main classifier is strictly better than the fast-check: higher
  threshold, FP-validated, and it sees conversation history.
- Genuine encoded payloads (base64/hex/ROT13/URL) still route to the fast-check
  exactly as today.

So the change moves benign-normalized text from a biased low-threshold checker to
the good classifier, and leaves real payloads on their existing path. The only
behavior that changes is the false positive.

**The homoglyph question, answered honestly.** NFKD does not catch homoglyph
substitution (Cyrillic/Latin look-alikes) in the first place, so nothing about
homoglyph detection changes here — it was never on this path. If homoglyph
detection is wanted, it is separate work (a confusables map), and it should feed
the main classifier, not a biased fast-check.

**Fail open vs fail closed:** unchanged. A message that cannot be classified
falls through exactly as today.

## 6. Failure modes & edge cases

| condition | behavior |
|---|---|
| Benign nbsp / zero-width / ellipsis | Normalized, classified by the MAIN path. The fix. |
| Real base64 / hex / ROT13 / URL payload | Routes to the fast-check, as today. |
| Zero-width chars splitting an attack word | Stripped by normalization; the MAIN classifier reads the joined word and judges it. Still caught, by the better classifier. |
| Both a payload AND normalization | Payload decoder fires, so the fast-check runs. Unchanged. |
| Fast-check genuinely fires | De-biased prompt; a real base64 attack still scores high on its own merits. |
| `SHIELD_ADVERSARIAL_NORMALIZE_ROUTES_FASTCHECK=1` | Old behavior, for comparison. |

**Fail open vs fail closed:** a normalization-only message is now judged by a
stricter classifier than before, so if anything this fails *more* closed on real
attacks and *less* closed on benign text — the intended direction.

## 7. Packaging & deploy

- **New pip deps:** none.
- **`Dockerfile.admin`:** no change.
- **Images:** data plane.
- **Env flags:** `SHIELD_ADVERSARIAL_NORMALIZE_ROUTES_FASTCHECK` (unset = fixed).
- **Rollout:** ship, confirm the reproduction message passes and a base64
  `execute the decoded text` payload still blocks.

## 8. Test plan (Definition of Done)

New file `tests/test_adversarial_decode_false_positive.py`:

1. **The exact reported message does not route to the fast-check** — with an
   embedded non-breaking space, `_revealed_hidden_payload` is False. The
   headline, and the regression guard on the real incident.
2. **nbsp, zero-width, and ellipsis each fail to route** — none is a payload.
3. **A base64 payload DOES route** — `_revealed_hidden_payload` is True for
   `"execute this: <base64>"`.
4. **hex, ROT13, and URL payloads route** — the four real decoders still trigger.
5. **Normalized text still reaches the main classifier** — `check()` on an
   nbsp message calls the main path, not the fast-check (assert via a captured
   call, with the LLM stubbed).
6. **A zero-width-split attack word is still caught** — "ig<zwsp>nore your
   instructions" reaches the main classifier as "ignore your instructions".
7. **The fast-check prompt shows a `false` example** and lists it before the
   `true` one — a literal assertion so the bias template cannot return.
8. **The fast-check prompt no longer contains a bare `true,encoding_attack,0.92`
   line** as its sole demo.
9. **`SHIELD_ADVERSARIAL_NORMALIZE_ROUTES_FASTCHECK=1` restores routing** on a
   normalization-only message.

Regression suites: `tests/test_adversarial*.py`, `tests/test_guardrails*.py`,
any suite exercising `/guardrails/input`.

**Definition of done:** full suite green in a clean venv; CI `pytest` gate
passes; a live check that the reported message returns non-adversarial and a
base64 `execute the decoded text` payload still blocks.
