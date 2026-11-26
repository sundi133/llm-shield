# Spec: built-in financial patterns and decoded PII

Status: **approved 2026-11-26** (open questions resolved with the spec's defaults). Branch `spec/poc-phase1-quick-wins`.

Roadmap item R3 (POC "Test Cases G": AG-12 financial information, AG-21
obfuscated / encoded PII). Builds on `icap/rules.py` (the rule engine shared by
ICAP and the device agent), `api/routes_edge._build_bundle` (rules for the
extension, ICAP and the device bundle), `api/routes_device_dlp.bundle_policy`,
`core/dlp/device_policy.py`, `core/dlp/floor.py` and `guardrails/registry.py`.

## 1. Problem & outcome

**Problem.** Every deterministic path ships only the rules a tenant typed in:
- `_build_bundle` emits the tenant's `sanitization_rules` and keyword blocklist,
  nothing built in.
- The device fallback (`votal_device_agent/trust.py BUILTIN_FALLBACK`) has five
  secret patterns only.
- The device model's `financial` category is monitor-only because Tev1 misses it
  (recall 0.44, `dlp-bench/reports/SUMMARY.md`).
- On the server, `pii_detection` is an LLM call. `pii_leakage` (output) uses
  unvalidated patterns (`credit_card` is any 16 digits, `bank_account` is any
  8 to 17 digits).

So a card number, IBAN or routing number pasted into ChatGPT is not reliably
caught. Spacing it out ("4 1 1 1 ..."), fullwidth digits, or base64 / hex /
URL encoding defeat the regex rules that exist. The only decoders in the repo
(`guardrails/input/adversarial.py`) feed the prompt-injection classifier, not PII.

**Outcome.**
1. **Validated detectors.** One pure-Python module, `detectors`: card number
   (Luhn, issuer prefix and length), IBAN (country length table, mod-97), US ABA
   routing (checksum and prefix range, context keyword required), SWIFT/BIC
   (context required), bank account number (context required), US SSN
   (area/group/serial validity).
2. **A decode pass that runs before them.** NFKC, zero-width and format characters
   stripped, Unicode digits mapped to ASCII, separators collapsed inside digit
   runs, plus base64, hex, URL-encoding and HTML-entity fragments. It has size,
   depth and time limits.
3. **The same module in three places:**
   - the device agent and ICAP, through a new `detectors` key in the edge bundle;
   - an opt-in server input guardrail, `sensitive_identifiers`, on
     `/guardrails/input`;
   - which also covers the browser extension, since it screens there.

**Observable success.**
- A POC tester pastes `4111 1111 1111 1111`, `GB82 WEST 1234 5698 7654 32`, or the
  base64 of either into chatgpt.com on an enrolled laptop.
- Shield records a `card_number` / `iban` finding (monitor) or blocks / redacts it
  (when the tenant sets that).
- An order number such as `Order #4000123412341234` with a bad checksum, a git SHA
  or a UUID does not fire.

**Non-goals.**
- Changing the LLM `pii_detection` prompt.
- Feeding decoded text to any model. No extra LLM call anywhere.
- Words-to-digits ("four one one one"), Cyrillic or Greek letter homoglyphs in
  IBAN/BIC, and images or OCR (R16).
- A JavaScript port for the extension's local fast path.
- Replacing `pii_leakage` output patterns (follow-up).
- Non-US national IDs beyond IBAN.

## 2. Plane & latency contract

| Where | Path | Contract |
|---|---|---|
| Endpoint: device agent, ICAP | inline on prompts to AI hosts | Runs inside the existing rule deadline (`RULES_BUDGET_S = 0.25` in `engine.py`, `timeout_s` in `icap/rules.evaluate`); no new budget. Timeout is already fail-open there; detectors inherit it. |
| Data plane, guard path | `/guardrails/input`, only for tenants that enable `sensitive_identifiers` | Regex and arithmetic only. Budget p95 ≤ 3 ms at 4 KB, ≤ 15 ms at 64 KB, hard deadline 25 ms. Off by default, so no latency for anyone who does not opt in. |
| Data plane, off hot path | `GET /v1/edge/policy-bundle`, `GET /v1/edge/dlp-bundle` | One extra small dict in the bundle; ETag changes once on deploy. |
| Admin plane | device DLP policy save (`PUT /v1/tenant/me/dlp-policy`) | Validates the new optional section. |

Not touched: `cap/mint`, `tools/call`, `/guardrails/output`.

## 3. Data model

No new Redis keys.

**Endpoint settings.** These are an optional section of the existing device DLP
policy, `dlp_policy:{tenant_id}` (`core/dlp/device_store.py`, no TTL). It is
validated strictly like the rest of `validate_policy`:

```json
"builtin_detectors": {
  "card_number": "monitor", "iban": "monitor", "aba_routing": "monitor",
  "swift_bic": "monitor", "bank_account": "monitor", "us_ssn": "monitor",
  "decode": true,
  "ignore_test_values": false
}
```

- Each detector takes one of `off | monitor | redact | block`.
- A section that is absent means the defaults above. It is stored only when set,
  like `discovery`, so an untouched policy keeps its hash.

**Bundle.** `_build_bundle(tenant_id)` gains one key. Both
`/v1/edge/policy-bundle` and `bundle_policy()` (the signed laptop bundle) carry it:

```json
"detectors": {"schema": 1, "decode": true, "ignore_test_values": false,
              "items": [{"id": "card_number", "action": "monitor", "severity": "high"}, ...]}
```

- The bundle carries ids and actions only. The detection code ships with the
  agent and ICAP image.
- `schema` lets a newer server add ids an older agent skips. An unknown id is
  ignored and logged, never fatal.
- Older agents and ICAP builds ignore the key: `compile_bundle` reads only
  `rules` / `blocklists`, and `trust.REQUIRED` is unchanged. So the signed bundle
  verifies on every agent version.

**Device record.** The heartbeat gains an optional `detectors_schema` (int). It is
stored on the device record so the fleet view can show laptops that do not run
detectors yet.

**Server guardrail.** The setting is
`input_guardrails.sensitive_identifiers = {enabled, action, settings: {detectors: [...], decode, ignore_test_values}}`,
using the standard guardrail shape, in the tenant config. It is independent of
the endpoint section, as `pii_detection` is today. The tenant scope comes from the
tenant config the guard path already loads; there is no cross-tenant state.

**Findings never contain the value.** A finding is
`{detector, count, encodings: ["base64", ...], test_value: bool}`. Redaction
replaces a span with `[REDACTED:<detector>]`. When the finding came from decoded
text, the whole encoded fragment is replaced, because decoded offsets do not map
back to the original.

## 4. API / interface

- **No new endpoints.** The changes are to existing routes:
  - `/v1/edge/policy-bundle` and `/v1/edge/dlp-bundle` (data plane): the
    `detectors` key.
  - `PUT /v1/tenant/me/dlp-policy` (admin plane, registry write gate as
    today): accepts `builtin_detectors`.
    - 422 on an unknown detector id or action, with the strict error list.
  - Device heartbeat (data plane, device key): optional `detectors_schema`.
- **New guardrail.**
  - `guardrails/input/sensitive_identifiers.py`, `name = "sensitive_identifiers"`.
  - It is auto-registered by `guardrails/registry.py` and runs on
    `/guardrails/input` like any input guardrail.
  - Its result `details` are `{findings: [...], decoded: bool, truncated: bool, timeout: bool}`.
- **Engine API** (`icap/rules.py`):
  - `compile_bundle` also compiles `detectors`.
  - `evaluate` returns a `Hit(kind="detector")` for a `block` detector.
  - `redact` applies `redact` detectors.
  - New: `observe(bundle, text)` returns monitor-only hits. The device engine
    records them in the decision audit with verdict `allow`, and ICAP logs them.
  - ICAP cannot rewrite bodies, so a `redact` detector resolves through
    `redact_fallback` exactly like a redact rule. ICAP enforcement therefore needs
    `block`.

## 5. Security & backward compatibility

- **Default is monitor on every endpoint.**
  - Turning detectors on records findings (audit, telemetry, shadow report) and
    changes nothing a user sees.
  - Blocking or redacting needs the tenant to set it per detector. That is the
    secure-but-non-breaking line: existing tenants see new findings, not new
    blocks.
- **Escape hatch.** `SHIELD_BUILTIN_DETECTORS=off` (data plane) drops the
  `detectors` key from every bundle, which returns agents to today's behavior on
  their next sync.
- **Server guardrail.** It is opt-in: `config/default.yaml` has it
  `enabled: false`, like `pii_detection`.
- **Device fallback.** `BUILTIN_FALLBACK` gains `detectors` with every item set to
  `monitor`. A laptop without a bundle records financial findings but does not
  change traffic. The MDM `fallback.json` still overrides it.
- **Test values.**
  - Published test cards (4111..., 4242..., 5555 5555 5555 4444, 3782 822463
    10005), `123-45-6789`, `078-05-1120`, and the ECBS example IBANs are detected
    and flagged `test_value: true`.
  - They are acted on unless `ignore_test_values: true`. POC testers use exactly
    these values, so ignoring them by default would fail AG-12 in front of the
    customer. Production tenants can set the flag.
- **Abuse.** Detectors are code, not tenant patterns, so no tenant can upload a
  catastrophic regex through this feature. The patterns are fixed and reviewed,
  and run with the `regex` per-match timeout like `floor.py`.
- **Privacy.** No value is logged, counted or exported. `encodings` lists only
  decoder names.

## 6. Packaging & deploy

- **One source file, two copies.**
  - `icap/detectors.py` is the source. The device agent installers already bundle
    it (`--collect-submodules icap` in `build_pkg.sh` / `build_msi.ps1`), and the
    ICAP image copies `icap/`.
  - The server images do not ship `icap/` (`Dockerfile` copies `core/` and
    `guardrails/`). So `core/dlp/detectors.py` is a byte-identical copy, held
    equal by a test. This is the precedent `DEFAULT_AI_HOSTS` set in
    `core/dlp/device_policy.py`.
- **Admin image.** `Dockerfile.admin` already copies `core/dlp/` wholesale.
  `admin_app.py` imports neither the guardrail nor the module, so there is no
  change to the COPY list. Confirmed by `tests/test_admin_dockerfile_imports.py`.
- **Dependencies.** None new. The code is stdlib (`unicodedata`, `base64`,
  `binascii`, `html`, `urllib.parse`) plus `regex`, which is already in
  `requirements.txt`, `-test`, `-admin` and `-icap`.
- **Rollout.**
  1. Deploy the data plane; bundles gain `detectors` (monitor).
  2. Release the device agent and ICAP image.
  3. Tenants opt in to `redact` / `block`.
- **Images to rebuild:** data plane, admin, ICAP, device agent installers.

## 7. Failure modes & edge cases

| Case | Behavior |
|---|---|
| Input over 256 KiB | Scan the first 256 KiB, `truncated: true`. Device text is already segmented. |
| Decode bomb (nested base64, huge hex) | Depth ≤ 2. Fragments ≤ 32. Decoded bytes ≤ min(2 × input, 128 KiB). A fragment is kept only if ≥ 70 % printable, so git SHAs, image base64 and binary are dropped. |
| Deadline exceeded | Fail-open with `timeout: true` and a counter. This is the stance of `floor.py`, `icap/rules.evaluate` and the device engine. A DLP floor must not hold a prompt hostage to a scan. |
| Malformed `detectors` in a bundle | The key is ignored and logged; rules and blocklists still run. |
| Unknown detector id (newer server) | Skipped and logged. |
| Invalid UTF-8 / binary body | Extract as today (`icap/extract.py`); detectors see text only. |
| Redis down when building a bundle | Unchanged: `_load` and `_build_bundle` behave as today. Defaults are used if the policy section can't be read. |
| No DLP policy saved | Defaults (all monitor). |
| Old agent, new bundle | Detectors don't run; `detectors_schema` is missing from the heartbeat, and the fleet view shows it. |
| Digits inside longer runs | No match. Digit boundaries are enforced, and separators may not join two independent numbers across a sentence (at most 2 separators between digits). |
| Order / invoice / tracking / IMEI / ISBN | Luhn plus issuer prefix plus length rejects most cases. A negative-context word within 20 characters ("order", "invoice", "tracking", "ticket", "ref", "isbn", "imei") suppresses a card match. ABA, BIC and account require positive context ("routing", "ABA", "RTN", "SWIFT", "BIC", "account no", "acct", "a/c"). |
| Concurrency | Pure functions with no shared state. Compiled patterns are module-level constants. |

## 8. Test plan (Definition of Done)

- **Labelled corpus**, `tests/fixtures/sensitive_identifiers_corpus.jsonl`, about
  400 lines, each `{text, expect: [detector ids], note}`:
  - **Positives:** generated valid cards for Visa, MC (both ranges), Amex,
    Discover, JCB, Diners and UnionPay; IBANs for 20 countries; ABA with context;
    BIC with context; account with context; valid SSNs.
  - **Encoded positives:** spaced, dotted, dashed, fullwidth digits,
    zero-width-joined, base64, URL-safe base64, hex (`\x`, `0x`, plain), `%XX`,
    `&#NN;`, and base64 inside URL-encoding.
  - **Negatives:** order and invoice numbers (with and without valid Luhn), UPS
    `1Z...`, FedEx, IMEI, ISBN-13, phone numbers, Unix timestamps, UUIDs, git
    SHAs, JWTs without PII, PNG base64, version strings, dates, prices, 9-digit
    numbers without routing context, all-caps words shaped like a BIC.
  - **Gate:** 100 % recall on positives and 0 false positives on negatives
    (deterministic). Run the 115 benign prompts from `dlp-bench` and report
    false positives, with a gate of ≤ 1.
- **Unit tests**, one per §7 row:
  - Validators (Luhn, mod-97, ABA checksum, SSN rules) against published vectors.
  - Decoder limits (depth, fragment count, byte cap, printable ratio).
  - Truncation; deadline gives fail-open with `timeout: true`.
  - Test-value flagging and the `ignore_test_values` switch.
  - Redaction of plain and encoded spans; no value in any finding or log
    (assert the digits are absent from `details`).
- **Engine and bundle:**
  - `compile_bundle` with and without `detectors`; malformed and unknown ids.
  - `evaluate` / `redact` / `observe` per action; ICAP `redact_fallback`.
  - `_build_bundle` and `bundle_policy` include the key.
  - `SHIELD_BUILTIN_DETECTORS=off` removes it.
  - Strict validation of `builtin_detectors`.
  - An old-agent check: a bundle with `detectors` still passes `trust.check`.
- **Device engine:** monitor hits recorded with verdict `allow`; redact and block
  honored in enforce; fleet `mode: monitor` never blocks.
- **Server guardrail:**
  - Disabled by default.
  - Enabled: block / redact / warn per configured action.
  - Latency test: 64 KB payload under 15 ms locally; CI asserts < 100 ms to avoid
    flakes.
- **Drift guards:**
  - `icap/detectors.py` == `core/dlp/detectors.py` (bytes).
  - The detector id list is equal in the validator, the bundle builder and the
    module.
  - `test_admin_dockerfile_imports.py` stays green.
- **Full suite** green in a clean venv; CI `pytest` gate passes.

## 9. Tasks (one PR each, in order)

1. **Detector module.** `icap/detectors.py` plus the `core/dlp/detectors.py`
   copy: validators, decode pass, findings API; labelled corpus and its tests;
   copy-drift test. No wiring.
2. **Endpoints.**
   - `icap/rules.py` compile / evaluate / redact / observe;
     `_build_bundle` and `bundle_policy` emit `detectors`.
   - `builtin_detectors` validation in `device_policy.py`.
   - `SHIELD_BUILTIN_DETECTORS` flag.
   - Device engine records monitor hits.
   - `BUILTIN_FALLBACK` detectors (monitor).
   - Heartbeat `detectors_schema` and the fleet-view column.
3. **Server guardrail.** `guardrails/input/sensitive_identifiers.py`,
   `config/default.yaml` entry (disabled), latency test.
4. **Portal and docs.** Detector toggles on the Device DLP page, a guardrail card
   on Input & Output Guardrails, a POC note (set `card_number` / `iban` to
   block), and a docs page listing detectors and limits.

## As built (tasks 1 to 4, 2026-11-26)

- **Corpus.** 373 labelled rows (194 positives computed valid by
  `tests/fixtures/make_sensitive_identifiers_corpus.py`, independently of the
  detectors): 100% recall, 0 false positives. Of the 178 benign dlp-bench
  prompts (all `sensitive: false` rows, not only the 115 test-split ones), none
  fire. None of the 28 dlp-bench "financial" prompts fire either: they are
  business figures, not identifiers, which this spec does not cover.
- **Latency** (local, Apple Silicon): p95 0.7 ms at 4 KB and 11 to 13 ms at
  64 KB (ASCII and with Unicode plus base64), inside the 3 / 15 ms budget. The
  URL-encoding scan walks from each `%` instead of a token regex, which was
  the 64 KB hot spot.
- **BIC context** is stricter than "near": the code must follow its label
  (`SWIFT: X`, `BIC X`, `SWIFT/BIC code is X`), so an all-caps word near the
  word SWIFT does not fire.
- **Card windows.** A digit run that is not a card as a whole is split only at
  real group boundaries of 3 or more digits, so a list of small numbers is
  never stitched into a card.
- **Device verdict.** Monitor hits are recorded with verdict `monitor` (action
  `allow`), the engine's existing meaning for "allowed and recorded". Verdict
  `allow`, as section 4 says, is not recorded by an enforce-mode engine.
- **ICAP redact** resolves through `redact_fallback`: `block`, or `monitor`
  (still observed and logged) when the fallback is `pass`.
- **Overlap.** The same value reached two ways (base64 found directly and again
  after URL decoding) counts once; the merged span is the widest.
- **Portal.** A Built-in detectors panel on Endpoint DLP > Policy writes the
  `builtin_detectors` section (only when changed); the guardrail card is
  "Financial Identifiers & SSNs"; the Devices table flags agents without
  `detectors_schema`. Docs: `docs/builtin-financial-detectors.md`.
- **Server guardrail deadline** is `SHIELD_SENSITIVE_IDENTIFIERS_DEADLINE_MS`
  (default 25, clamped 1 to 1000); timeouts are counted in
  `guardrails.input.sensitive_identifiers.TIMEOUTS`.

## Follow-ups (not in this spec)

- Reuse the validators in `guardrails/output/pii_leakage.py` (`credit_card`,
  `bank_account` are unvalidated today) behind a flag, since it changes what
  existing tenants see.
- A JavaScript port for the extension's local fast path.
- Words-to-digits and letter homoglyphs (Cyrillic `А` in an IBAN country code).
- More national identifiers (UK NI, Indian PAN / Aadhaar with Verhoeff, Canadian
  SIN) as further detector ids.
- Let `adversarial.py` reuse the shared decode pass instead of its private
  decoders.
