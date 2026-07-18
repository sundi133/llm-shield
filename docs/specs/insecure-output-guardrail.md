# Spec: Insecure Output Handling guardrail (P0-1)

From `docs/specs/guardrails-gap-analysis-2026-07.md` task P0-1.

## 1. Problem & outcome
- Model output rendered by customer apps can carry XSS (script tags, event
  handlers, javascript: URIs), markdown links with dangerous URI schemes, and
  SQL injection fragments. Shield has no output-side content sanitization
  today (only agent-registration input is sanitized).
- Outcome: a fast-tier output guardrail `insecure_output` that detects (and
  optionally sanitizes) these payloads before the response reaches the user.
  Observable success: XSS and SQLi payloads in `/guardrails/output` requests
  come back `passed: false` with category-tagged detections; with
  `sanitize: true`, `details.sanitized_output` is safe to render.
- Non-goals: LLM-based semantic analysis, CSP header changes (already in
  `core/security_headers.py`), input-side scanning, code-linting of generated
  programs.

## 2. Plane & latency contract
- Plane: data plane only. Runs inside the existing output pipeline
  (`/guardrails/output`), which is exactly the traffic it must inspect, so it
  is on the guard path by design.
- Latency budget: fast tier, regex only, no LLM call, no I/O. Same cost class
  as `competitor_mention` (sub-millisecond for typical outputs). Disabled by
  default, so guarded traffic that does not opt in sees zero added latency.

## 3. Data model
- None. No Redis keys, no persistence. Stateless per-request regex scan.
- Tenant scoping: config arrives via the existing per-request guardrail
  config contextvar (`guardrails/base.py`), same as every other guardrail.

## 4. API / interface
- No new endpoints. Reachable through existing `POST /guardrails/output`
  with `guardrails: {"insecure_output": {...}}` (aliases `insecure-output`,
  `insecure-output-handling`) and through tenant policies
  (`output_guardrails.insecure_output`).
- Settings:
  - `detect_categories`: subset of `["html_injection", "markdown_injection",
    "sql_injection", "code_execution"]`. Default: first three
    (`code_execution` is opt-in because coding assistants legitimately emit
    `eval`/`exec`).
  - `sanitize` (bool, default false): emit `details.sanitized_output` with
    HTML findings escaped and dangerous markdown URI schemes neutralized.
    SQL/code findings are never rewritten (block/warn only).
  - `ignore_fenced_code` (bool, default true): do not flag content inside
    ``` fenced blocks (code samples are the point of many assistants).
- Result shape mirrors `pii_leakage`: `details.detections` =
  `[{category, pattern, match, start, end}]`, plus `categories_checked` and
  optional `sanitized_output`.

## 5. Security & backward compatibility
- Opt-in: `enabled: false` in `config/default.yaml`; no behavior change for
  existing tenants. Tenants enable per policy; portal seeds it enabled for
  new-tenant DEFAULT_POLICIES like other output guardrails.
- Fail mode: fail-closed on detection when action is `block` (consistent with
  the customer plan's default for output leakage). Regex errors cannot occur
  at runtime (patterns are compiled at import).
- Authz: none new; same tenant-scoped policy paths as existing guardrails.

## 6. Packaging & deploy
- Data-plane module only; `admin_app.py` does not import it, so no
  `Dockerfile.admin` change. No new pip deps (stdlib `re`, `html`).

## 7. Failure modes & edge cases
- Empty content: pass. Huge outputs: regex is linear; patterns avoid
  catastrophic backtracking (no nested unbounded quantifiers).
- Overlapping detections when sanitizing: replacements applied right-to-left
  by start offset so earlier offsets stay valid.
- Fenced-code masking preserves offsets (fenced spans are space-masked, not
  removed) so detection offsets always index into the original content.
- Category name unknown in config: ignored (only known categories run).

## 8. Test plan (Definition of Done)
- `tests/test_insecure_output.py`: script-tag XSS, img/onerror handler,
  javascript: markdown link, UNION SELECT, `' OR '1'='1`, stacked
  `; DROP TABLE`, safe text passes, fenced-code suppression on/off,
  sanitize mode escapes script and neutralizes javascript: link,
  code_execution off by default and detected when enabled, configured
  action propagation, disabled-guardrail passthrough.
- Full suite green in a clean venv; CI pytest gate passes.
