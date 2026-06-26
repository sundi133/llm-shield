# Spec: HR Shield Breaker QA fixes (2026-06-26)

Source: `HR_Shield_Breaker_QA_2026-06-26.docx` — 55/60 pass, 5 candidate bugs
against tenant `hr-helpdesk-agent` on data-plane host
`kebrpqdbp1log1.api.runpod.ai`.

## 0. Triage summary — what's a code bug vs. a config/repro issue

| ID | Sev | One-liner | Verdict after code investigation |
|---|---|---|---|
| auth-008 | CRITICAL | `GET /v1/shield/audit` (+`/stats`) returns 200 unauthenticated, global scope | **Code bug — fix definitively** |
| tel-004 | MEDIUM | `GET /v1/tenant/me/guardrails/metrics` → 404 on data plane | **Code bug — fix definitively** |
| output-003 | HIGH | DOB `1991-03-14` + phone not blocked on output | **Partly code** (ISO-date regex gap) **+ partly tenant config** |
| output-006 | HIGH | direct `/guardrails/output` PASS vs MCP BLOCK (salary response) | **Repro-needed** — both call the same handler; divergence is input/context- or config-driven |
| dlp-007 | MEDIUM | `lookup_employee` name/title/office over-blocked to PROTECTED | **Likely tenant config** (sanitization rules too broad) — confirm with repro |

Honest note: 3 are clean code fixes; 2 (output-006, dlp-007) depend on the live
`hr-helpdesk-agent` Redis config and the exact payloads the QA runner sends
(`scripts/run_hr_shield_breaker_qa.py` — **not in this repo**). Those two get a
reproduction task before any code change, so we don't "fix" a config problem in code.

---

## 1. Problem & outcome
- **Outcome:** the 3 confirmed code defects are fixed with regression tests; the 2
  config-dependent findings are reproduced locally and either fixed (if code) or
  closed with a documented tenant-config change (if config).
- **Observable success:** re-running the breaker suite shows auth-008, tel-004,
  output-003 as PASS; output-006/dlp-007 either PASS or are reclassified as
  tenant-config items with the corrected config applied.
- **Non-goals:** rewriting the guardrail pipeline; changing the MCP↔REST
  delegation model (already unified in #191); adding new guardrails beyond the
  DOB regex gap; building the QA runner into this repo.

## 2. Plane & latency contract
- **auth-008** — both planes (router mounted in `core/app.py:107` and
  `admin_app.py:1078`). Auth/scope check is on a **read/analytics** route, **off
  the guard path**. No `/guardrails/*`, `cap/mint`, `tools/call` impact.
- **tel-004** — add the existing read-only metrics router to the **data plane**
  (`core/app.py`). Read endpoint, **off the hot path**.
- **output-003** — `guardrails/output/pii_leakage.py` runs inside
  `/guardrails/output` (**guard path**). Change is a regex alternation (one extra
  branch); negligible latency, no new allocation, no network.
- **output-006 / dlp-007** — guard path if any code change results; default is
  config-only.

## 3. Data model
No new Redis keys. Relevant existing keys (read-only here):
- `audit:{tenant_id}` and `audit:global` ZSETs — `audit_logger.query(...,
  tenant_id=...)` and `get_stats(..., tenant_id=...)` already accept a
  `tenant_id` param (`storage/audit_log.py:104,176`). The bug is the **route
  never passes it** and never authenticates.
- Guardrail metrics — `storage/guardrail_metrics.py` (shared Redis), already read
  by the existing `routes_guardrail_metrics.py`.

## 4. API / interface

### auth-008 — `api/routes_audit.py` (`/v1/shield/audit`, `/v1/shield/stats`)
Today: no `Depends`, queries global (`tenant_id=None`).
Change to:
- Require an authenticated principal (reject anonymous → **401**).
- **Tenant key** → force-scope the query to `request.state.tenant_id`
  (caller cannot read another tenant or global). Ignore/override any client-sent
  tenant.
- **Master/admin key** (valid key, `request.state.tenant_id` unset) → may read
  global or pass an explicit `tenant_id` query param (preserves admin-portal
  cross-tenant view).
- Mirrors the IDOR model already used by `require_tenant_access`
  (`core/auth.py:268`).

### tel-004 — mount existing router on the data plane
`core/app.py`: `from api.routes_guardrail_metrics import router as
guardrail_metrics_router` + `app.include_router(guardrail_metrics_router)`.
Path unchanged: `GET /v1/tenant/me/guardrails/metrics`. Auth via `X-API-Key`
(same as admin plane). No response-shape change.

### output-003 — `guardrails/output/pii_leakage.py`
Extend `_BUILTIN_PATTERNS["date_of_birth"]` to also match **ISO `YYYY-MM-DD`**
(the QA value `1991-03-14` is missed; current regex is `MM/DD/YYYY|MM-DD-YYYY`
only — `pii_leakage.py:27-29`). No API change. (Phone regex at line 18 already
matches `+1-415-555-2210`; if QA shows phone also passing, the cause is the
tenant not enabling `pii_leakage`/`Phone Number` on output — see §5.)

## 5. Security & backward compatibility
- **auth-008 is a behavior change, but a security fix that closes a disclosure.**
  Before: anyone could read all tenants' audit + stats. After: tenant keys see
  only their own; master keys retain full view. This is the
  **secure-by-default** direction; the only callers who "lose" access are
  unauthenticated/cross-tenant ones who should never have had it. No escape-hatch
  flag (we do not want an opt-out of an authz fix). **Migration note:** any
  internal dashboard hitting `/v1/shield/audit` with no key must switch to a
  tenant or master key.
- **tel-004** — additive (new mount on data plane). Non-breaking.
- **output-003 regex** — strictly broadens detection. Risk = false positives on
  bare ISO dates in legitimate output. Mitigation: the guardrail's configured
  **action** governs severity (a tenant can set DOB→redact/warn vs block); the
  regex only *detects*. Document that ISO dates now count as DOB.
- **output-003 / dlp-007 config:** if root cause is the `hr-helpdesk-agent`
  tenant config (PII not enabled on output / sanitization rules too broad), the
  remedy is a **tenant-config change**, not a default change — captured in the
  repro task with the exact before/after config.

## 6. Packaging & deploy
- **No new pip deps.** (Phone/DOB use stdlib `re`; presidio is already optional.)
- **`Dockerfile.admin`:** `routes_guardrail_metrics` is **already** imported by
  `admin_app.py` and copied — no change. The new mount is in `core/app.py`
  (full-Shield image), which copies the whole tree — no allowlist edit. Guard
  test `tests/test_admin_dockerfile_imports.py` still applies.
- **Rebuild:** data-plane image (full Shield) for tel-004 + output-003 +
  auth-008; admin image for auth-008 (already imports the audit router).
- **Rollout:** redeploy RunPod (data plane) and Railway (admin).

## 7. Failure modes & edge cases
- auth-008: anonymous (no key) → 401; valid tenant key + foreign `tenant_id`
  query → ignored/own-scope (never 200 cross-tenant); master key, no tenant →
  global as before; Redis down → existing `audit_logger` behavior (empty/handled),
  fail-closed on **authz** (deny if principal can't be established).
- tel-004: empty metrics → existing handler returns `total_guardrails=0`-shaped
  body (not 404); Redis down → existing handler path.
- output-003: empty/huge output → unchanged; ISO date inside a longer token →
  `\b` anchors prevent partial matches; leap/невalid dates → regex is
  format-level, action handles severity.
- output-006/dlp-007: must reproduce with the live tenant config; if not
  reproducible in a clean local tenant, classify as config and document.

## 8. Test plan (Definition of Done)
- **auth-008** (`tests/test_audit_authz.py`, new): anonymous → 401; tenant key →
  200 scoped to own tenant only; tenant key cannot read another tenant's entries;
  master key → global + explicit `tenant_id` param works; same for `/stats`.
- **tel-004** (extend `tests/` metrics test): assert the route is mounted on the
  **data-plane** app (`core/app.py` app fixture) and returns 200 with the
  summary shape (regression guard against "admin-only mount" drift).
- **output-003** (`tests/test_pii_leakage_dob.py`, new): `1991-03-14` and
  `1991/03/14` and `03/14/1991` all detected as `date_of_birth`; `+1-415-555-2210`
  detected as `phone_number`; a non-date like `1234-56-7890` not misclassified as DOB.
- **output-006 / dlp-007** (repro task): a failing→passing test **only if** the
  root cause is code; otherwise a documented config diff + a note in the report.
- Full suite green in a **clean venv** (`python -m venv /tmp/x && /tmp/x/bin/pip
  install -r requirements-test.txt && /tmp/x/bin/python -m pytest tests -q`); CI
  `pytest` gate passes; node `extension` job unaffected.

---

## Task breakdown (one PR each, in order)

1. **PR-A (CRITICAL, auth-008):** authenticate + tenant-scope `/v1/shield/audit`
   and `/v1/shield/stats` in `api/routes_audit.py`; new `tests/test_audit_authz.py`.
   *Self-contained, no deps/Dockerfile changes.*
2. **PR-B (MEDIUM, tel-004):** mount `guardrail_metrics_router` on `core/app.py`
   (data plane); regression test asserting data-plane mount.
3. **PR-C (HIGH, output-003):** ISO-date branch in `pii_leakage.py`
   `date_of_birth` regex; `tests/test_pii_leakage_dob.py`. Plus a doc note that
   the `hr-helpdesk-agent` output guardrails must enable `pii_leakage`
   (Phone Number + Date of Birth, blocking action) — config checklist.
4. **PR-D (repro, output-006 + dlp-007):** obtain the runner +
   `hr-helpdesk-agent` config export; reproduce locally; then either a code fix PR
   or a documented tenant-config change. No speculative code before repro.

## Open decisions for you
1. **auth-008 master-key behavior:** OK to let valid **master/admin** keys keep
   the global/all-tenant audit view (tenant keys strictly own-scope)? (Recommended
   — preserves the admin portal.)
2. **output-003 default action:** when DOB/phone is detected on output for a
   tenant with no explicit config, should the server default be **block** or
   **redact**? (I lean redact for least-disruption; block only when the tenant
   opts in.)
3. **output-006/dlp-007:** can you get me (a) `scripts/run_hr_shield_breaker_qa.py`
   and (b) a redacted export of the `hr-helpdesk-agent` tenant config
   (output_guardrails + data_policies)? Without these I can only harden, not
   root-cause.
