---
title: "Spec: Sigma policies + ASIM telemetry"
layout: default
nav_exclude: true
permalink: /specs/sigma-policy-asim-telemetry/
description: Sigma rules as a custom input/output policy format enforced by the existing custom-policy guardrails, Sigma import/export for those policies, and ASIM as the default telemetry format.
---

# Spec: Sigma policies + ASIM telemetry

> Status: **IMPLEMENTED on `feat/sigma`.** Customer doc: [sigma-policies](/sigma-policies/).
> Revision 2. Revision 1 proposed a separate "Votal Policy" schema and store;
> that was built as PR2 and reverted, because the requirement is Sigma *inside*
> the existing policies, enforced by the existing runtime path.

## 1. Problem & outcome

**Requirement (from the product owner):**
1. A custom input/output policy can be written as a **Sigma rule**, alongside
   natural language.
2. **Import/export**: Sigma rules import as input/output policies; any policy
   exports as a Sigma rule.
3. **Runtime enforcement is unchanged**: policies are enforced by the existing
   `custom_policy_input` / `custom_policy_output` guardrails.
4. **Telemetry is ASIM** going forward.

**Outcome (observable):**
- `POST /v1/tenant/me/custom-policies/` with `format: "sigma"` + `sigma_rule`
  creates a policy; `/guardrails/input` blocks a matching prompt with the
  policy's action, **without an LLM call** for that policy.
- `POST .../import/sigma` turns Sigma YAML into policies; `GET .../export/sigma`
  returns every policy as Sigma. Export then re-import is lossless.
- Exported telemetry carries ASIM field names by default;
  `VOTAL_TELEMETRY_FORMAT=native` restores the previous shape.

**Non-goals:** Sigma correlation rules (`timeframe`, `| count()`); converting
data policies, sanitization rules or blocklists (only custom input/output
policies); changing the per-tenant SIEM dispatcher formats
(`core/siem_dispatcher.py`).

## 2. Plane & latency contract

- **Data plane:** the guardrails, `core/sigma.py`, and the import/export endpoints
  (`api/routes_custom_policies.py`, mounted in `core/app.py`). NL->Sigma
  translation (`core/sigma_translate.py`) runs here because the guardrail LLM is
  here.
- **Admin plane:** policy CRUD in `api/routes_tenant_self.py` accepts the new
  fields; storage validates Sigma with `core/sigma.py`.
- **Guard path (`/guardrails/*`):** touched, and **faster** for Sigma policies:
  a Sigma policy replaces an LLM call with deterministic matching run in a worker
  thread (`asyncio.to_thread`), bounded by `SHIELD_SIGMA_EVAL_TIMEOUT_MS`
  (default 250). Natural-language policies take the identical code path as
  before. Tenants with no Sigma policy never load `core/sigma.py` (lazy import).
- **Import/export** are admin-initiated and not on `/guardrails/*`, `cap/mint` or
  `tools/call`. NL export makes one LLM call per natural-language policy on the
  shared model server.
- **Telemetry:** formatting runs only in the off-thread flush/export path.

## 3. Data model

No new Redis keys. The existing custom-policy record (inside the tenant's
`input_guardrails` / `output_guardrails`, `custom_policy_{stage}.settings.policies`)
gains:

| Field | Value |
|---|---|
| `format` | `natural_language` (default; records without the key are NL) or `sigma` |
| `sigma_rule` | validated Sigma rule, stored as an object (sigma only) |

`prompt` is required for NL and empty for Sigma. Tenant scoping is unchanged.

## 4. API / interface

Data plane, `X-API-Key` tenant auth, prefix `/v1/tenant/me/custom-policies`:

| Method | Path | Purpose |
|---|---|---|
| POST / PUT | `/`, `/{id}` | now accept `format`, `sigma_rule` |
| POST | `/import/sigma` | `{sigma, stage?, action?, dry_run?}`; per-rule `created` / `errors` |
| GET | `/export/sigma?stage=&translate=` | all policies as Sigma (`yaml`, `rules`, `errors`) |
| GET | `/{id}/export/sigma?translate=` | one policy; 404 missing, 422 not convertible |

Portal API `/v1/tenant/me/policies/custom` (`api/routes_tenant_self.py`, mounted
on both planes) accepts `format` and `sigma_rule` on create/update and exposes
the same `import/sigma`, `export/sigma`, `{id}/export/sigma` plus
`validate-sigma`. Both routers delegate to `core/sigma_io.py`, so behavior is
identical. Import precedence: request field, then the rule's `votal:` block,
then `logsource.category` / `level`. Exported rules carry a `votal:` block
(stage, action, priority, and for NL the original prompt). Stored Sigma
policies keep the author's YAML as `sigma_source` for editing.

**Portal UI** (`static/tenant.html`): a Format selector (natural language /
Sigma), a YAML editor with example and validate, a Sigma badge on cards, and
Import/Export buttons per stage. The natural-language card markup and the NL
create/edit payloads are unchanged (verified: DOM-identical card; payload has no
`format` unless converting a Sigma policy back to NL). NL export from a server
without a reachable guardrail LLM reports those policies in `errors`.

## 5. Security & backward compatibility

- **Policies:** opt-in per policy. Existing records have no `format` and are
  evaluated exactly as before; the NL request contract is unchanged (a prompt is
  still required for NL).
- **Telemetry default change (behavior change):** ASIM is now the default. Escape
  hatch `VOTAL_TELEMETRY_FORMAT=native` (or `telemetry.format: native`);
  migration note in `core/telemetry.py` and the customer doc. No code in the repo
  reads the native field names; external dashboards on the Elasticsearch index
  shipped by `Dockerfile.cloud` (`votal-shield-logs`) must be updated.
- **Untrusted rules:** YAML loaded with a SafeLoader that refuses anchors/aliases
  (no billion-laughs), 64 KiB cap, unsupported features rejected at save time,
  regex bounded by the `regex` module's interruptible timeout plus an overall
  per-evaluation deadline.
- **Fail-open/closed:** a Sigma evaluation error or timeout is an evaluation
  error, identical to an LLM failure, governed by `SHIELD_CUSTOM_POLICY_FAIL_OPEN`.

## 6. Packaging & deploy

- `Dockerfile.admin`: `COPY core/sigma.py` (reached from `storage/custom_policies.py`)
  and `COPY core/asim.py` (reached from `core/telemetry.py`).
- Dependencies: `pyyaml` and `regex` are already in `requirements.txt` and
  `requirements-admin.txt`. `requirements-gateway.txt` gains an explicit `regex`
  (the gateway image copies `core/` and `guardrails/`; it had `regex` only via
  `tiktoken`).
- Env: `SHIELD_SIGMA_EVAL_TIMEOUT_MS`, `VOTAL_TELEMETRY_FORMAT`.
- Rebuild: data-plane, admin, and gateway images.

## 7. Failure modes & edge cases

| Case | Behavior |
|---|---|
| Invalid / unsupported rule on create, update or import | 400 (import: per-rule error, others still import) |
| Catastrophic regex at runtime | Stopped by the deadline; evaluation error; fail-open flag decides |
| Absent field in the event | Never matches a value; matches `null` / `exists: false` |
| Mixed NL + Sigma policies | Evaluated concurrently; only NL policies call the LLM |
| NL export, model returns nothing usable | Per-policy error; bad regexes from the model are dropped |
| Rule with no stage on import | Error unless `stage` is supplied |
| Unknown telemetry format value | Warning, falls back to ASIM |

## 8. Test plan (Definition of Done)

- `tests/test_sigma_policies.py`: rule validation (unsupported modifiers,
  unknown identifiers, correlation, aliases, size cap, invalid regex), matching
  semantics (wildcards, modifiers, null/exists, quantifiers, boolean logic),
  timeout bound on a pattern that otherwise runs over 5 s, storage (create,
  switch formats, reject without mutating), runtime (input/output guardrails block
  on Sigma **with the LLM patched to fail if called**, mixed policies, context
  fields, timeout honoring fail-open), import/export round trips, translation
  dropping invalid regexes, and the API.
- `tests/test_telemetry_asim.py`, `tests/test_asim.py`: ASIM default, native
  escape hatch, unknown value fallback, file exporter selects the same records in
  both formats.
- `tests/test_admin_dockerfile_imports.py`, `tests/test_admin_image_transitive_imports.py`.
- Full suite in a clean Python 3.12 venv. One pre-existing failure,
  `test_middleware_tenant_route_coverage`, is unrelated (unpinned FastAPI) and
  tracked separately.
