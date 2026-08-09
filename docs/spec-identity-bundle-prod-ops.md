---
title: "Spec: Identity Bundle Production Ops"
layout: default
permalink: /spec-identity-bundle-prod-ops/
---

# Spec: Identity Bundle — production-ops gaps

Status: **DRAFT — awaiting approval.** Built one PR at a time.

## 1. Problem & outcome

A doc review of [identity-bundle.md](/workload-identity-bundle/) found it strong as a
design + threat-model doc but **thin as a production operations manual**, and in
one place **overpromising** (it references a Helm chart and SPIRE Controller
Manager that do not exist in the repo). Concrete gaps:

1. **Overpromise:** points at a Helm chart / non-Python clients as if they exist.
2. **Day-2 operations:** no failure-modes (fail-open vs closed), SVID TTL/sizing,
   Postgres backup/DR, CA-rotation runbook, SPIRE upgrade path, troubleshooting.
3. **Observability:** no "what to watch" — SPIRE/Envoy stats, Shield logs, the
   guardrail-metrics API.
4. **Secret sourcing:** `SHIELD_TRUSTED_PROXY_SECRET` + Postgres password shown as
   bare env vars, no secrets-manager guidance.
5. **Kubernetes path:** the compose story is documented; K8s/Helm is not.
6. **Client integration:** only a Python/LangChain pointer — no Go/Node, no sample
   of the injected `X-Forwarded-Client-Cert`, no SVID caching/rotation notes.
7. **Federation:** named, not shown.
8. **Smoke checks** not enumerated in the doc.

**Outcome:** an operator can stand up, run, observe, and recover a **production**
deployment from the docs alone, with no undocumented promises; and a K8s shop has
a real (validated-on-cluster) Helm path.

### Non-goals
- No change to Shield's runtime behavior — this is docs + deploy artifacts.
- Not adding a Prometheus `/metrics` endpoint (none exists today); observability
  documents what already exists (structured logs, the guardrail-metrics JSON API,
  SPIRE/Envoy's own stats). A metrics endpoint is a separate future spec.
- Not writing SDKs for every language — document the Workload API contract + one
  additional worked example (Go), point to `py-spiffe`/`go-spiffe` for the rest.

## 2. Plane & latency contract
**N/A — no code on any plane.** Docs, a Helm chart, and client examples only.
**Off the hot path** entirely; no change to `/guardrails/*`, `cap/mint`,
`tools/call`, or any middleware.

## 3. Data model
No new state. Documents the existing SPIRE Postgres datastore (backup/DR) and the
existing env/config surface. No new Redis keys.

## 4. API / interface
No new endpoints. Documents existing surfaces an operator observes:
`GET /health`, `GET /v1/tenant/me/guardrails/metrics`, SPIRE server/agent
`healthcheck`, Envoy admin `/stats` + access logs.

## 5. Security & backward compatibility
Docs + additive deploy artifacts. The Helm chart is a **new, opt-in** artifact
(nobody is auto-migrated). No behavior change, no default change. Secret-sourcing
guidance strengthens posture without changing code.

## 6. Packaging & deploy
- **No new pip deps**, no `requirements*.txt` change, no `Dockerfile.admin` change.
- New files: `deploy/helm/shield-identity/` (chart), `examples/identity/` (Go
  client + XFCC sample), doc edits.
- The Helm chart references upstream SPIRE/Envoy images + a Shield image; it adds
  nothing to the Shield image itself.

## 7. Failure modes & edge cases (this becomes doc content)
The doc must state these explicitly:
- **spire-server down:** agents keep working until their SVID TTL expires; new
  SVIDs stop issuing; once expired, Envoy rejects → Shield token issuance **fails
  closed** (403). HA (3 replicas) mitigates.
- **Postgres down:** SPIRE server can't issue/rotate → same expiry-driven
  fail-closed. DR = documented restore.
- **CA rotation:** SPIRE rotates automatically; Envoy gets the new bundle over
  SDS; `SHIELD_SPIFFE_TRUST_BUNDLE` must be refreshed (spiffe-helper) — runbook.
- **Clock skew:** SVID validity is time-bound; document NTP requirement.
- **Secret rotation:** rotating `SHIELD_TRUSTED_PROXY_SECRET` = update Envoy +
  Shield together (brief overlap window guidance).

## 8. Test plan (Definition of Done)
- **Docs (PR 1):** rendered locally (Jekyll build clean), all internal links/anchors
  resolve, no reference to unbuilt artifacts without a "not yet available" marker.
- **Helm (PR 2):** `helm lint` clean; `helm template` renders; **validated on a
  `kind` cluster** (documented run, since CI/local here can't) — the chart is not
  claimed working until that passes. Add a `helm template` check to the identity CI.
- **Client example (PR 3):** the Go example compiles (`go build`); documents the
  Workload API fetch + a real XFCC sample.
- Full Python suite stays green (no code change, so this is a regression guard only).

## Invariant risk flags
- ✅ Off the hot path; no plane/data-model/dep/Dockerfile impact.
- ✅ Non-breaking (docs + opt-in artifacts).
- ⚠️ **Helm chart cannot be validated in this environment** (no cluster). It ships
  marked "validate on your cluster," with `helm lint`/`template` as the automatable
  gate; a `kind`-based CI job is the follow-on.
- ⚠️ **Fix the overpromise first** — until Helm/clients land, the doc must say
  "not yet available," not imply they exist.

## Task breakdown (build order)
- **PR 1 — Production Operations doc section** (verifiable now, closes gaps 1-4,7,8):
  add to `identity-bundle.md`: Failure modes & recovery, Troubleshooting,
  Observability (what to watch), Secret sourcing, Federation worked example,
  the enumerated 5 smoke checks; and **correct the overpromising** Helm/client
  references to "not yet available." Fully reviewable as markdown.
- **PR 2 — Helm chart** (gap 5): `deploy/helm/shield-identity/` with SPIRE
  server/agent + SPIRE Controller Manager (auto-registration) + Envoy; `helm lint`
  + `helm template` in CI; documented `kind` validation. Then document the K8s path.
- **PR 3 — Client integration** (gap 6): a Go Workload-API example + an XFCC
  header sample + SVID caching/rotation notes; point to go-spiffe/py-spiffe.

## Open decisions for approver
1. **PR 1 scope** — do all doc gaps in one PR (recommended) or split ops vs clients?
2. **Helm now or defer** — author PR 2 as "validate-on-cluster" (recommended, so
   the K8s path exists), or just mark Helm "coming soon" and defer the build?
3. **Client example language** — Go (recommended: most common non-Python workload
   + go-spiffe is first-class) vs Node?
