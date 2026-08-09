---
title: "Spec: Observability Bundle"
layout: default
permalink: /spec-observability-bundle/
---

# Spec: Observability Bundle (trace storage + UI for agent runs)

Status: **DRAFT — awaiting approval.** No code yet. (Being built next.)

## 1. Problem & outcome

Agent run tracing (PR #320) makes Shield emit OTLP spans to
`SHIELD_OTLP_TRACES_ENDPOINT`, but **Shield ships no trace backend or UI** — you
must point it at your own. A customer who **has no observability stack** (common
on-prem / air-gapped) has nowhere to send or view the traces. LiteLLM users often
already have an OTEL collector / Langfuse to reuse, but many customers have
nothing.

**Outcome:** an **opt-in Observability Bundle** — separate containers, layered on
Shield like the [identity bundle](/workload-identity-bundle/) — that gives a customer a
working, durable, **scalable** trace store + UI with one command, without them
assembling it or Shield reinventing a trace database. Two tiers:

- **Demo tier:** Jaeger all-in-one (one container, built-in UI). "See a run tree
  in 30 seconds." In-memory — not durable, not for scale.
- **Production tier (Kubernetes):** **Grafana Tempo (distributed) → object storage
  (S3 / MinIO)** + Grafana UI + an **OpenTelemetry Collector** doing batching +
  tail-sampling, pre-wired to Shield's OTLP endpoint.

The **storage engine at scale is object storage** (managed S3, or MinIO on-prem)
behind Tempo — durable, elastic, cheap. Shield stays out of the trace-database
business; the bundle wires up the CNCF standard (same principle as embedding SPIRE,
not rebuilding it).

### Non-goals
- **No Shield code change** — the OTLP traces exporter already exists (PR #320);
  this is deploy artifacts + docs.
- Not building a trace UI or storage engine — Tempo/Jaeger/object-storage are used.
- Not mandatory — a customer who has (or reuses) observability skips this entirely.
- Not the only sink — the file / ES / Splunk exporters remain available.

## 2. Plane & latency contract

- **Plane:** infrastructure packaging (new containers: Jaeger, or Tempo + MinIO +
  Grafana + OTel Collector). **No Shield plane touched; no code on any plane.**
- **Guard path:** none. Shield already emits spans fire-and-forget to the OTLP
  endpoint (PR #320); this bundle only stands up the *receiver*. Zero added
  guard-path latency. **Off the hot path entirely.**

## 3. Data model

- **No Shield Redis state.** Traces live in the bundle's storage engine:
  - Demo: Jaeger in-memory (ephemeral).
  - Prod: **object storage** (S3 bucket / MinIO), owned by Tempo — not Shield.
- Retention = the object-store lifecycle policy (documented default, e.g. 14 days).
- No new Shield config keys beyond the existing `SHIELD_OTLP_TRACES_ENDPOINT`
  (points Shield at the bundle's collector/Jaeger).

## 4. API / interface

**No new Shield endpoints.** Deploy artifacts + the existing env var:
- `deploy/observability/docker-compose.jaeger.yml` — demo profile (`--profile obs`).
- `deploy/helm/shield-observability/` — production Helm (Tempo-distributed + MinIO
  + Grafana + OTel Collector), or values/overlays over the upstream `grafana/tempo`
  + `open-telemetry/opentelemetry-collector` charts (delegate, don't vendor).
- Shield side: set `SHIELD_OTLP_TRACES_ENDPOINT` at the bundle's OTel Collector
  (`http://otel-collector:4318`) or Jaeger (`http://jaeger:4318`).

## 5. Security & backward compatibility

- **Opt-in, default off.** No profile / no Helm release → nothing runs; Shield
  unaffected. Non-breaking.
- **Traces can contain sensitive attributes** — span attributes carry
  agent/tenant/route/status but the guard *content* (prompts/outputs) is NOT put on
  spans (only metadata). Document that operators control what the collector
  forwards; provide a collector `attributes`/`redaction` processor example.
- **Object-storage credentials** (S3/MinIO) sourced from a Secret / secrets
  manager, never values files (mirror the identity bundle's guidance).
- **UI access** (Grafana / Jaeger) must be put behind the customer's auth / network
  policy — documented; the bundle does not expose it publicly by default.

## 6. Packaging & deploy

- **No new pip deps**, no `requirements*.txt` change, no `Dockerfile.admin` change,
  **core Shield image unchanged.** Upstream images only (Jaeger, Tempo, MinIO,
  Grafana, OTel Collector).
- New files: `deploy/observability/` (compose + collector config),
  `deploy/helm/shield-observability/` (prod), `docs/observability-bundle.md`.
- CI: `docker compose config` + `helm lint`/`template` + OTel Collector config
  validation (`otelcol validate`). Live `kind` run is the manual pre-release gate.

## 7. Failure modes & edge cases

- **Collector / Tempo down** → Shield's OTLP export errors are logged and swallowed
  (existing fire-and-forget); **guard path unaffected**, spans for that window are
  lost (telemetry, not audit — audit stays in Redis). Document HA (multi-replica
  collector + Tempo ingesters).
- **Object storage unreachable** → Tempo ingesters buffer then error; traces for
  the outage window lost. DR = the object store's own durability/replication.
- **Trace volume explosion** (agent runs are span-heavy) → **tail-sampling** in the
  Collector (keep all errored/blocked runs, sample the rest, default e.g. 10%
  baseline) + object-store retention. Ship sane defaults; document tuning.
- **Demo tier restart** → Jaeger in-memory loses all traces (expected; demo only).
- **No `SHIELD_OTLP_TRACES_ENDPOINT` set** → bundle runs but receives nothing
  (misconfig); NOTES/health surface this.

## 8. Test plan (Definition of Done)

- **Demo:** `docker compose --profile obs up`; Shield → Jaeger; a guarded request
  produces a span visible in Jaeger UI (manual + a scripted OTLP-receive check).
- **Prod:** `helm lint` + `helm template` clean; **validate on a `kind` cluster** —
  Tempo + MinIO + Grafana + Collector come up, Shield spans land in MinIO and
  render in Grafana. (Cluster run is the manual gate — CI does lint/template only.)
- **Collector config:** `otelcol validate` passes; tail-sampling keeps errored runs.
- Full Python suite unaffected (no Shield code change) — regression guard only.

## Invariant risk flags
- ✅ Off the hot path; no Shield code, no plane/data-model/dep/Dockerfile impact.
- ✅ Opt-in, default off → non-breaking.
- ⚠️ **Helm/scale parts cannot be validated in CI without a cluster** — ship
  `helm lint`/`template` as the automatable gate; a `kind` run is the pre-release
  manual gate (same posture as the identity bundle).
- ⚠️ **Trace-volume cost** at agent scale — mitigated by tail-sampling + retention
  defaults, documented.

## Task breakdown (build order)
- **PR 1 — Demo tier:** `deploy/observability/docker-compose.jaeger.yml`
  (Jaeger all-in-one + a minimal OTel Collector), `docs/observability-bundle.md`
  "quickstart", a scripted smoke that a span is received. The one-command
  "customer with nothing" answer.
- **PR 2 — Production Helm tier:** `deploy/helm/shield-observability/` — Tempo
  distributed + MinIO (or bring-your-own S3) + Grafana + OTel Collector with
  tail-sampling; `helm lint`/`template` in CI; documented `kind` validation.
- **PR 3 — LiteLLM / reuse note + hardening:** docs for pointing Shield + LiteLLM
  at the same collector/Langfuse; attribute-redaction processor; retention/sampling
  tuning guide.

## Open decisions for approver
1. **Prod storage engine** — Grafana Tempo + object storage (recommended: cheapest,
   K8s-native) vs Jaeger + Elasticsearch/Cassandra (if the customer already runs ELK)?
2. **On-prem object storage** — bundle **MinIO** (self-contained) vs require
   bring-your-own S3-compatible endpoint? (Recommend bundle MinIO with a BYO override.)
3. **Vendor Helm charts vs subchart-depend** on `grafana/tempo` +
   `open-telemetry/opentelemetry-collector` (recommend depend, don't vendor).
4. **Default sampling** — 100% (simplest, costly) vs tail-sample keep-errors + 10%
   baseline (recommended for scale)?
