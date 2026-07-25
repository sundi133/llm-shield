---
title: Agent Run Tracing
layout: default
permalink: /agent-run-tracing/
description: Correlate and trace a multi-turn agent run across Shield's guard calls — a run_id on every record, optional spans, and OTLP-compatible export to Jaeger/Tempo/Datadog.
---

# Agent run tracing

A multi-turn agent produces a stream of guard records — input per turn, output per
reply, a check per tool call. Agent run tracing ties them together so you can see
and query **one run** end to end.

It has three layers, each independently useful:

1. **`run_id` correlation** — always on, additive.
2. **Spans** — opt-in structure (run → per-call spans as a tree).
3. **OTLP traces export** — opt-in shipping to a trace backend.

## 1. run_id — always on

Every guard record carries a `run_id` in its audit metadata, so records for one run
join together. Shield resolves it per request (first hit wins):

1. `X-Shield-Run-Id` request header
2. body `run_id`
3. body `session_id` (reused when present)
4. generated `run-<uuid>`

The resolved value comes back on every guard response as the **`X-Shield-Run-Id`**
header, so a client that didn't supply one can correlate its later calls.

```bash
# supply your own run id; it is echoed back and stamped on every record
curl -sD - https://<host>/guardrails/input \
  -H "X-Shield-Run-Id: run-order-8821" -H "Content-Type: application/json" \
  -d '{"message":"..."}' | grep -i x-shield-run-id
```

This is **additive**: `run_id` is a new field, existing `session_id` values are
unchanged. Reconstruct a run by joining `audit:{tenant}` records (time-ordered) on
`run_id`.

## 2. Spans — opt-in

Enable span emission and Shield produces one span per guarded request. All spans of
a run share a trace id derived from the `run_id` and hang under a synthetic
run-root, so a backend renders the run as a tree (input, output, each tool call).
If your agent framework propagates a W3C **`traceparent`**, Shield honors it for
real nesting.

```bash
SHIELD_SPAN_TRACING=true          # or just set SHIELD_OTLP_TRACES_ENDPOINT (below)
```

Spans are **off by default** — without this, event volume and behavior are
identical to before.

## 3. OTLP traces export — opt-in

Point Shield at any OTLP collector and the spans render as trace trees in
Jaeger / Grafana Tempo / Datadog:

```bash
SHIELD_OTLP_TRACES_ENDPOINT=http://otel-collector:4318   # also enables span emission
```

Only spans are sent to `/v1/traces`; guardrail log events continue to your existing
log exporters (Elasticsearch / Splunk / file).

## Viewing traces — Shield does not ship a UI

Shield emits standard OTLP; you view runs in **your** trace backend. Three paths:

**1. Reuse an existing observability platform (most enterprises).**
Point Shield at your OTLP ingest — no new tool to run:

| Backend | `SHIELD_OTLP_TRACES_ENDPOINT` |
|---|---|
| Datadog (Agent OTLP) | `http://datadog-agent:4318` |
| Grafana Cloud / Tempo | your Tempo OTLP endpoint |
| Splunk Observability | your OTLP ingest URL |
| Elastic APM | your APM OTLP endpoint |
| Honeycomb / New Relic | their OTLP endpoint (+ API key header) |

**2. Self-host, free / open-source (on-prem or air-gapped).** The quickest is
**Jaeger all-in-one** — one container, UI included:

```bash
docker run -d -p 16686:16686 -p 4318:4318 jaegertracing/all-in-one

# point Shield at it, then open the UI
SHIELD_OTLP_TRACES_ENDPOINT=http://localhost:4318
# → http://localhost:16686  (search by service "votal-shield", filter by run.id)
```

For production self-hosting, **Grafana Tempo + Grafana** (or an OpenTelemetry
Collector fanning out to Tempo/Jaeger) is the common choice.

**3. Nothing extra.** If you don't need the waterfall view, skip spans entirely and
correlate runs by `run_id` in Shield's portal / audit records (Redis) — no backend
required.

To find one run in any backend: filter by the `run.id` attribute (or the trace id,
which is derived from `run_id`).

## Is this OpenTelemetry?

**It is OTLP-compatible — it speaks the OpenTelemetry *protocol* — but it does not
use the OpenTelemetry *SDK*.**

| | Shield agent run tracing |
|---|---|
| OTLP wire format (`/v1/traces`) | ✅ yes |
| Works with Jaeger / Tempo / Datadog / OTel Collector | ✅ yes |
| W3C `traceparent` propagation | ✅ parsed / honored |
| `opentelemetry-*` SDK dependency | ❌ none (hand-rolled OTLP JSON) |
| Auto-instrumentation of libraries | ❌ no |
| SDK sampling / baggage / batch processor | ❌ no |

This is deliberate: it keeps Shield self-contained (no new dependencies on the
guard path). A trace backend cannot tell the difference for these spans; a
developer reading the code will see no `opentelemetry` import. If you need full
SDK-based OpenTelemetry (auto-instrumentation, the Context API, configurable
sampling), that is a heavier, separate integration.

## Where the data is stored

Two different layers, two different stores — **Shield does not add a new store for
traces**:

| Data | Stored in | Retention |
|---|---|---|
| **`run_id` + audit records** (correlation) | **Redis** — the existing `audit:{tenant}` ZSET (run_id is just a new field) | 30-day TTL, 1M-entry cap |
| **Spans / trace trees** | **Your observability backend** via the configured exporter — OTLP (Jaeger / Grafana Tempo / Datadog), Elasticsearch, Splunk, or a local JSON file (`logs/votal-shield.json`) | your backend's retention |

Spans are **not** written to Redis. They transit an in-memory buffer
(`deque(maxlen=10000)`) and are shipped by the exporters; if **no** exporter is
configured, spans are simply dropped (fire-and-forget — telemetry never blocks the
guard path). The in-memory buffer is not durable: unflushed events are lost on a
crash, so durability comes from the exporter's backend, not from Shield.

**In short:** Redis stays the hot / enforcement store and holds the correlated
audit records; the **trace backend you point Shield at is the system-of-record for
the trace trees.** The [tamper-evident audit chain](https://docs.shield.votal.ai/)
is a separate integrity layer over the audit records.

## Config reference

| Env var | Effect | Default |
|---|---|---|
| `X-Shield-Run-Id` (header) | supply a run id for the request | generated |
| `SHIELD_SPAN_TRACING` | emit spans into the telemetry buffer | off |
| `SHIELD_OTLP_TRACES_ENDPOINT` | OTLP collector for `/v1/traces` (also enables spans) | unset |
