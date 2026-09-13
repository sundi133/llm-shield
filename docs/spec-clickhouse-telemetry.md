---
title: "Spec: ClickHouse telemetry store"
layout: default
nav_order: 68
permalink: /spec-clickhouse-telemetry/
description: "Durable, time-retained storage for guardrail decision and request audit events in ClickHouse, for on-prem deployments. Opt-in, dual-write alongside Redis, zero network I/O on the guard path, readers switched by a separate flag."
---

# Spec: ClickHouse telemetry store

Status: DRAFT, awaiting approval. No code written.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. Problem & outcome

### What is wrong today

Shield keeps two kinds of audit event in the same Redis that serves tenant
policies and API keys. Both were verified on `main` (832672b).

| Store | Redis shape | Retention | Problem |
|---|---|---|---|
| Decision audit, `storage/decision_audit.py` | `decisions:{tenant_id}` LIST, `decisions:global` LIST | **count-capped**: `ltrim` to 50,000 per tenant, 200,000 global | Older decisions are discarded silently. For a busy tenant 50,000 entries can be hours, not the months an audit needs |
| Request audit, `storage/audit_log.py` | `audit:{tenant_id}` ZSET scored by unix time | `AUDIT_MAX_ENTRIES` (default 1,000,000) and `AUDIT_TTL_SECONDS` (default 30 days) | A single sorted set of up to 1M JSON records is expensive memory, and it stores `input_text` (first 500 characters of the prompt) |

The readers cannot answer the questions an audit asks:

- `query_decisions` fetches `(offset + limit) * 4` entries with `lrange` and
  filters them in Python. A filtered query such as `action=block,
  guardrail=pii_detection` silently misses every match older than that window,
  and the response gives no sign of it.
- `AuditLogger.get_stats` with no `since` reads the whole set with
  `zrange(key, 0, -1)`, up to 1M JSON documents parsed per call.
- `get_blocked_dashboard` caps its scan at `_DASHBOARD_MAX_SCAN = 20_000` because
  reading more stalls the admin plane. It reports `truncated` honestly, but it is
  still an answer about the last 20,000 events, not the requested window.

On-prem customers (RHEL, government and enterprise, often air-gapped, per
`docs/on-premises-deployment-guide.md`) need audit retained by time, queryable
over that whole time, and stored in something their operators can run.

### Outcome

When an operator sets `SHIELD_CLICKHOUSE_URL`, every decision audit event and
request audit event is also written to ClickHouse by a bounded background
writer, retained by time, and, once the operator sets
`SHIELD_TELEMETRY_READ_BACKEND=clickhouse`, served to the existing read
endpoints with server-side filtering over the full retention window.

Observable success conditions:

1. With 60,000 decisions for one tenant, `GET /v1/shield/decisions/{tenant_id}?action=block`
   returns blocks from the oldest 10,000, which Redis has already discarded.
2. The dashboard for a 30-day window reports `truncated: false` regardless of
   event volume.
3. With ClickHouse unreachable, `/guardrails/input` and `/v1/shield/tool/check`
   latency is unchanged, and the loss is counted rather than silent.
4. With the variable unset, behavior is byte-for-byte what it is today: no
   thread, no connection, no new log line.
5. No prompt text reaches ClickHouse unless the operator opts in.

### Non-goals

- **Replacing Redis for policies, tenants, API keys, rate limits or nonces.**
  Those stay in Redis.
- **Removing the Redis audit writes.** This spec is dual-write. Turning Redis
  audit writes off is a later spec, gated on the disk spool (below).
- **Guardrail metric counters** (`storage/guardrail_metrics.py` `hincrby`
  counters). They are small and TTL'd, and already off the request path. Moving
  them to a ClickHouse materialized view is a follow-up.
- **The tamper-evident audit chain** (`storage/audit_chain.py`). Its home is
  object storage with object lock, not an analytics table.
- **A disk spool** for events that cannot be delivered. Needed before Redis audit
  writes are removed; not needed while Redis still holds the same events.
- **Backfilling** existing Redis audit data into ClickHouse.
- **Clustered DDL.** The shipped schema is single-node `MergeTree`. Operators
  running a cluster adapt it to `ReplicatedMergeTree`.
- **SIEM exporters** in `core/telemetry.py` (Elasticsearch, Splunk HEC, OTLP,
  file) are unchanged and keep running alongside.

## 2. Plane & latency contract

**Both planes.**

| | Data plane (`core/app.py`) | Admin plane (`admin_app.py`) |
|---|---|---|
| Writes decisions | `/v1/shield/tool/check` (`api/routes_tool.py`), MCP enforcement (`core/mcp/enforcement.py`), A2A (`api/routes_a2a.py`), `api/routes_agent.py` | none |
| Writes request audit | `/guardrails/input`, `/guardrails/output`, gateway, agent, action, MCP routes | `/v1/shield/chat/agent` (`admin_app.py:256`) |
| Mounts readers | `routes_audit`, `routes_decisions`, `routes_guardrail_metrics` | the same, plus `routes_board_report` |

### Guard path: touched, with a zero-I/O budget

Writers sit on the guard path. The contract for the ClickHouse addition is:

- **On the request thread: one dict construction and one `queue.put_nowait`.**
  No network I/O, no disk I/O, no lock held beyond the queue's own.
- **Budget: under 50 microseconds per event** for the enqueue, asserted by a test
  that enqueues against a transport that blocks for 5 seconds (§8).
- **Never raises into the caller.** A full queue, a bad row or a disabled sink
  returns immediately.

For `audit_log`, the enqueue happens inside `_write_sync`, which already runs in
the executor, so it adds nothing to the request thread at all.

For `decision_audit`, `log_decision` runs on the request thread.

### A pre-existing guard-path violation this spec does not fix

`log_decision` performs **four synchronous Redis round trips** (`lpush` and
`ltrim` on the tenant list, then on the global list) on `/v1/shield/tool/check`
and in MCP enforcement. On Upstash each is an HTTPS request. That violates the
off-hot-path invariant today, independent of ClickHouse.

This spec puts the ClickHouse enqueue **before** the Redis writes so the new path
is not delayed by the old one, and proposes moving the Redis writes off the
request thread as a **separate, flagged task** (§9). It is not bundled here
because it changes existing behavior on its own.

### Readers: off hot path

Read endpoints are portal and compliance traffic, not guarded traffic. Two rules
keep a slow ClickHouse from harming either plane:

- Every query has a hard timeout, `SHIELD_CLICKHOUSE_QUERY_TIMEOUT_S`, default 10.
- Query calls from async routes run in `asyncio.to_thread`. Today
  `list_decisions` calls the synchronous `query_decisions` directly from an async
  route, which blocks the event loop; with a network call behind it that becomes
  a worker-wide stall.

## 3. Data model

### Redis

**No new Redis keys. No change to existing keys, shapes or TTLs.**
`decisions:{tenant_id}`, `decisions:global` and `audit:{tenant_id}` keep being
written exactly as today.

### ClickHouse

Database: `SHIELD_CLICKHOUSE_DATABASE`, default `shield`. Validated against
`^[A-Za-z_][A-Za-z0-9_]{0,63}$` at startup, because it is interpolated into SQL
and cannot be a bound parameter.

The DDL ships as `deploy/clickhouse/schema.sql` and is **run by the operator**,
not by Shield. On-prem database teams want to review DDL, and Shield's
ClickHouse user then needs no DDL privilege.

```sql
CREATE DATABASE IF NOT EXISTS shield;

CREATE TABLE IF NOT EXISTS shield.decisions
(
    event_id     UUID,
    ts           DateTime64(3, 'UTC'),
    tenant_id    LowCardinality(String),
    action       LowCardinality(String),
    guardrail    LowCardinality(String),
    agent_key    String,
    tool_name    String,
    user_role    LowCardinality(String),
    session_id   String,
    reason       String,
    source_ip    String,
    metadata     String,
    shield_node  LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (tenant_id, ts)
TTL toDateTime(ts) + INTERVAL 90 DAY
SETTINGS non_replicated_deduplication_window = 1000;

CREATE TABLE IF NOT EXISTS shield.request_audit
(
    event_id              UUID,
    ts                    DateTime64(3, 'UTC'),
    tenant_id             LowCardinality(String),
    agent_key             String,
    endpoint              LowCardinality(String),
    action_taken          LowCardinality(String),
    guardrails_triggered  Array(LowCardinality(String)),
    latency_ms            Float64,
    run_id                String,
    user_role             LowCardinality(String),
    input_chars           UInt32,
    input_hmac            String,
    input_text            String,
    metadata              String,
    shield_node           LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (tenant_id, ts)
TTL toDateTime(ts) + INTERVAL 90 DAY
SETTINGS non_replicated_deduplication_window = 1000;
```

Column mapping is one-to-one with the existing Redis entry dicts, so readers can
return the same response shapes:

- `shield.decisions` mirrors the `entry` built in `log_decision`.
- `shield.request_audit` mirrors the `record` built in `AuditLogger._write_sync`.
  `run_id` and `user_role` are lifted out of `metadata`, where the classify route
  puts them, because they are filter columns.
- `metadata` is stored as JSON text. ClickHouse's native JSON type is avoided so
  older on-prem ClickHouse versions work.
- `tenant_id` is the empty string for events without a tenant, matching
  `audit:global`.
- `shield_node` is the hostname, so an operator can tell which worker a gap came
  from.

**Retention** is 90 days in the shipped DDL, matching `_METRICS_TTL_DAYS`.
Operators change it with `ALTER TABLE ... MODIFY TTL`. SOC 2 programs often want
a year; this is an operator decision, not a code change.

**Sort key.** `(tenant_id, ts)` makes every tenant-scoped, time-bounded query a
range scan. Partitioning by month makes TTL expiry a partition drop.

### Prompt text

Redis stores `input_text[:500]` today. ClickHouse keeps prompts longer and
queries them more easily, so the default is stricter:

| Column | Default | When populated |
|---|---|---|
| `input_chars` | always | length of the full input |
| `input_hmac` | empty | `HMAC-SHA256(SHIELD_CLICKHOUSE_INPUT_HMAC_KEY, input)` hex, only when that key is set |
| `input_text` | empty | first 500 characters, only when `SHIELD_CLICKHOUSE_STORE_INPUT_TEXT=1` |

A keyed HMAC rather than a plain SHA-256, because a short prompt's plain hash is
reversible by dictionary. The HMAC lets an investigator confirm "was this exact
prompt sent" without the table holding the prompt.

### Tenant scoping and isolation

- `tenant_id` is resolved exactly as today, by the existing auth
  (`verify_tenant_path_access` on `/v1/shield/decisions/{tenant_id}`, the tenant
  resolution in `routes_audit`). This spec adds no new way to name a tenant.
- **Every reader query binds `tenant_id` as a parameter.** The query builder
  refuses to build a statement without it (§8 tests this). There is no global
  read in this spec; no current route calls `query_decisions` without a tenant.
- Values never reach SQL text. Queries use ClickHouse HTTP query parameters:
  `WHERE tenant_id = {tenant_id:String}` with `param_tenant_id` in the URL.

### Write path

Per process (the data plane runs `WORKERS`, default 32):

```
request thread / executor
   |  queue.put_nowait(row)            bounded: SHIELD_CLICKHOUSE_QUEUE_MAX (50,000)
   v
writer thread (daemon, one per process)
   |  batch up to SHIELD_CLICKHOUSE_BATCH_MAX rows (5,000)
   |  or SHIELD_CLICKHOUSE_FLUSH_MS (1,000 ms), whichever first
   v
POST {url}/?query=INSERT INTO shield.decisions FORMAT JSONEachRow
     &insert_deduplication_token=<batch uuid>
```

- **Retries** with exponential backoff, capped at
  `SHIELD_CLICKHOUSE_RETRY_MAX` (5). A retry resends the identical batch with the
  identical `insert_deduplication_token`, and `non_replicated_deduplication_window`
  makes ClickHouse discard the duplicate if the first attempt landed.
- **`async_insert` is not used.** The client already batches, and async-insert
  deduplication has separate semantics that would make retries unsafe.
- **When the queue is full** the new event is dropped and
  `dropped_total` increments. **When retries are exhausted** the batch is dropped
  and `failed_rows_total` increments. Neither is silent (§4, heartbeat).
- **On shutdown** (`atexit` and the FastAPI lifespan), the writer flushes for up
  to `SHIELD_CLICKHOUSE_SHUTDOWN_FLUSH_S` (5) seconds.

This is **at-most-once with counted loss**, not durable delivery. That is
acceptable only because Redis still receives the same events. The disk spool in
the non-goals is the precondition for ever removing the Redis write.

## 4. API / interface

### HTTP: no new guard or tenant endpoints

Existing endpoints keep their paths, parameters, auth and response shapes. With
`SHIELD_TELEMETRY_READ_BACKEND=clickhouse` they read ClickHouse instead of Redis:

| Endpoint | Auth | Backed by |
|---|---|---|
| `GET /v1/shield/decisions/{tenant_id}` | `verify_tenant_path_access` | `query_decisions` |
| `GET /v1/shield/audit` | as today (`routes_audit`) | `AuditLogger.query` |
| `GET /v1/shield/stats` | as today | `AuditLogger.get_stats` |
| `GET /v1/tenant/me/guardrails/dashboard` | tenant key | `get_blocked_dashboard` audit scan |
| `GET /v1/tenant/me/board-report` | tenant key | `query_decisions` |

Behavioral differences on the ClickHouse path, all strictly better and none
changing the shape:

- Filters are applied in SQL over the whole retention window.
- `get_stats` is one aggregate query, not a full scan.
- The dashboard reports `truncated: false` and `scanned` equal to the rows
  aggregated.

`/v1/shield/audit/verify` and `/v1/shield/audit/export` (the audit chain) are
unchanged.

### HTTP: one new admin endpoint

`GET /v1/admin/telemetry/clickhouse`, admin plane and data plane, `X-Admin-Key`
(the existing `/v1/admin/*` check in `core/auth.py`).

```json
{
  "write_enabled": true,
  "read_backend": "redis",
  "reachable": true,
  "nodes": [
    {"shield_node": "dp-7f9c", "last_heartbeat": "2026-09-13T10:00:00Z",
     "sent_rows_total": 184220, "dropped_total": 0, "failed_rows_total": 0,
     "queue_depth": 12}
  ]
}
```

Per-process counters are meaningless behind 32 workers, because a request lands
on one arbitrary worker. So each writer inserts a heartbeat row every 60 seconds
into `shield.sink_heartbeat`, and this endpoint aggregates them fleet-wide:

```sql
CREATE TABLE IF NOT EXISTS shield.sink_heartbeat
(
    ts                 DateTime64(3, 'UTC'),
    shield_node        LowCardinality(String),
    pid                UInt32,
    sent_rows_total    UInt64,
    dropped_total      UInt64,
    failed_rows_total  UInt64,
    queue_depth        UInt32
)
ENGINE = MergeTree
ORDER BY (shield_node, ts)
TTL toDateTime(ts) + INTERVAL 7 DAY;
```

### Python interface

New module `storage/clickhouse_sink.py`:

```python
def write_enabled() -> bool: ...
def read_enabled() -> bool: ...
def enqueue(table: str, row: dict) -> None: ...        # never blocks, never raises
def query(sql: str, params: dict, *, tenant_id: str,
          timeout_s: float | None = None) -> list[dict]: ...
def status() -> dict: ...
def shutdown(timeout_s: float = 5.0) -> None: ...

class TelemetryStoreUnavailable(Exception): ...
```

- `table` is one of a fixed set (`decisions`, `request_audit`,
  `sink_heartbeat`); anything else is rejected.
- `query` requires `tenant_id` as a keyword argument and binds it as
  `param_tenant_id`.

Transport is ClickHouse's **HTTP interface through `httpx`**, which is already in
`requirements.txt` and `requirements-admin.txt`. No ClickHouse client library.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SHIELD_CLICKHOUSE_URL` | unset | `https://host:8443` or `http://host:8123`. **Unset disables everything** |
| `SHIELD_CLICKHOUSE_DATABASE` | `shield` | validated identifier |
| `SHIELD_CLICKHOUSE_USER` / `SHIELD_CLICKHOUSE_PASSWORD` | unset | sent as `X-ClickHouse-User` / `X-ClickHouse-Key` |
| `SHIELD_CLICKHOUSE_PASSWORD_FILE` | unset | read the password from a mounted file instead |
| `SHIELD_CLICKHOUSE_CA_CERT` | unset | CA bundle path for a private on-prem CA |
| `SHIELD_TELEMETRY_READ_BACKEND` | `redis` | `redis` or `clickhouse`. Independent of the write switch |
| `SHIELD_CLICKHOUSE_STORE_INPUT_TEXT` | `0` | store the first 500 characters of the prompt |
| `SHIELD_CLICKHOUSE_INPUT_HMAC_KEY` | unset | enables `input_hmac` |
| `SHIELD_CLICKHOUSE_QUEUE_MAX` | `50000` | per-process queue bound |
| `SHIELD_CLICKHOUSE_BATCH_MAX` | `5000` | rows per insert |
| `SHIELD_CLICKHOUSE_FLUSH_MS` | `1000` | max wait before a partial batch is sent |
| `SHIELD_CLICKHOUSE_RETRY_MAX` | `5` | insert attempts per batch |
| `SHIELD_CLICKHOUSE_QUERY_TIMEOUT_S` | `10` | per read query |
| `SHIELD_CLICKHOUSE_SHUTDOWN_FLUSH_S` | `5` | flush budget at exit |

## 5. Security & backward compatibility

**Opt-in, non-breaking.** With `SHIELD_CLICKHOUSE_URL` unset nothing changes: no
thread, no connection, no import-time network activity. With it set and
`SHIELD_TELEMETRY_READ_BACKEND` left at `redis`, only an additional write
happens.

**Separate read switch, deliberately.** Operators dual-write, compare ClickHouse
against Redis for a period, then flip reads. Switching reads automatically when
the URL appears would put an empty ClickHouse in front of compliance readers on
day one.

**Migration path**

1. Run `deploy/clickhouse/schema.sql`. Create a user with `INSERT, SELECT` on
   `shield.*` and no DDL.
2. Set `SHIELD_CLICKHOUSE_URL` and credentials on both planes. Restart.
3. Confirm `GET /v1/admin/telemetry/clickhouse` shows every node heartbeating
   with `dropped_total` and `failed_rows_total` at 0.
4. After ClickHouse has covered the window you care about, set
   `SHIELD_TELEMETRY_READ_BACKEND=clickhouse`. Revert by setting it back to
   `redis`; Redis never stopped being written.

**Escape hatch:** unset `SHIELD_CLICKHOUSE_URL`, or set
`SHIELD_TELEMETRY_READ_BACKEND=redis`.

**Read failure is visible, not a silent fallback.** With reads on ClickHouse and
ClickHouse down, readers return `503 {"error": "telemetry_store_unavailable"}`.
Falling back to Redis would serve a count-capped window that looks like a
complete answer, which is the exact defect this spec exists to remove.

**Threats considered**

| Threat | Mitigation |
|---|---|
| SQL injection through filters | All values are bound HTTP query parameters. The database name is regex-validated. No string formatting of values into SQL |
| Cross-tenant read | `tenant_id` comes only from existing auth, is bound in every query, and the builder refuses a query without it |
| Prompt data exposure | Not stored by default. Opt-in text is truncated to 500 characters, matching Redis |
| Credential leakage | Never logged. `_FILE` variant for mounted secrets. TLS verification is never disabled; a private CA is configured, not bypassed |
| Plaintext on the wire | `https://` recommended and documented. `http://` accepted for a same-host or isolated-subnet install, with a startup warning when the host is not loopback |
| A tenant filling the store | Retention is time-based and partitioned. Per-tenant rate limits upstream are unchanged |

**New network egress.** The data plane now connects to ClickHouse (8443 or
8123). Firewall rules for air-gapped sites must allow it; the operator doc says
so.

## 6. Packaging & deploy

- **New module `storage/clickhouse_sink.py`** is imported by
  `storage/decision_audit.py` and `storage/audit_log.py`, both of which are
  already in `Dockerfile.admin` (lines 128 and 131). It **must be added** to
  `Dockerfile.admin`.

  The failure mode here is quieter than a crash-loop. `admin_app.py` imports
  `routes_decisions` and `routes_audit` inside `try/except Exception: pass`, so a
  missing file silently removes those endpoints from the admin plane rather than
  failing boot. `tests/test_admin_dockerfile_imports.py` follows module-level
  `try` blocks and will catch it; the PR must keep that test green.

- **No new pip dependency.** `httpx` is in `requirements.txt` and
  `requirements-admin.txt`, and CI gets it through `requirements-test.txt`'s
  `-r requirements.txt`. A test asserts the sink imports nothing outside the
  stdlib and `httpx`.

- **New non-code files:** `deploy/clickhouse/schema.sql`,
  `docs/clickhouse-telemetry.md` (operator guide, linked from
  `docs/on-premises-deployment-guide.md`), and
  `docker-compose.clickhouse.yml` for local development.

- **Images to rebuild:** data plane (`Dockerfile`, `Dockerfile.cloud`) and admin
  (`Dockerfile.admin`).

- **ClickHouse placement on-prem:** CPU nodes, never the GPU nodes.

## 7. Failure modes & edge cases

| Case | Behavior | Fail mode |
|---|---|---|
| URL unset | Sink never initializes. `enqueue` is a no-op returning immediately | n/a |
| ClickHouse unreachable at startup | Writer starts anyway and retries. Guard traffic unaffected. Heartbeats resume on recovery | open (writes), guard path unaffected |
| ClickHouse down mid-run | Batches retry, then drop with `failed_rows_total`. Queue fills, then `dropped_total` | open, counted |
| Reads set to ClickHouse, ClickHouse down | `503 telemetry_store_unavailable` | **closed and visible** |
| Slow ClickHouse on reads | Query aborted at `SHIELD_CLICKHOUSE_QUERY_TIMEOUT_S`, then `503` | closed and visible |
| Queue full (burst) | New event dropped, counter increments. Request unaffected | open, counted |
| Huge `metadata` or `reason` | Serialized row over 64 KB: `metadata` replaced with `{"truncated": true}` and counted, so one row cannot stall a batch | open |
| Non-serializable metadata value | `json.dumps(default=str)`, matching `core/telemetry.py` | open |
| Missing `tenant_id` on a decision | Stored as `''`. Unreachable through tenant readers, which always bind a tenant | n/a |
| Invalid `since`/`until` | `400`, not an unbounded query. Today `AuditLogger.query` silently treats an unparseable value as open-ended, and `query_decisions` compares it as a string | closed |
| `limit` / `offset` | Existing FastAPI bounds (`limit` 1 to 1000) kept. `offset` above 100,000 rejected, because deep offsets are the wrong tool for audit export | closed |
| Clock skew between nodes | `ts` is taken on the writing node. Ordering across nodes is best-effort, as in Redis today | n/a |
| Retry after an insert that actually landed | Same `insert_deduplication_token`, so ClickHouse drops the duplicate within the dedup window | exact within window |
| Process killed (SIGKILL, OOM) | Up to one queue of events lost. Redis still has them | open, bounded |
| Worker fork after sink starts | Sink initializes lazily on first `enqueue` in each process, never at import, so no thread survives a fork | n/a |
| Schema not applied | Inserts fail with a table-not-found error, counted, logged once per interval rather than per batch | open, counted |
| Database name fails validation | Sink disabled at startup with one clear error. Guard path unaffected | open, loud |
| Wrong credentials | Same as unreachable, plus an explicit auth error in the log | open, counted |

## 8. Test plan (Definition of Done)

All tests use a fake `httpx` transport unless marked integration.

**Sink, `tests/test_clickhouse_sink.py`**
- Disabled when URL unset: `enqueue` no-op, no thread created, `status()` reports disabled.
- **Guard-path budget:** with a transport that blocks for 5 s, 10,000 `enqueue`
  calls complete in under 0.5 s total, and the calling thread performs no socket
  operation.
- Batching by size and by `FLUSH_MS`.
- Retry resends the identical body with the identical `insert_deduplication_token`.
- Retries exhausted: `failed_rows_total` increments, and the writer continues with the next batch.
- Queue full: `dropped_total` increments, and `enqueue` still returns immediately.
- Unknown table name rejected.
- Database name validation rejects `shield; DROP` and similar.
- `query` without `tenant_id` raises. Values appear only as `param_*`, never in SQL text.
- Oversized row: metadata truncated and counted.
- Shutdown flushes pending rows within the budget.
- Credentials never appear in log output, including on auth failure.
- Lazy init: importing the module starts no thread.
- Imports only stdlib and `httpx`.

**Writers**
- `log_decision` enqueues a row matching the Redis entry field for field, and
  still writes Redis exactly as before (existing `tests/test_decision_audit.py`
  stays green unchanged).
- `log_decision` calls `enqueue` before the first Redis command (call-order test).
- `AuditLogger._write_sync` enqueues with `input_text` empty by default,
  populated only with `SHIELD_CLICKHOUSE_STORE_INPUT_TEXT=1`, and truncated to 500.
- `input_hmac` empty without a key, correct HMAC with one.
- `run_id` and `user_role` lifted from metadata.

**Readers**
- `SHIELD_TELEMETRY_READ_BACKEND=redis` (default): existing reader tests pass
  unchanged, and the ClickHouse transport is never called.
- `clickhouse`: `query_decisions` issues one parameterized query with each filter
  as a bound parameter, plus `ORDER BY ts DESC LIMIT/OFFSET`, and returns the
  existing entry shape.
- The regression the spec exists for: a match older than the Redis fetch window
  is returned.
- `get_stats` issues a single aggregate query and returns the existing shape.
- Dashboard reports `truncated: false`.
- Unavailable store gives `503 telemetry_store_unavailable` on each read endpoint.
- Invalid `since` gives `400`.
- Cross-tenant: a query for tenant A never carries tenant B's id, including when
  the path tenant and the authenticated tenant differ (existing
  `verify_tenant_path_access` behavior preserved).

**Status endpoint**
- Requires `X-Admin-Key`; `401` without it, `403` with a wrong one.
- Aggregates heartbeats from several nodes.

**Drift guards**
- `tests/test_admin_dockerfile_imports.py` passes with the new module in `Dockerfile.admin`.
- The column list in `deploy/clickhouse/schema.sql` matches the row dicts the
  writers build (parsed test), so the schema and code cannot drift.

**Integration, `tests/integration/test_clickhouse_live.py`**, skipped unless
`SHIELD_CLICKHOUSE_TEST_URL` is set: apply the schema to a real ClickHouse
container, write through both writers, read through each endpoint, and verify
TTL and dedup settings are accepted by the server.

**Done means:** full suite green in a clean venv (`python -m pytest tests -q`),
the integration test run once against a real ClickHouse with the result recorded
in the PR, and the CI `pytest` gate passing. Main's CI is currently red on
`test_at_least_one_tenant_scoped_route_is_discovered`, which predates this work;
the PR must show that no other test fails.

## 9. Task breakdown

On one branch, `feat/clickhouse-telemetry`, as one reviewable commit per task, in
order. Each commit leaves the suite green.

1. **Spec.** This document.
2. **Sink.** `storage/clickhouse_sink.py`, `deploy/clickhouse/schema.sql`, the
   `Dockerfile.admin` COPY, sink tests, schema drift test. No call sites, so no
   behavior change.
3. **Writers.** Enqueue from `log_decision` and `AuditLogger._write_sync`, the
   prompt-text policy, writer tests.
4. **Readers.** `SHIELD_TELEMETRY_READ_BACKEND` in `query_decisions`,
   `AuditLogger.query` and `get_stats`, and the dashboard scan; `to_thread` at the
   routes; `400` and `503` handling; reader tests.
5. **Visibility.** Heartbeat writes, `shield.sink_heartbeat`, and
   `GET /v1/admin/telemetry/clickhouse`, with tests.
6. **Operator path.** `docs/clickhouse-telemetry.md`, the on-prem guide link,
   `docker-compose.clickhouse.yml`, the live integration test, and one recorded run.

**Flagged, not in this branch**

- Move `log_decision`'s four synchronous Redis writes off the request thread
  (a pre-existing guard-path violation, §2).
- Disk spool for undeliverable events, the precondition for removing Redis audit writes.
- Guardrail metric counters as a ClickHouse materialized view.
- Audit chain to object storage with object lock.

## 10. Decisions needed before implementation

1. **Separate read switch** (`SHIELD_TELEMETRY_READ_BACKEND`, default `redis`), or
   switch reads automatically when the URL is set? Recommended: separate.
2. **Prompt text off by default** in ClickHouse, which is stricter than Redis
   today? Recommended: off.
3. **Reads when ClickHouse is down:** `503`, or fall back to Redis? Recommended: `503`.
4. **Default retention 90 days** in the shipped DDL, or a year?
5. **One PR** with a commit per task (matches the working preference so far), or a
   PR per task (the CLAUDE.md default)?
