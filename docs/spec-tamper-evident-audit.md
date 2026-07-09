# Spec: Tamper-evident audit trail

Status: **DRAFT — for approval.** Spec-first per `CLAUDE.md`; no code until sign-off.

## 1. Problem & outcome

Shield has three append-only audit stores — `storage/audit_log.py` (Redis ZSET
`audit:{tenant}`), `storage/decision_audit.py` (Redis LIST `decisions:{tenant}`),
`storage/admin_audit.py` (Redis LIST `admin_audit:{tenant}`). They are append-only
**by convention only**: anyone with Redis access (a rogue admin, a compromised
node, a backup-restore) can delete or rewrite entries **undetectably**. There is
no hashing, chaining, or signing today.

Enterprise buyers and SOC2 / EU AI Act Art. 12 / ISO 42001 §9.2 require an audit
trail whose integrity is **provable** — you can show an auditor that no record was
altered or dropped since it was written.

**Outcome:** every audit event is linked into a per-scope **hash chain**, and the
chain head is **signed into periodic checkpoints**. Given the log + checkpoints,
anyone can verify offline that the log is intact, and pinpoint the exact sequence
number where any tampering occurred. A `verify` endpoint and a signed `export`
bundle make this turnkey for auditors.

**Non-goals.** Not confidentiality (that's redaction, already present). Not
preventing deletion (Redis can't) — only making it **detectable**. Not an external
transparency log / WORM anchor in v1 (designed for, deferred). Not backfilling
integrity onto pre-existing records (chain starts at enablement with a signed
genesis).

## 2. Plane & latency contract

- **Guard path impact — the hard constraint.** Audit writes happen on the data
  plane inside guard endpoints (`/guardrails/*`, `tool/check`, `tool/output`).
  Chaining MUST NOT add latency to guarded traffic.
  - Hashing is one `sha256` over a canonical record + `prev_hash` — microseconds.
  - The chain append is done by a **background writer** (bounded async queue); the
    guard response never awaits it. Guard latency budget: **+0 ms** (enqueue only).
- **Admin plane** mounts the read-side: `verify` and `export` endpoints (read-only
  over Redis; off hot path).
- Signing checkpoints is periodic (every N records or T seconds) on a background
  task — not per request.

## 3. Data model

Per **scope** (a scope = `audit:{tenant}`, `decisions:{tenant}`,
`admin_audit:{tenant}`, and the `*:global` variants; token/cap events added — §7):

- Each record gains: `seq` (monotonic int per scope, from a Redis counter),
  `prev_hash` (hex), `record_hash = sha256(canonical_json(record_without_hash) ||
  prev_hash)`.
- `audit:chain:{scope}:head` → `{seq, record_hash}` (the current chain head).
- `audit:chain:{scope}:seq` → Redis INCR counter (monotonic, gap = evidence).
- **Atomicity:** head-read → hash → head-write + record-append run in one **Redis
  Lua script** so concurrent writers can't fork the chain or reuse a `seq`.
- **Checkpoints:** `audit:checkpoint:{scope}` → LIST of signed objects
  `{scope, seq, head_hash, ts, sig, kid}`, `sig` = Ed25519 over
  `canonical_json({scope, seq, head_hash, ts})`. Reuses the existing Ed25519
  signer used by agent tokens / capabilities (`core/agent_tokens.py`,
  `core/capabilities.py`) — **no new key material, no new dep**.
- **Genesis:** on enable, a signed genesis checkpoint at `seq=0`,
  `prev_hash="GENESIS"`.
- **Tenant scoping:** unchanged — chains and checkpoints are per-scope, so tenant
  isolation is inherited from the existing key layout; cross-tenant verify is
  rejected by the existing `_resolve_audit_scope` (`api/routes_audit.py`).
- TTL: checkpoints are **not** TTL'd (tiny, and needed to verify retained
  records); records keep their existing `AUDIT_TTL`. Expiry is legitimate and
  bounded by checkpoint seq ranges, so expired-out records don't read as tamper
  (verify only checks records still present against their covering checkpoints).

## 4. API / interface

Additive endpoints on the **admin plane** (auth: existing tenant/admin key via
`_resolve_audit_scope`):

- `GET /v1/shield/audit/verify?scope=&since=&until=` →
  `{"valid": bool, "checked": int, "break_at_seq": int|null, "reason": str|null,
    "last_checkpoint": {seq, ts}}`. Recomputes the chain over the range and checks
  it against the signed checkpoints + counter continuity.
- `GET /v1/shield/audit/export?scope=&since=&until=` → a signed **verifiable
  bundle**: NDJSON records + covering checkpoints + `kid`/public-key reference, so
  an auditor verifies **offline** with a ~30-line standalone script (shipped).
- Existing `GET /v1/shield/audit` / `/stats` are unchanged (back-compat); the new
  `seq`/`prev_hash`/`record_hash` fields simply appear in entries when enabled.

Write path: a shared helper `append_hashchained(scope, record)` in a new module
`storage/audit_chain.py`, called by the three existing writers (and token/cap
writers, §7) behind the enable flag.

## 5. Security & backward compatibility

- **Opt-in, non-breaking.** Gated by `SHIELD_AUDIT_TAMPER_EVIDENT=1` (default off).
  Off ⇒ writers behave exactly as today (no new fields, no queue, no endpoints
  active). On ⇒ additive fields + endpoints. This satisfies the "secure-by-default
  but non-breaking" invariant via an explicit opt-in flag + migration note
  ("enable in staging, confirm `verify` green, then prod").
- **Threat covered:** silent deletion/alteration of audit records by anyone with
  Redis/backup access. After tampering, `verify` returns `valid:false` with the
  exact `break_at_seq`. A truncation (delete newest N) is caught by counter/head
  mismatch against the latest checkpoint.
- **What it can't do:** stop deletion, or prove integrity for the window between
  the last checkpoint and a crash (bounded by checkpoint interval — tunable).
- **Key handling:** signing key is the existing on-prem Ed25519 signer; public key
  already published at `GET /oauth/jwks` for offline verify. Private key never
  leaves the signer.

## 6. Packaging & deploy

- **New module** `storage/audit_chain.py`. If `admin_app.py` imports it (it will —
  verify/export live on the admin plane) → **add it to `Dockerfile.admin` COPY
  allowlist** (enforced by `tests/test_admin_dockerfile_imports.py`). Flagged
  explicitly.
- **No new pip dependency** — reuses stdlib `hashlib` + the existing Ed25519
  signer already in `requirements.txt`. Redis Lua needs no dep.
- **Env flags:** `SHIELD_AUDIT_TAMPER_EVIDENT` (enable), `SHIELD_AUDIT_CHECKPOINT_N`
  (records per checkpoint, default 100), `SHIELD_AUDIT_CHECKPOINT_SECS` (max
  interval, default 60). Rebuild: data-plane image (writer) + admin image
  (verify/export).

## 7. Failure modes & edge cases

- **Redis down / audit best-effort:** if a write is lost, the counter leaves a gap
  ⇒ would falsely read as tamper. Mitigation: the writer emits a signed **gap
  marker** record when it detects an enqueue drop or Redis error on resume, so
  `verify` distinguishes "known outage gap" from "tamper." Gap markers are
  themselves chained.
- **Queue full (hot-path protection):** bounded queue; on overflow, guard path
  still returns (never blocks), and a gap marker is recorded — availability >
  completeness, made explicit and logged.
- **Concurrent writers:** Lua-script atomic head update ⇒ no forked chains, no
  duplicate `seq`.
- **Enable on a non-empty store:** genesis checkpoint at current tip; older records
  remain unchained and are reported by `verify` as `unchained_before_seq` (honest,
  not a failure).
- **Huge export range:** streamed NDJSON, capped page size; `verify` works on
  ranges.
- **Clock skew:** irrelevant — integrity is `seq`+hash based, not time based (`ts`
  is informational).

## 8. Test plan (Definition of Done)

- **Unit:** chain continuity over N records; modify one record → `verify` fails at
  its `seq`; delete a middle record → fail; truncate newest → fail vs latest
  checkpoint; checkpoint signature verifies with the published key; tamper a
  checkpoint → fail; concurrent appends keep `seq` monotonic and unique (Lua);
  outage gap marker ⇒ `verify` stays `valid`; opt-out (flag off) ⇒ byte-identical
  behavior to today; export bundle verifies with the standalone offline script.
- **Regression guard:** `test_admin_dockerfile_imports.py` covers the new admin
  import; a test pins the canonical-JSON serialization (hash stability across
  py versions).
- **Clean venv:** full `pytest tests -q` green in a fresh venv; CI `pytest` gate
  passes.

## Invariant risk flags
- ⚠️ **Hot path** — mitigated: enqueue-only on the guard path, all hashing/signing
  off-response; budget +0 ms. Must be load-verified.
- ⚠️ **Admin import** — `storage/audit_chain.py` → add to `Dockerfile.admin`.
- ✅ No new pip dep (reuse Ed25519 signer + hashlib).
- ✅ Opt-in flag, default off, migration note.

## Task breakdown (one branch, ordered)
1. `storage/audit_chain.py` — `append_hashchained` (Lua atomic), checkpointer,
   verify/export core + unit tests (Redis mocked/fakeredis). Flag-gated.
2. Wire the three existing writers + token/cap events to it behind the flag.
3. Admin endpoints `verify` / `export` + `Dockerfile.admin` COPY + offline
   verifier script + docs.

## Open questions (for approval)
1. **Checkpoint cadence default** — 100 records / 60 s ok, or tighter for
   higher-assurance tenants?
2. **External anchor** — v1 keeps checkpoints in Redis. Want a v2 hook to also push
   checkpoints to S3-WORM / a public transparency log for off-box durability?
3. **Coverage** — include the currently-unaudited token/cap mint/verify events in
   this same chained log now (recommended), or keep v1 to the three existing
   stores?
