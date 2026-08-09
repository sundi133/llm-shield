# Spec: AIBOM runtime attestation (k8s-aibom interop)

## 1. Problem & outcome

`GoogleCloudPlatform/k8s-aibom` emits CycloneDX 1.6 ML-BOM documents for AI
workloads by observing the Kubernetes API. It tags every attribute with a
confidence level: `declared` (the customer wrote it in a pod spec or the
`model.k8saibom.dev/name` annotation), `inferred` (a heuristic, e.g. matching an
image against `^vllm/.*`), or `unresolved`. A fourth level, `verified`
(Sigstore/Rekor), is v1.1 roadmap and is currently a `NoopVerifier`.

A K8s-API observer cannot see what actually executed. Their own v2 roadmap
concedes this: it proposes "an eBPF-based scraper for in-container model load
events, egress destination capture, runtime version verification."

Shield is already in the request path and already receives, Ed25519-verified on
every request, the two claims an ML-BOM most needs — `model_version` and
`build_hash` (`core/agent_tokens.py:262`). They are validated and then
discarded. Nothing persists them.

**Outcome:** a tenant can retrieve a CycloneDX 1.6 document describing what their
AI system *actually ran*, and can reconcile it against a k8s-aibom document to
see drift between declared and observed. Observable success: for a tenant whose
agents have called through Shield, `GET /v1/tenant/me/aibom` returns a
schema-valid CycloneDX 1.6 BOM whose model components carry
`confidence: verified` sourced from signed token claims, and
`POST /v1/tenant/me/aibom/reconcile` returns the set of components present in
one document but not the other.

**Non-goals** (all structural — Shield is an inference-path proxy and cannot see
these; k8s-aibom covers them and we should say so rather than compete):
- Training / fine-tuning jobs, mounted datasets, W&B or HF Hub telemetry.
- Vector stores and RAG corpora. Shield has no retrieval layer (confirmed: no
  vector/embedding/dataset concept anywhere in the repo).
- Inference serving runtime and container image digests — infrastructure layer.
- Evaluation harnesses.
- SPDX 3.0 output. Match k8s-aibom's current CycloneDX 1.6 first; they slate
  SPDX for v2.
- Replacing k8s-aibom. This produces an overlay that merges with theirs.

## 2. Plane & latency contract

**Two planes, meeting in Redis — no cross-plane HTTP.**

- **Data plane (`core/app.py`)** — *observation only*. Records what it already
  has in hand during request handling.
- **Admin plane (`admin_app.py`)** — *emission and reconciliation*. Reads Redis,
  serializes CycloneDX. This is where `routes_evidence` and `routes_board_report`
  already live, so the export surface stays consistent.

**Touches the guard path: YES, on the observation side.** `verify_agent_token`
is called from `AgentIdentityMiddleware` on every request, so this is the
hottest path in the system. Mitigation, and it is the whole design:

- **`core/agent_tokens.py` is not modified.** The hook goes in the middleware
  where the verified `IdentityTuple` is already in hand, so verification itself
  is untouched.
- **Zero I/O on the request path.** Observation appends to an in-process dict
  under a lock and returns. This is the pattern already proven by shadow-agent
  detection (`core/middleware.py:75-190`): buffer in memory, flush to Redis on
  an interval from a daemon thread.
- **Deduplicated in memory.** The buffer is keyed by
  `(tenant_id, agent_id, model_version, build_hash)`, a tuple that changes only
  on deploy — so a million requests produce a handful of entries and the
  hot-path cost is one dict lookup plus a timestamp write.

**Latency budget:** p50 delta < 0.1 ms, p99 < 0.5 ms. No Redis, no LLM, no
network. Task 4 measures rather than asserts.

**Emission is off the hot path entirely** — admin plane, read-only, no writes to
any guard-path key.

## 3. Data model

New Redis key, per tenant:

| Key | Type | Value | TTL |
|---|---|---|---|
| `aibom:observed:{tenant_id}` | hash | field = `sha256(component_type\|name\|version)[:16]`, value = JSON below | none (see retention) |

Value shape:

```jsonc
{
  "type": "machine-learning-model" | "application" | "service",
  "name": "claude-opus-4-8",
  "version": "<model_version or build_hash claim>",
  "confidence": "verified" | "observed",
  "source": "agent_token_claim" | "mcp_registry" | "tool_invocation",
  "first_seen": 1752900000,
  "last_seen":  1752986400,
  "observations": 41234,
  "agent_ids": ["billing-agent"]        // capped at 20, for attribution
}
```

**Retention.** Entries older than `SHIELD_AIBOM_RETENTION_DAYS` (default 90) are
dropped at flush time, not by Redis TTL — a per-field TTL is not available on a
hash, and we want `first_seen` to survive as long as the component is live.
Hash is capped at 5 000 fields per tenant; on overflow the oldest `last_seen`
entries are evicted and a `aibom_inventory_truncated` metric is recorded, so the
document never silently claims completeness it does not have.

**Tenant scoping.** `tenant_id` comes from the verified token claim
(`core/agent_tokens.py:262` lists it as required), not from a header. The key is
tenant-prefixed, so cross-tenant read requires the existing
`_require_tenant()` bypass, not a new one.

**No existing key is modified.** Nothing here writes to a guard-path key.

## 4. API / interface

Both endpoints on the **admin plane**, tenant `X-API-Key` auth via the existing
`_require_tenant()` (`api/routes_tenant_self.py:110`).

### `GET /v1/tenant/me/aibom`

Query: `format=cyclonedx` (default; only value in v1), `since=<ISO date>`.

Returns a CycloneDX 1.6 document assembled from:

| Component | Source | `confidence` |
|---|---|---|
| Models | `aibom:observed:{tenant}` ← token claims | `verified` |
| Agents (registered) | `agents:{tenant}` | `declared` |
| Agents (shadow) | `unregistered:{tenant}` | `observed` |
| MCP upstream servers | `mcp_gateway:upstream:{tenant}:{route}` | `declared` |
| Tools invoked | governance activity index | `observed` |
| OpenAPI-imported tools | existing per-tenant store | `declared` |

Confidence rides as a CycloneDX `property`, namespaced to match k8s-aibom's
convention:

```jsonc
{
  "type": "machine-learning-model",
  "name": "claude-opus-4-8",
  "version": "20260101",
  "properties": [
    {"name": "aibom:confidence", "value": "verified"},
    {"name": "shield:source", "value": "agent_token_claim"},
    {"name": "shield:first_seen", "value": "2026-05-01T00:00:00Z"},
    {"name": "shield:observations", "value": "41234"}
  ]
}
```

Response carries `Content-Disposition: attachment; filename="aibom-{tenant}-{date}.json"`
and `X-Shield-Pack-Id: <sha256 of the canonical document>`. This closes a gap in
the existing evidence pack, which returns inline HTML/dict with the filename
synthesized only in portal JavaScript (`static/tenant.html:11314`) — useless to
a CI job or an auditor's script.

### `POST /v1/tenant/me/aibom/reconcile`

Body: a k8s-aibom (or any CycloneDX 1.6) document. Returns:

```jsonc
{
  "declared_only": [...],   // in their BOM, never observed by Shield
  "observed_only": [...],   // Shield saw it, their BOM does not list it
  "both": [...],            // matched, with confidence upgraded to Shield's
  "merged": { /* CycloneDX 1.6 */ }
}
```

`observed_only` is the finding customers care about: shadow models and
unregistered MCP servers running in production that no manifest declares.

Component matching is by `(type, name)` with version compared separately, so a
version drift surfaces in `both` with a `shield:version_mismatch` property rather
than appearing as two unrelated components.

**Not** an ingestion endpoint: the posted document is processed in-request and
never stored. That keeps it read-only with respect to tenant state.

## 5. Security & backward compatibility

**Default behaviour: additive, opt-out.** Observation is on by default (it is a
dict write, and an inventory that only some tenants have is not an inventory),
with `SHIELD_AIBOM_OBSERVE=0` as the escape hatch. No existing endpoint or key
changes shape. No default guard behaviour changes.

**Authz.** Both endpoints require a tenant API key and return only that tenant's
data. Nothing here grants a capability that `GET /v1/governance/agents` does not
already grant.

**BLOCKER — resolve before this ships.** `get_tenant_from_api_key`
(`api/routes_agents_registry.py:124`) auto-provisions a tenant for any key
prefixed `sk-test-`, and it is the auth path for all of `/v1/governance/*`,
which is a data source here. If that branch is reachable in a deployed
environment, agent inventory including shadow agents is retrievable without a
real tenant key — and this spec would turn that into a signed compliance
artifact. Confirm it is env-gated, or gate it, before Task 3.

**A signed artifact must not overclaim.** The document always carries
`shield:completeness` = `full` or `truncated`, and `shield:window` naming the
observation period. Two known sources of incompleteness, both documented in the
output rather than hidden: the shadow buffer is in-memory and flushed on an
interval, so sightings are lost on crash (`core/middleware.py:143-152`); and the
governance activity index is a bounded recent-events buffer. Given the recurring
theme in this repo — controls that report success while inert — the document
stating what it does not know is a requirement, not a nicety.

**Untrusted input.** `/reconcile` accepts a caller-supplied JSON document. It is
parsed, size-capped at 10 MB, never executed, never stored, and never used to
construct a Redis key. Component names are treated as opaque strings and are not
interpolated into any query.

## 6. Packaging & deploy

- **New modules:** `storage/aibom.py` (buffer, flush, read), `core/cyclonedx.py`
  (serializer).
- **`Dockerfile.admin` — HARD REQUIREMENT.** `admin_app.py` will import
  `api/routes_aibom.py`, `storage/aibom.py`, and `core/cyclonedx.py`. All three
  MUST be added to the per-file COPY allowlist in the *same PR*, or the admin
  image crash-loops at boot. `tests/test_admin_dockerfile_imports.py` enforces
  this; make sure it actually covers the new modules.
- **New pip deps: none.** CycloneDX 1.6 is emitted as a plain dict serialized
  with `json`, matching how `storage/evidence_pack.py` hand-rolls HTML with no
  dependency. A `cyclonedx-python-lib` runtime dep is not worth the packaging
  cost for a document we only write. Schema validation happens in tests against
  a vendored copy of the 1.6 schema; if that needs `jsonschema`, it goes in
  `requirements-test.txt` only.
- **Env flags:** `SHIELD_AIBOM_OBSERVE` (default `1`),
  `SHIELD_AIBOM_RETENTION_DAYS` (default `90`),
  `SHIELD_AIBOM_FLUSH_INTERVAL` (default `60`).
- **Images to rebuild:** both. Data plane for observation, admin for emission.

## 7. Failure modes & edge cases

| Case | Behaviour | Open / closed |
|---|---|---|
| Redis down at flush | Buffer retained up to a 10 000-entry cap, then oldest dropped; a warning is logged once per interval. Never raises into the request path. | Fail-open — this is telemetry, and a BOM writer must never break traffic |
| Redis down at emission | 503 with an explicit reason. Never a partial document presented as complete. | Fail-closed — a compliance artifact must not silently omit |
| No observations yet | 200 with a valid BOM containing zero model components and `shield:completeness: no_observations`. Not a 404: "nothing ran" is a real answer. | n/a |
| mTLS caller | `build_hash="mtls"`, `model_version="n/a"` are middleware placeholders (`core/agent_identity_middleware.py:38-39`). Skipped, not recorded as a model named "n/a". | Closed |
| Claim is absent or empty | Skipped. Never emit a component with an empty name or version. | Closed |
| Claim is absurdly long / non-ASCII | Truncated at 256 chars; rejected if it fails `^[\w.:/+-]{1,256}$`. Bounds the hash field count and keeps names JSON-safe. | Closed |
| Tenant exceeds 5 000 components | Evict oldest by `last_seen`, set `shield:completeness: truncated`, record a metric. | Closed |
| `/reconcile` given malformed JSON, wrong `bomFormat`, or wrong `specVersion` | 400 naming the problem. Never a partial merge. | Closed |
| `/reconcile` given a 500 MB document | 413 at 10 MB. | Closed |
| Concurrent flush and read | Flush writes with `HSET` per field; a read may see a document mid-flush. Acceptable — `last_seen` is monotonic and the window is one interval. Documented, not locked. | n/a |
| Two agents, same model, different build | Distinct components; `agent_ids` attributes both. | n/a |

## 8. Test plan (Definition of Done)

**Observation (hot path)**
- A verified token's `model_version` / `build_hash` reach the buffer
- The buffer dedupes: 1 000 identical requests produce one entry with
  `observations == 1000`
- **No Redis call occurs during request handling** (assert with a mock that
  raises if touched) — this is the hot-path contract
- `SHIELD_AIBOM_OBSERVE=0` records nothing
- mTLS placeholders (`"mtls"` / `"n/a"`) are not recorded
- Malformed, empty, overlong, and non-matching claims are rejected
- Redis down at flush does not raise into the request path

**Emission**
- Output validates against the vendored CycloneDX 1.6 schema
- `specVersion` is exactly `1.6` (must merge with k8s-aibom output)
- Model components carry `aibom:confidence: verified`; shadow agents `observed`;
  registry entries `declared`
- `Content-Disposition` and `X-Shield-Pack-Id` are present; the pack ID is stable
  for identical content and changes when content changes
- Empty tenant yields a valid BOM, not a 404
- Truncation sets `shield:completeness: truncated`
- Cross-tenant: tenant A's key never returns tenant B's components

**Reconcile**
- A component in theirs but not ours lands in `declared_only`, and vice versa
- Matching components merge with Shield's confidence winning over `inferred`
- Version mismatch appears in `both` with `shield:version_mismatch`
- Malformed / wrong-format / oversized documents are rejected with the right code
- A real k8s-aibom sample document (vendored as a fixture) reconciles cleanly

**Packaging (drift-prone coupling)**
- `tests/test_admin_dockerfile_imports.py` fails if any of the three new modules
  is missing from `Dockerfile.admin`

**Gates:** full suite green in a clean venv; CI `pytest` passes.

## 9. Task breakdown (one PR each, in order)

| # | Task | Why separate |
|---|---|---|
| 1 | `storage/aibom.py`: in-memory buffer + interval flush, hooked in `core/middleware.py` alongside shadow detection. No endpoint yet. | The only hot-path change. Small, independently reviewable, and independently revertable. Delivers value alone: the claims stop being discarded. |
| 2 | `core/cyclonedx.py` serializer + `GET /v1/tenant/me/aibom`, with the `Dockerfile.admin` COPY additions **in the same PR**. | Pure read path. Cannot ship without the Dockerfile change (repo invariant). |
| 3 | `POST /v1/tenant/me/aibom/reconcile` | The interop payoff, and the part with untrusted input. Deserves its own review. |
| 4 | Portal button beside the existing evidence-pack exports (`static/tenant.html:4346`); hot-path benchmark. | UI + the measurement backing §2. |

Task 1 is the one worth doing even if the rest is deferred: it is the difference
between emitting `verified` where k8s-aibom emits `inferred`, and having no model
component at all.

**Prerequisite:** resolve the `sk-test-` auto-provisioning question in §5 before
Task 3.
