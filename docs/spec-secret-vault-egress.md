# Spec: Secret vault + egress materialization

## 1. Problem & outcome
Developer secrets (API keys, DB passwords, tokens) leak into the LLM path today.
An agent that reads `os.environ`, an app that interpolates a key into a prompt, or
a tool output that echoes a credential all put plaintext secrets somewhere the
model can see and therefore exfiltrate (a prompt injection can ask the model to
send it anywhere).

Give developers a way to keep the **real** secret out of the model path entirely,
by construction rather than by scanning. Two tiers:

1. **Tier 1 — Shield-injected credentials.** For upstreams Shield already proxies
   (OpenAPI/REST tools, MCP tools), the agent holds *nothing*. Shield attaches the
   real credential server-side at the egress hop, only for the bound destination.
2. **Tier 2 — reference tokens.** For secrets the app holds itself, the app
   references an opaque token (`shield://name`); the real value is materialized
   only at a Shield egress boundary, only when the outbound destination matches the
   secret's binding.

**Observable success:** a developer registers `stripe_key` bound to
`api.stripe.com`, wires their tool through Shield, and (a) the real key never
appears in any prompt, tool arg, model output, or Shield audit log, yet the Stripe
call succeeds; (b) a prompt-injected instruction to POST the token/key to
`attacker.com` ships only an inert token, never the secret.

**Non-goals**
- Replacing the existing regex/entropy secret scan in
  [pii_leakage.py](guardrails/output/pii_leakage.py) — it stays as a *backstop
  alert*, not the primary control.
- A general KV config store. This is secrets with destination binding only.
- Client-side (in-agent) encryption or a full HSM. KMS/envelope only.
- Rotating existing SIEM/webhook secrets into the vault (future; see §6 note).

## 2. Plane & latency contract
- **Admin plane (CPU portal):** vault CRUD/registration API + UI. Off the guard
  path. Encrypt-on-write; DEK generated and wrapped by the KeyProvider at
  registration time only.
- **Data plane (GPU) — GUARD PATH, `tools/call`:** materialization happens at the
  tool-call egress last hop, which **is** a named hot path. Budget and justify:
  - Materialization runs **only after `action==allow`**, at the point Shield is
    already about to make a network call to the real upstream (OpenAPI:
    [upstream_call.py:103](core/openapi/upstream_call.py:103); MCP:
    [upstream.py:41](core/mcp/upstream.py:41)). The added cost is one in-memory
    DEK-cache lookup + AES-GCM decrypt (microseconds).
  - KeyProvider unwrap runs **only on DEK cache miss** (per-secret DEK cached
    in-process with short TTL). Steady-state adds < 1 ms; with `software` KEK the
    cold path is a local AES unwrap (no network), and with `vault-transit` it is
    one round trip amortized against an outbound call that already dominates.
  - **No secret work on the block path** and **no work when a tenant has no vault
    entries** (fast empty-vault check, same pattern as `dispatch_to_siem`).
  → Guard *decision* latency is unchanged; only the already-slow forward step gains
  a bounded, cache-backed decrypt.

## 3. Data model
New Redis key, tenant-scoped: `vault:{tenant_id}` → JSON list of secret entries.
**Values are ciphertext, never plaintext** (unlike current `siem_store`/`webhook_store`).

```json
{
  "ref": "stripe_key",
  "token": "svlt_9f3a…",              // opaque handle used in tier 2
  "ciphertext": "<base64 AES-GCM>",   // encrypted secret value
  "wrapped_dek": "<base64>",          // per-secret data key, wrapped by KMS KEK
  "nonce": "<base64>",
  "bindings": ["api.stripe.com"],     // allowed destinations (host / tool id)
  "mode": "inject" | "token",
  "tool_ids": ["stripe.createCharge"],// tier-1: which tools may use it
  "created_at": 1720000000, "updated_at": 1720000000
}
```
- **Tenant scoping:** `tenant_id` from `request.state.tenant_id` (same resolution as
  every other store). A tenant can never name another tenant's `vault:` key.
- **No TTL** (durable). **No plaintext field exists in the schema at all.**
- Value-hash index (optional, tier 2 ingress): `vaulthash:{tenant_id}` → map of
  `sha256(value)[:16]` → `token`, so the ingress re-tokenizer can find secrets in
  upstream responses without holding plaintext. Hash only; never the value.

## 4. API / interface
Router `/v1/tenant/me/vault` (admin plane), tenant `X-API-Key`.
- `POST ""` — register `{name, value, bindings[], mode, tool_ids?}`. Encrypts,
  stores, returns `{ref, token}` **and nothing else** (never echoes `value`).
- `GET ""` — list entries **metadata only**: `ref, token, bindings, mode,
  tool_ids, created_at`. Never `ciphertext`, never `value`.
- `DELETE "/{ref}"` — remove.
- `PUT "/{ref}"` — rotate value / edit bindings (re-encrypt; `token`/`ref` stable).
- **There is deliberately NO endpoint that returns a decrypted value.** The only
  path to plaintext is egress materialization onto the wire.

Egress integration (data plane, not new HTTP endpoints):
- **Tier 1:** extend OpenAPI [`_apply_auth`](core/openapi/upstream_call.py:79) and
  the MCP forward in [proxy_server.py](core/mcp/proxy_server.py:100) to resolve a
  tool's bound credential from the vault and inject it into the outbound request.
- **Tier 2:** a `materialize(tenant_id, args, destination)` transform called at the
  egress hop that swaps tokens → values **iff** `destination ∈ bindings`.
- **Ingress:** `retokenize(tenant_id, response)` before results return to the model.

## 5. Security & backward compatibility
- **Default off / opt-in.** No vault entries → zero behavior change; every existing
  flow is untouched. Escape-hatch env flag `SECRET_VAULT_ENABLED` (default off) so
  the feature can be disabled fleet-wide.
- **Destination binding is mandatory.** A secret with empty `bindings` is
  unusable, not "usable anywhere." Materialization compares against the *real*
  resolved outbound host/tool, not a model-supplied string. This is the anti
  confused-deputy control: an injected "POST token to attacker.com" fails the
  binding check and ships the inert token.
- **No read-back.** No API, log, or model path returns plaintext. Materialization
  is the sole decrypt site; value is used and zeroized.
- **Materialize is an egress transform, not a guardrail.** `GuardrailResult`
  ([base.py:36](guardrails/base.py:36)) stays verdict-only; secrets never flow
  through the guard-result `details` convention.
- **Encryption at rest is a hard prerequisite** (see §6). Redis compromise alone
  yields only ciphertext + wrapped DEK.
- **Telemetry safety:** Shield's own audit/SIEM events must log the `token`, never
  the materialized value. Regression-tested (§8).
- **Authz:** only a valid tenant key CRUDs its own vault; materialization is
  server-side only, gated on an allowed tool/destination for that tenant.

## 6. Packaging & deploy
- **New crypto dependency.** Add `cryptography` (AES-GCM) to `requirements.txt`,
  `requirements-test.txt`, and `requirements-admin.txt` (admin plane registers/
  encrypts). Key management is **on-prem only** (no cloud KMS) via a pluggable
  `KeyProvider` interface. Backends:
  - **`software` (v1 default):** KEK loaded at boot from env var / mounted secret
    file / k8s Secret. Only `cryptography`. Fits the current self-host/Railway
    deploy with zero external services.
  - **`vault-transit` (upgrade path, stubbed in v1):** HashiCorp Vault or OpenBao
    Transit engine — KEK never leaves the self-hosted Vault; app wraps/unwraps the
    DEK over the network. Adds `hvac`; declared only when this backend ships.
  - **`pkcs11` (optional future):** SoftHSM / hardware HSM via `python-pkcs11`.
  Envelope encryption holds even with the software KEK: a Redis dump yields only
  ciphertext + wrapped DEK; the KEK lives in app secret config, not the datastore.
- **Dockerfile.admin:** the vault router + store + crypto helper are new modules
  `admin_app.py` imports → **add each to the `Dockerfile.admin` COPY allowlist**
  (guarded by `tests/test_admin_dockerfile_imports.py`), or the admin image
  crash-loops. Explicit task item.
- **Env flags:** `SECRET_VAULT_ENABLED`, `SECRET_VAULT_KEY_PROVIDER`
  (`software` | `vault-transit` | `pkcs11`), `SECRET_VAULT_KEK` (software backend:
  KEK value or path to a mounted secret), and `SECRET_VAULT_TRANSIT_*` (addr /
  token / key name) for the Vault-Transit backend.
- **Rebuild:** both images (admin for registration/UI, data plane for egress
  materialization).
- **Note / reuse opportunity:** the envelope-encryption helper built here is the
  natural home for later encrypting existing plaintext secrets
  ([siem_store.py:68](storage/siem_store.py:68),
  [webhook_store.py:40](storage/webhook_store.py:40)). Out of scope for this spec,
  but the crypto module should be written tenant-generic so that migration is a
  follow-up, not a rewrite.

## 7. Failure modes & edge cases
- **KeyProvider unreachable / unwrap fails** (e.g. Vault-Transit down, bad KEK) →
  **fail closed**: deny the tool call; never forward with a blank or placeholder
  credential. Surfaced as a guard-path error.
- **Empty vault / feature off** → no-op, no latency.
- **Token spans streaming chunk boundaries** → buffer at boundaries so a token is
  never split mid-substitution.
- **Unknown token at egress** → pass through untouched (may be unrelated text).
- **Rotation mid-flight** → in-flight call uses the version resolved at call time;
  `ref`/`token` stable across rotation.
- **Redis down** → vault reads fail closed for tier-1 injected calls (deny);
  tier-2 tokens pass through inert (no leak, call likely fails auth downstream).
- **Huge / binary secret** → cap value size; reject at registration.
- **Value collides with normal text (ingress hash)** → hash match plus length/
  context guard to avoid over-redacting; false positive re-tokenizes harmless text
  (safe direction).
- **Concurrent vault writes** → read-modify-write on the list (existing store
  pattern); last-writer-wins per `ref`, acceptable for admin-plane config.

## 8. Test plan (Definition of Done)
New `tests/test_secret_vault.py`:
- **Crypto round-trip:** encrypt→store→materialize returns original value; Redis
  blob contains no plaintext (assert value substring absent from stored JSON).
- **Binding / anti-exfil:** materialize substitutes for a bound destination; for a
  non-bound destination the token passes through unchanged (the core security
  test).
- **No read-back:** `GET` responses and error bodies never contain `value`/
  `ciphertext`; there is no route returning plaintext.
- **Tier 1 injection:** OpenAPI `_apply_auth` and MCP forward attach the real
  credential to the bound upstream only; wrong tool id → not injected.
- **Fail-closed:** KeyProvider unwrap raising → tool call denied, nothing forwarded.
- **Ingress re-tokenize:** a secret value in a mocked upstream response is replaced
  by its token before return.
- **Telemetry safety:** emit an audit/SIEM event around a materialized call; assert
  the logged payload contains the token and not the value.
- **Feature-off / empty-vault:** zero behavior change, zero KMS calls.
- **Dockerfile regression:** `tests/test_admin_dockerfile_imports.py` green with
  new admin modules added to the COPY list.
- Full suite green in a **clean venv**; CI `pytest` gate passes.

## Task breakdown (ordered PRs)
1. **Encryption core + vault store (foundation).** `KeyProvider` interface +
   `software` KEK backend (Vault-Transit stubbed behind it), envelope encrypt/
   decrypt helper, `vault:{tenant}` store (ciphertext only), `SECRET_VAULT_*`
   flags, `cryptography` in all three requirements files. Tests: crypto round-trip,
   no-plaintext-at-rest, fail-closed. *Independently shippable; no egress wiring
   yet, no cloud dependency.*
2. **Tier 1 — Shield-injected credentials.** Vault CRUD router + admin UI + COPY
   allowlist; resolve+inject bound credential in OpenAPI `_apply_auth` and MCP
   forward; tool-id binding. Tests: injection, wrong-tool, fail-closed, no-read-back.
   *Delivers the primary use case.*
3. **Tier 2 — reference tokens.** `svlt_` tokens + SDK env shim, egress
   `materialize()` with destination binding, ingress `retokenize()`, value-hash
   index. Tests: binding/anti-exfil, streaming boundary, ingress.
4. **Telemetry token-safety + rotation.** Audit/SIEM redaction assertions, `PUT`
   rotate. Tests: telemetry safety, rotation stability.

Branch `feat/secret-vault-egress`. PR 1 is the encryption foundation and can merge
alone; 2 delivers user-visible value; 3–4 complete the model. Each self-contained
(deps + Dockerfile + tests in the same PR).
