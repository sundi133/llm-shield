---
title: "Spec: Certificate-based agent identity that enterprises can rely on"
layout: default
nav_exclude: true
permalink: /specs/agent-cert-identity/
description: Make certificate-based agent identity mean what it says. Headers that carry a certificate are honored only from the proxy that did the TLS handshake, identity is anchored in the tenant's own CA rather than in pinned fingerprints, certificates are checked for validity and can rotate, and an agent can be required to prove itself.
---

# Spec: Certificate-based agent identity that enterprises can rely on

> Status: **DRAFT, awaiting approval.** Branch `spec/agent-cert-identity`.
> Related: `docs/spec-modular-workload-identity.md`, `docs/spec-agent-token-pop.md`,
> `docs/AGENT_AUTH_ARCHITECTURE.md`, `core/proxy_trust.py`, `core/oauth/spiffe.py`.
> A narrower fix (task 1 below, on its own) was started separately as task
> `task_d4a83662`; this spec contains it and goes further. Keep one.

## 1. Problem & outcome

Shield offers three ways for an agent to be identified by an X.509 client
certificate. Each derives identity from a request header, and a header is not
proof that the sender holds the certificate's private key:

| Path | Header | Proxy boundary | What a caller can do today |
|---|---|---|---|
| Fingerprint, guard path (`core/middleware.py`, `SHIELD_ENABLE_CERT_IDENTITY`) | `X-Client-Cert-Fingerprint` | **None** | Send any registered agent's fingerprint (it is a hash of the **public** cert) and be recorded as that agent with `identity_method: cert`, `trust_level: high` |
| Fingerprint via mTLS (`core/mtls_middleware.py`, `SHIELD_MTLS_ENABLED`) | `X-Client-Cert-Fingerprint` or the cert in `X-Forwarded-Client-Cert` | Only when `SHIELD_TRUSTED_PROXY_ONLY` is on; otherwise a warning | Same, when the boundary is off |
| SPIFFE (`core/oauth/spiffe_middleware.py`, `SHIELD_SPIFFE_ENABLED`) | `X-Client-Cert` / `X-Forwarded-Client-Cert` | Only when `SHIELD_TRUSTED_PROXY_ONLY` is on | Replay a captured SVID: the chain check proves the cert is CA-issued, not that the sender holds its key |

And the fingerprint feature itself has gaps an enterprise review will find:

1. **The portal tells customers to do the spoofable thing.** Agent Identity,
   step 3: the agent sends `X-Client-Cert-Fingerprint` on every call.
2. **Formats never match.** The portal's example registers
   `AB:CD:12:...` (OpenSSL's output); `core/mtls_middleware.py` computes
   lowercase hex without colons; `cert_registry` normalizes neither. A customer
   who follows the portal and then sets up real mTLS is silently not
   recognized, while the spoofable path matches.
3. **Pinned fingerprints do not scale.** Every renewal is a new fingerprint to
   register; nothing records or checks expiry; revocation is manual and only
   per agent; short-lived certificates (SPIFFE SVIDs live about an hour) are
   impossible to pin.
4. **No way to require it.** An agent bound to a certificate can still be
   claimed with a plain `X-Agent-Key` header; certificate identity only adds a
   label.
5. **The portal overstates it.** "Higher trust = more permissive guardrails":
   no guardrail reads `trust_level`.

**What is not broken.** Authorization (`cap/mint`, RBAC,
`core/identity_resolution.resolve_identity`) uses verified identities: a
signed agent token, or proxy-gated mTLS/SPIFFE. The spoofable path changes
`request.state.agent_key` (which `X-Agent-Key` can already assert) and the
audit labels. So today's impact is **false attribution in audit and
telemetry**, not an access bypass. Task 4 is what turns certificate identity
into an enforced control.

**Outcome.** A certificate identity in Shield means: a proxy performed a TLS
handshake in which the agent proved possession of a private key, for a
certificate that chains to an anchor the tenant trusts, is within its
validity period, is not revoked or pinned-out, and maps to exactly one
registered agent. Anything less is not labeled `cert`.

**Non-goals.**
- Terminating TLS in Shield itself. The proxy (Envoy, nginx, a cloud load
  balancer) does the handshake; Shield verifies what the proxy forwards.
- OCSP. Revocation is by short-lived certificates, per-fingerprint revoke, and
  (task 5) CRLs.
- Making `trust_level` drive guardrail strictness. If wanted, its own spec.
- Changing agent tokens or DPoP (`SHIELD_AGENT_TOKEN_POP`), which already
  provide proof of possession without a proxy.

## 2. Plane & latency contract

- **Data plane, guard path**: the three middlewares above run on guarded
  requests. Budget: **under 0.2 ms added** for a certificate seen before (an
  in-process cache hit), **under 2 ms** the first time a certificate is seen
  (chain verification: a few signature checks). The cache is keyed by the
  certificate's SHA-256, bounded (10,000 entries per process, LRU), and an
  entry lives until the earlier of 5 minutes or the certificate's `notAfter`,
  so a revoke takes effect within 5 minutes everywhere and at once on the
  worker that handled it.
- Requests with no certificate header pay one header lookup, as today.
- **Admin plane**: the anchor, rule and certificate management routes and the
  portal page. Off the guard path.

## 3. Data model

All keys tenant-scoped by `{tenant_id}` in the key name.

| Key | Shape | Notes |
|---|---|---|
| `cert_registry:{tenant}` | HASH normalized fingerprint → JSON `{agent_key, registered_at, registered_by, not_after?, subject?, sans?}` | Today: fingerprint → plain agent key string. Both shapes are read; writes use the new one. Several fingerprints may map to one agent (rotation overlap) |
| `cert_anchors:{tenant}` | JSON list of `{id, name, pem, not_after, added_by, added_at}` | The tenant's CA certificates (root or intermediate). At most 20, each at most 64 KB |
| `cert_rules:{tenant}` | JSON list of `{id, match: "san_uri" \| "san_dns" \| "subject_cn", pattern, agent_id}` | Map a validated certificate to an agent. `pattern` is an exact value or one `{agent_id}` placeholder, for example `spiffe://acme.com/agent/{agent_id}`. First match wins |
| `agents:{tenant}` → agent record | new optional `identity.require`: `"any"` (default) \| `"cert"` \| `"token"` \| `"cert_or_token"` | Task 4 |
| `cert_crls:{tenant}` | JSON `{anchor_id: {pem, next_update}}` | Task 5 |

**Normalized fingerprint**: lowercase hex of SHA-256 over the DER
certificate, no separators. Input accepted as `AB:CD:...`, `ab cd ...`,
`SHA256:AB:CD...` or plain hex; anything that is not 64 hex digits after
normalization is refused.

## 4. API / interface

**Trust boundary (task 1), all three middlewares:**
- A certificate header is honored **only** when `SHIELD_TRUSTED_PROXY_ONLY` is
  on and `core/proxy_trust.peer_is_trusted(request)` is true (the proxy's
  `X-Shield-Proxy-Token` secret; IP lists only as an extra constraint). That is
  one function, called by all three, instead of three implementations.
- With the boundary off, certificate headers are **ignored**, not trusted with
  a warning. Escape hatch for development: `SHIELD_CERT_HEADER_UNGUARDED=allow`,
  logged loudly at start-up and on the portal's Agent Identity page.
- The proxy must overwrite, not append, the certificate headers it forwards
  (Envoy `forward_client_cert_details: SANITIZE_SET`; nginx
  `proxy_set_header X-Forwarded-Client-Cert $ssl_client_escaped_cert`). The
  runbook gives both configurations.

**Fingerprint registration (task 2)**, existing routes extended:
- `POST /v1/shield/agent/identity/register`: `{agent_key, fingerprint}` as
  today, **or** `{agent_key, cert_pem}` (preferred: Shield computes the
  fingerprint and records `not_after`, subject and SANs). Normalized on write.
  Adding a second fingerprint to an agent keeps the first (rotation).
- `POST /v1/shield/agent/identity/revoke`: `{agent_key}` revokes all, as today;
  `{agent_key, fingerprint}` revokes one.
- `GET /v1/tenant/me/agent-identity/certs`: every registered certificate with
  agent, `not_after`, days left, last seen, and how it was last verified
  (`mtls`, `spiffe`), paged like the device list.

**Anchors and rules (task 3), admin plane, registry write gate:**
- `GET/POST/DELETE /v1/tenant/me/agent-identity/anchors`: upload a CA
  certificate (PEM). Refused if it is not a CA certificate (`basicConstraints
  CA:TRUE`), is expired, or uses a weak key (RSA < 2048, or SHA-1 signature).
- `GET/PUT /v1/tenant/me/agent-identity/rules`: the mapping rules, validated:
  every `agent_id` a rule names, or the `{agent_id}` it captures, must be a
  registered agent at match time.
- `POST /v1/tenant/me/agent-identity/test`: `{cert_pem}` → which anchor it
  chains to, which rule matches, the resulting agent, or why not. For
  setting up rules without sending traffic.

Verification of a forwarded certificate, in order:
1. Trust boundary passed (task 1).
2. A pinned fingerprint matches → that agent (still checked for `not_after`
   when known).
3. Otherwise, the chain verifies to one of the tenant's anchors (signature of
   each link, validity windows, `CA:TRUE` on issuers, `clientAuth` extended
   key usage on the leaf when present), it is not revoked (task 5), and a rule
   maps it to a registered agent → that agent.
4. Otherwise no certificate identity; the request continues as it would with
   no certificate (string key or anonymous).
Chain validation reuses the verified-issuer logic in `core/oauth/spiffe.py`
(`verify_directly_issued_by` per link), generalized from SPIFFE to any
X.509 client certificate.

**Requiring it (task 4):** agent record `identity.require`. On the guard path,
a request that claims an agent (by `X-Agent-Key`, body field or certificate)
whose policy requires `cert` and carries no verified certificate identity for
that agent is refused with 401 and an audit row `identity_required`. `token`
requires a verified agent token; `cert_or_token` either. `any` (the default)
changes nothing.

**Audit truthfulness (task 1):** `identity_method: cert` and
`trust_level: high` are set only by a verified path, and the audit row records
which (`pinned` or `anchor:{id}` + rule id).

**Portal (task 2):** the Agent Identity page is rewritten: real mTLS or SPIFFE
behind a proxy, or agent tokens bound with DPoP; register by uploading the
certificate; an expiry column and "expires in under 14 days" warnings; the
unsupported "more permissive guardrails" sentence removed. No em dashes in
customer-facing text.

## 5. Security & backward compatibility

- **Behavior changes, and how each is cushioned:**

| Change | Who notices | Cushion |
|---|---|---|
| Certificate headers ignored without the proxy boundary | Deployments using `SHIELD_ENABLE_CERT_IDENTITY` or `SHIELD_MTLS_ENABLED` without `SHIELD_TRUSTED_PROXY_ONLY` | Labels only today (§1): their agents drop from `cert/high` to `string_key/medium` in audit; no request is refused. Escape hatch `SHIELD_CERT_HEADER_UNGUARDED=allow` for one release; migration note in the release notes and the runbook |
| Fingerprint normalization | Registrations in colon format | Normalized on read and rewritten on first touch, so existing registrations start matching real mTLS; nothing that matched stops matching |
| `identity.require` | Nobody until set | Default `any` |

- **Proxy secret handling:** `SHIELD_TRUSTED_PROXY_SECRET` is high entropy,
  compared in constant time (already the case), never logged, rotated by
  accepting two values during a change window (new: comma-separated list).
- **Anchors are a privilege:** adding an anchor lets anyone that CA issues to
  become a tenant's agent (subject to rules). Admin plane only, registry write
  gate, audited with the anchor's subject and fingerprint; anchors from one
  tenant never apply to another.
- **Rules cannot mint agents:** a rule maps only to a registered agent; an
  unregistered capture is no identity.
- **Weak certificates refused:** SHA-1 signatures, RSA under 2048, expired, or
  not-yet-valid.
- **Recommended architecture** (documented, not enforced): certificate or
  SPIFFE identity at the edge to obtain a short-lived, DPoP-bound agent token
  (`POST /v1/shield/auth/agent-token` already accepts mTLS/SPIFFE workload
  identity), then tokens per call. Certificates prove the workload; tokens
  carry the user, session and runtime-profile claims that authorization needs.

## 6. Packaging & deploy

- New module `core/cert_identity.py` (one verifier the three middlewares
  share: boundary, normalization, pinned lookup, chain validation, rules,
  cache). Imported by `core/middleware.py`; admin routes in
  `api/routes_agent_cert_identity.py` → **both added to `Dockerfile.admin`**
  (the admin plane also runs the shared middleware), guarded by
  `tests/test_admin_dockerfile_imports.py`.
- `cryptography` is already a dependency (`core/oauth/spiffe.py`); no new pip
  dependency.
- Env flags: `SHIELD_CERT_HEADER_UNGUARDED` (new, escape hatch, default off);
  `SHIELD_TRUSTED_PROXY_SECRET` accepts a comma-separated list (rotation).
- Runbook: `docs/agent-cert-identity-runbook.md` with Envoy and nginx
  configurations, the proxy secret, uploading a CA, writing rules, rotating
  certificates and the proxy secret, and the migration note.
- Rebuild both images.

## 7. Failure modes & edge cases

| Case | Behavior |
|---|---|
| Boundary on, request without the proxy secret, with a certificate header | Header ignored; no certificate identity; request continues |
| Boundary on, no secret and no IP list configured | Trusts nobody (existing fail-closed behavior of `core/proxy_trust.py`) |
| Malformed PEM or fingerprint header | Ignored as no certificate; counted in a metric; never a 500 |
| Certificate expired or not yet valid | No certificate identity; audit row `cert_rejected: expired` (rate-limited) |
| Chain to an anchor that has expired | Rejected; the portal flags expired anchors |
| Two rules match | First in list order wins; the rules editor warns about overlaps |
| Rule captures an unregistered agent | No identity |
| Pinned fingerprint and anchor both match, different agents | Pinned wins; audit notes the conflict |
| Revoke on one worker | Immediate there; at most 5 minutes elsewhere (cache TTL). Documented |
| Redis down | Pinned and anchor lookups fail closed to "no certificate identity" (the request continues as string key); `identity.require: cert` agents are refused |
| `identity.require: cert`, agent behind a proxy that does not forward certs | Every call refused with a clear reason naming the missing header; this is the point |
| Proxy appends instead of overwriting the header (a client value survives) | Not detectable by Shield; the runbook's proxy configuration is mandatory and its check (`/test` with a crafted header) is in the acceptance list |
| 10,000+ distinct certificates per process | LRU eviction; a miss costs one verification (under 2 ms) |

## 8. Test plan (Definition of Done)

**Task 1** (`tests/test_cert_identity_boundary.py`): for each of the three
paths, a certificate header without the proxy secret is ignored (no
`agent_key` override, no `cert`/`high` labels) and with it is honored;
boundary off + escape hatch honors it and logs; colon, `SHA256:` and plain
forms normalize to one value; existing colon registrations match a computed
fingerprint; audit rows carry the verified path. Regression: existing tests
for `tests/test_agent_auth*.py`, SPIFFE and mTLS stay green.

**Task 2**: register by PEM records `not_after`/subject/SANs; two
fingerprints per agent both resolve; revoke one leaves the other; expired
pinned certificate is refused; the certs list pages and flags expiry; portal
static test: the page no longer shows the self-sent header, shows the proxy
setup and upload, and escapes every value.

**Task 3**: chain of root → intermediate → leaf verifies; a self-signed copy
of the issuer DN fails (signature, not names); expired link, missing
`CA:TRUE`, wrong EKU, SHA-1, RSA-1024 each fail; rules match SAN URI, SAN DNS
and CN, with and without `{agent_id}`; unregistered capture is no identity;
tenant A's anchor never validates for tenant B; `/test` explains each
outcome; latency: cached verification under 0.2 ms, first under 2 ms
(benchmarked with a 3-link RSA-2048 chain).

**Task 4**: `require: cert` refuses `X-Agent-Key`-only and token-only claims,
accepts a verified certificate; `token`, `cert_or_token`, `any`; Redis down
refuses `cert`-required agents and nobody else.

**Task 5**: a certificate on a loaded CRL is refused; a stale CRL
(past `nextUpdate`) is reported and, per tenant setting, fails open or closed.

Full suite green in a clean venv; CI `pytest` passes; Dockerfile import guard.

## Tasks (one branch, one PR, or one PR each)

1. **Trust boundary, normalization, truthful audit.** One shared verifier for
   the three middlewares, header ignored without the proxy secret, escape
   hatch, fingerprint normalization with migration, audit records the verified
   path, runbook proxy configs. (This is the narrower fix started separately;
   if that lands first, this task shrinks to normalization and audit.)
2. **Registry v2 and portal.** Register by PEM, expiry, several fingerprints
   per agent, revoke one, certs list, portal page rewritten.
3. **CA anchors and mapping rules.** Chain validation, rules, `/test`, cache,
   latency benchmark.
4. **Require it.** `identity.require` on the agent record, enforced on the
   guard path.
5. **CRLs.** Upload or fetch per anchor, cached, with a stale-CRL policy.

Tasks 1 and 4 are what an enterprise security review will ask for first;
tasks 2 and 3 are what makes it operable at scale; task 5 completes revocation
for customers who cannot use short-lived certificates.
