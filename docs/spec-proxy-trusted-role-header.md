---
title: "Spec: proxy-trusted role header (strict_proxy mode)"
layout: default
nav_order: 39
permalink: /spec-proxy-trusted-role-header/
description: "On a public endpoint, strict role binding is the only safe mode, but it breaks every caller that sends X-User-Role. A fourth mode accepts the header only from a proxy that proved itself with a shared secret, so headers keep working behind the gateway and mean nothing from the internet."
---

# Spec: proxy-trusted role header (`strict_proxy` mode)
{: .no_toc }

`strict` refuses a self-asserted role unconditionally, so a deployment that wants
forged roles to stop working must also break every integration that sends
`X-User-Role`. This adds one mode that distinguishes *who sent the header* using
the trusted-proxy boundary Shield already has, so both can be true at once.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. Problem & outcome

`core/identity_resolution.py` resolves the role for every authorization decision
in three modes:

| mode | verified claim present | no verified claim |
|---|---|---|
| `off` (default) | header wins | header wins |
| `prefer` | claim wins, header ignored | header wins |
| `strict` | claim wins, header ignored | **no role** |

On a publicly reachable deployment, `off` and `prefer` are both forgeable: a
caller that presents no credential at all and sends `X-User-Role: sre_lead` is
granted `sre_lead`, because there is no verified claim for the mode to prefer.
The RBAC matrix, the capability mint and the audit trail all then operate
correctly on an attacker-supplied input.

`strict` closes that, but it closes it for everyone. Any caller that legitimately
sends `X-User-Role` — an internal service behind the gateway, a dev harness, the
LangChain examples — silently drops to no role and loses every grant.

Shield already has the primitive that separates the two cases.
`core/proxy_trust.py` establishes a trusted hop via a shared secret the proxy
injects as `X-Shield-Proxy-Token`, and `core/mtls_middleware.py` and
`core/oauth/spiffe_middleware.py` already gate header-derived identity on it.
Role resolution does not use it.

**Outcome.** A fourth mode, `strict_proxy`: identical to `strict`, except a
self-asserted role is accepted when — and only when — `peer_is_trusted(request)`
says the request came through the trusted proxy. Observable success condition:

- With `SHIELD_ROLE_BINDING=strict_proxy` and the proxy boundary configured,
  a request carrying the proxy secret and `X-User-Role: sre_lead` resolves
  `user_role="sre_lead"` with `role_source="proxy"`.
- The same request without the secret resolves `user_role=""`, exactly as
  `strict` does today.
- A request carrying a verified role claim resolves from the claim in both
  cases, and the header is ignored and audited as overridden.

### Non-goals
- **Not** a change to `off`, `prefer` or `strict`. All three keep their current
  behaviour byte for byte. This spec adds a mode; it does not modify one.
- **Not** a fix for the demo's Keycloak issuer mismatch (`iss` is
  `http://keycloak:8080/...` while the deployment trusts a stale ngrok URL).
  That is a configuration fix and is tracked separately; this spec assumes
  tokens that verify.
- **Not** per-tenant proxy secrets. The boundary is a deployment property, one
  secret per Shield instance, as it already is for mTLS and SPIFFE.
- **Not** a new transport. No mTLS requirement, no RFC 9421 signature. The hop
  is proved by the existing shared secret.
- **Not** a change to delegation (`X-On-Behalf-Of`). Delegation short-circuits
  ahead of all of this and stays untouched.

## 2. Plane & latency contract

**Plane:** data plane (`core/app.py`). `resolve_identity()` is called from
`api/routes_tool.py`, `api/routes_classify.py`, `api/routes_agent_chat.py`,
`api/routes_agent_auth.py`, `api/routes_classify_output.py` and
`core/middleware.py`.

**Touches the guard path: YES.** `/guardrails/*`, `cap/mint` and `tools/call`
all resolve identity.

**Latency budget: < 50 µs added, and only in the new mode.**

The added work is `peer_is_trusted()`, which is one `os.environ` read, one
`request.headers.get`, and one `hmac.compare_digest` over a short string. No
Redis, no JWKS, no network, no crypto beyond a constant-time byte compare. It is
the same call `mtls_middleware` already makes per request.

Ordering constraints that keep it free for everyone else:

- The call sits in the `elif mode == MODE_STRICT_PROXY` branch only. Modes
  `off`, `prefer` and `strict` never reach it, so an existing deployment pays
  exactly zero.
- It runs only after the verified-claim branch has failed. A caller with a
  usable claim never triggers it.
- No new import at module scope. `core.proxy_trust` is imported inside the
  branch, matching the existing lazy import at `identity_resolution.py:75`, so
  module load cost is unchanged.

## 3. Data model

**No new Redis keys. No new value shapes. No new TTLs.**

One existing key gains one legal value. Per-tenant role binding is stored at:

    shield:role_binding:{tenant_id}   ->   JSON {"mode", "role_claim", "role_map"}

`mode` is validated against the `_MODES` tuple in `core/identity_resolution.py`
before use (`role_binding_mode()`, line 129). `strict_proxy` is added to that
tuple. A stored mode outside the tuple already falls back to the env default, so
an older Shield reading a config written by a newer one degrades to the env
value rather than crashing — worth stating because the two can run concurrently
during a rollout.

**Tenant scoping** is unchanged: `tenant_id` is passed by the caller,
`SHIELD_ROLE_BINDING=off` remains the global operator kill switch that overrides
any tenant setting, and a Redis read failure resolves to the env default rather
than locking tenants out. Note the known gap recorded in
[spec-idp-role-claim-config](spec-idp-role-claim-config.md): most call sites do
not currently pass `tenant_id`, so in practice the env value is what applies.
This spec does not fix that and does not depend on it.

**Cross-tenant isolation argument:** the proxy secret is deployment-wide, not
tenant-scoped, so a trusted proxy can assert a role for any tenant it can
already route to. That is the same authority the proxy has today for mTLS and
SPIFFE identity, and it is the reason the boundary is a shared secret rather
than something a tenant can self-serve. Called out in §5.

## 4. API / interface

**No new endpoints. No request or response shape changes. No new status codes.**

The interface change is three internal constants and one config value.

### Constants (`core/identity_resolution.py`)

```python
MODE_STRICT_PROXY = "strict_proxy"
_MODES = (MODE_OFF, MODE_PREFER, MODE_STRICT, MODE_STRICT_PROXY)

SOURCE_PROXY = "proxy"   # header, vouched for by the trusted-proxy boundary
```

`SOURCE_PROXY` is deliberately **not** added to `VERIFIED_SOURCES`. The proxy
proved the hop; it did not prove the end user's credential to Shield. Keeping it
out means `role_verified` stays honest — it continues to mean "a signature
Shield checked said this role" — and the audit can still tell a
cryptographically proven role from a vouched one. `header_overridden` is
likewise unaffected.

### Resolution logic

In `resolve_identity()`, the `elif mode == MODE_STRICT` branch (line 422) gains
a sibling:

```python
elif mode == MODE_STRICT_PROXY and _proxy_vouched(request):
    hdr = (body_user_role or "").strip() or _header(request, "X-User-Role")
    user_role, role_source = (hdr, SOURCE_PROXY) if hdr else ("", SOURCE_NONE)
elif mode in (MODE_STRICT, MODE_STRICT_PROXY):
    user_role, role_source = "", SOURCE_NONE
```

with a helper that fails closed on any error:

```python
def _proxy_vouched(request) -> bool:
    """True only when the trusted-proxy boundary is ON and this peer passed it.

    Any failure — boundary disabled, module missing, exception — is False. A
    role that cannot be attributed to a trusted hop is not a role.
    """
    try:
        from core.proxy_trust import peer_is_trusted, trusted_proxy_only
        return bool(trusted_proxy_only() and peer_is_trusted(request))
    except Exception:
        return False
```

Note `trusted_proxy_only()` is required, not merely `peer_is_trusted()`.
Without it an operator could set `strict_proxy` while the boundary is off and
get `strict` semantics with a misleading name; requiring both means the mode is
inert unless the boundary is actually enabled.

### Audit

`ResolvedIdentity.audit_fields()` already emits `role_source` and
`role_binding_mode`. A proxy-vouched decision therefore appears as
`role_source="proxy"`, `role_binding_mode="strict_proxy"`,
`role_verified=false` with no code change to the audit path. That distinction is
the point: an auditor can separate proven roles, vouched roles and refused roles
after the fact.

### Plane mounting
Unchanged. No router is added, so neither plane mounts anything new.

## 5. Security & backward compatibility

**Default behaviour: unchanged.** `SHIELD_ROLE_BINDING` still defaults to `off`.
The new mode is opt-in by existing, and no deployment reaches the new code
without an operator setting the value. There is no default change, therefore no
migration and no escape-hatch flag is required — `SHIELD_ROLE_BINDING=strict`
remains available and unmodified as the stricter setting.

**Who may assert a role:** only a caller that presents
`X-Shield-Proxy-Token` matching `SHIELD_TRUSTED_PROXY_SECRET`, and that
additionally matches `SHIELD_TRUSTED_PROXY_IPS` when set.

**What a malicious caller can do:** nothing new. Without the secret,
`strict_proxy` is `strict` — the header is discarded and the caller gets no
role. The forged-header path this whole spec exists to close stays closed.

**What a compromised proxy can do:** assert any role for any tenant it can
route to. This is not a new authority — `core/mtls_middleware.py` already lets
the same secret vouch for `X-Forwarded-Client-Cert`-derived identity, and
`core/identity_resolution.py:75` already lets it rewrite the DPoP `htu`. The
secret is a deployment-level trust root and must be treated as one:
high-entropy, injected by the proxy only, never reachable from a client-settable
header path, rotated on suspicion. Documented in the runbook task.

**Why not IP-only:** `proxy_trust` already documents this. Under uvicorn's
`proxy_headers`, `request.client.host` derives from the attacker-controlled
`X-Forwarded-For`, so an IP allowlist alone is spoofable. `peer_is_trusted()`
treats the secret as authoritative when set, and trusts nobody when neither a
secret nor an IP list is configured. This spec inherits that fail-closed
posture rather than restating it.

**Precedence is unchanged.** A verified claim still beats everything. The new
branch is reached only when no verified claim and no verified delegation was
found, so `strict_proxy` cannot be used to override a real credential.

## 6. Packaging & deploy

- **New module:** none. The change is confined to `core/identity_resolution.py`,
  which already exists in both images.
- **`Dockerfile.admin`:** no change. No new module is imported by
  `admin_app.py`. `tests/test_admin_dockerfile_imports.py` must still pass and
  is part of the DoD.
- **New pip dependency:** none. `hmac` and `ipaddress` are stdlib and already
  used by `core/proxy_trust.py`. No edit to `requirements.txt`,
  `requirements-test.txt` or `requirements-admin.txt`.
- **Env flags:** no new flag. Three existing ones combine:

  ```
  SHIELD_ROLE_BINDING=strict_proxy
  SHIELD_TRUSTED_PROXY_ONLY=true
  SHIELD_TRUSTED_PROXY_SECRET=<high-entropy>
  SHIELD_TRUSTED_PROXY_IPS=<optional cidr list>
  ```

- **Images to rebuild:** data plane only. The admin image is unaffected, though
  rebuilding both is harmless.
- **Rollout order matters.** Configure the proxy to inject
  `X-Shield-Proxy-Token` *before* switching `SHIELD_ROLE_BINDING` to
  `strict_proxy`. Reversing the order fails closed — correct, but it drops every
  header-derived role for the length of the window.
- **Rollback:** set `SHIELD_ROLE_BINDING=off`. Single env change, no data
  migration, no key cleanup.

## 7. Failure modes & edge cases

Fail-closed throughout. The governing rule: **a role that cannot be attributed
to either a verified claim or a trusted hop is not a role.** `resolve_identity`
returns `user_role=""` rather than raising, because `""` resolves to no grants
everywhere it is consulted, and a 500 on the guard path is worse than a denial.

| condition | behaviour | posture |
|---|---|---|
| `strict_proxy`, boundary off (`SHIELD_TRUSTED_PROXY_ONLY` unset) | identical to `strict`, no role | closed |
| `strict_proxy`, boundary on, no secret and no IP list | `peer_is_trusted` returns False, no role | closed |
| `strict_proxy`, secret configured, header absent | no role | closed |
| `strict_proxy`, secret configured, header wrong | `compare_digest` fails, no role | closed |
| `strict_proxy`, trusted peer, `X-User-Role` empty or whitespace | `user_role=""`, `role_source="none"` | closed |
| `strict_proxy`, trusted peer, unknown role name | role passes through; policy has no grants for it | closed at policy |
| `strict_proxy`, trusted peer, huge header value | passed through unchanged; already bounded by the server's header limit | n/a |
| `core.proxy_trust` import fails | `_proxy_vouched` catches, no role | closed |
| `peer_is_trusted` raises | caught, no role | closed |
| Redis down while reading tenant mode | existing behaviour: env default, not deny-all | open by design, unchanged |
| Verified claim **and** trusted-proxy header both present | claim wins, `header_overridden` true | closed |
| Verified delegation present | delegation short-circuits at line 398, mode irrelevant | unchanged |
| Stored tenant mode is `strict_proxy`, older Shield reads it | value not in that build's `_MODES`, falls back to env default | degrades, does not crash |
| Concurrent writes to the tenant mode key | last write wins, 30 s cache means propagation is bounded | unchanged |

The one deliberate exception to fail-closed is the Redis path, which already
resolves to the env default rather than denying every tenant on a blip. This
spec does not change that trade-off.

## 8. Test plan (Definition of Done)

New file `tests/test_role_binding_strict_proxy.py`, alongside the existing
`tests/test_role_binding_strict.py` and `tests/test_mtls_proxy_trust.py`. All
env is monkeypatched and `clear_role_binding_cache_for_tests()` is called
between cases.

**Happy path**
1. `strict_proxy` + boundary on + correct secret + `X-User-Role: sre_lead`
   → `user_role == "sre_lead"`, `role_source == "proxy"`.
2. Same, role supplied in the body instead of the header → same result, body
   takes precedence over the header as it does in `off`.
3. `audit_fields()` reports `role_source="proxy"`,
   `role_binding_mode="strict_proxy"`, `role_verified is False`.

**Every §7 edge case**
4. Boundary off → `user_role == ""`.
5. Boundary on, neither secret nor IP list → `""`.
6. Correct secret, no header → `""`, `role_source == "none"`.
7. Wrong secret → `""`.
8. Whitespace-only header → `""`.
9. `core.proxy_trust` import made to raise → `""` (monkeypatch the module).
10. `peer_is_trusted` made to raise → `""`.
11. IP allowlist set and matching, secret also set and matching → role accepted.
12. IP allowlist set but not matching, secret matching → `""` (both must pass).

**Precedence**
13. Verified claim present + trusted proxy header present → claim wins,
    `role_source` is the agent source, `header_overridden is True`.
14. Verified delegation present + trusted proxy header present → delegation
    wins, `acting_for` populated.

**Regression guards (the drift-prone part)**
15. `off`, `prefer` and `strict` produce byte-identical `ResolvedIdentity`
    output with the proxy boundary both on and off. This is the test that
    proves "adds a mode, does not modify one" and is the one to write first.
16. `role_binding_mode()` accepts `"strict_proxy"` from the tenant Redis key and
    rejects garbage, falling back to the env default.
17. `SOURCE_PROXY not in VERIFIED_SOURCES` asserted explicitly, so a future
     refactor cannot quietly promote a vouched role to a verified one.
18. Existing `tests/test_identity_resolution.py`,
    `tests/test_role_binding_strict.py`, `tests/test_mtls_proxy_trust.py` and
    `tests/test_spiffe_proxy_trust.py` pass unmodified. If any needs an edit,
    that is a signal the change is not additive.
19. `tests/test_admin_dockerfile_imports.py` passes.

**Gate**
20. `python -m pytest tests -q` green in a clean venv
    (`python -m venv /tmp/x && /tmp/x/bin/pip install -r requirements-test.txt`).
21. CI `pytest` gate green.

## 9. Deployment topologies

Shield is deployed two ways, and they have different roots of trust. A mode that
is correct in one is wrong in the other, so both are specified here rather than
left to the operator.

### A. Direct — the agent is Shield's HTTP client

    agent ──► Shield /guardrails/*, cap/mint, tools/call

The agent sets its own headers, and can carry a verified credential end to end.
`strict` is correct here and needs nothing from this spec. `strict_proxy` is for
the case where an internal service legitimately asserts a role and cannot carry
a token.

### B. Behind LiteLLM — the hook is Shield's HTTP client

    agent ──► LiteLLM /v1/chat/completions
                └─ VotalGuardrail hook ──► Shield /guardrails/input|output

This is `votal_guardrail.py`. From Shield's view the client is LiteLLM, not the
agent, and only what `_extract_shield_headers()`
([votal_guardrail.py:90](../votal_guardrail.py)) forwards survives: `x-api-key`,
`x-agent-key`, `x-user-role`, `x-tenant-id`. The `Authorization` header Shield
receives is LiteLLM's own Shield token
([votal_guardrail.py:82](../votal_guardrail.py)), not the caller's.

Two defects follow, and both must be fixed for any role-binding mode to mean
anything on this path.

**Defect 1 — the forwarded role is caller-controlled.**

```python
user_role = metadata.get("user_role") or proxy_headers.get("x-user-role", "")
```

`proxy_headers` is the *client's* request headers. LiteLLM forwards a value the
caller set, so trusting the LiteLLM hop launders the forgery rather than
stopping it. Meanwhile `user_api_key_dict: UserAPIKeyAuth` — LiteLLM's
authenticated virtual key, the one verified thing on the request — appears in
all three hook signatures and is used nowhere.

**Defect 2 — no verified user credential is forwarded.** The caller's OIDC token
never reaches Shield, so there is nothing for `prefer` or `strict` to verify
against, and every LiteLLM-routed request in `strict` resolves to no role.

### The ladder for topology B

Shield already resolves these in the right order, so no new precedence logic is
needed — `resolve_identity()` short-circuits on verified delegation at
[identity_resolution.py:398](../core/identity_resolution.py) before any mode is
consulted.

**Tier 1 — verified. Preferred, and it makes `strict` viable behind LiteLLM.**

The hook forwards the caller's OIDC user token as `X-On-Behalf-Of`. Shield's
existing delegation path verifies it: issuer allow-listed against
`SHIELD_WORKLOAD_OIDC_ISSUERS`, signature checked against that issuer's JWKS,
audience enforced, roles extracted via `SHIELD_ROLE_CLAIM`
([delegation.py:76](../core/delegation.py)).

This works because a bearer user token, unlike a DPoP proof, is **not bound to
the HTTP request**. It does not care that LiteLLM re-originated the call, so
cryptographic verification survives the hop unchanged. The role is proven, not
vouched, and `strict_proxy` is not needed at all on this path.

Requires `SHIELD_DELEGATION=optional|required` and one added forwarded header.
No Shield code change.

**Tier 2 — vouched. For callers with no human user token.**

CI bots, service-to-service traffic, and anything that authenticates to LiteLLM
by virtual key alone. The hook injects `X-Shield-Proxy-Token` and derives the
role from `user_api_key_dict` metadata rather than from the client's header.
Shield runs `strict_proxy`. LiteLLM's vouching now means something: the caller
proved a key, the key maps to a role.

**Tier 3 — nothing.** No role, per `strict`.

The tiers compose without configuration: a request carrying a user token gets
Tier 1, one without falls to Tier 2, one with neither gets Tier 3. That
ordering is already what the code does.

### Consequence for the hook

`votal_guardrail.py` ships with LiteLLM, not with Shield, but the change is a
**companion fix, not a follow-up**. Enabling `strict_proxy` or `strict` without
it breaks every LiteLLM-routed request: no proxy token means an untrusted peer,
and no user token means no verified claim. Per the repo's self-contained-PR
invariant it lands in this series, not after it.

## 10. Task breakdown (one PR each)

**PR 1 — regression guard, no behaviour change.**
Add test 15 against the current three modes. Proves the baseline before it can
move. Small, boring, and the thing that makes PR 2 reviewable.

**PR 2 — `strict_proxy` mode.**
`MODE_STRICT_PROXY`, `SOURCE_PROXY`, `_proxy_vouched()`, the resolution branch,
and tests 1 to 19. Self-contained: no dep, no Dockerfile, no companion fix
stranded elsewhere.

**PR 3 — LiteLLM hook, Tier 1.**
Forward `X-On-Behalf-Of` from `proxy_server_request.headers` in
`_extract_shield_headers()`. Tests: header forwarded when present, absent when
not, and size-capped so the hook cannot be used to push an 8 MiB "token" at
Shield. Independently useful — it turns on verified roles behind LiteLLM with no
Shield change and no mode change.

**PR 4 — LiteLLM hook, Tier 2.**
Inject `X-Shield-Proxy-Token` into `client_headers`. Derive `user_role` from
`user_api_key_dict` rather than `proxy_headers`, keeping the header read only as
a fallback when the proxy token is not configured. Tests: authenticated-key role
wins over a conflicting client header; no proxy token means no proxy token
header, not an empty one.

**PR 5 — operator documentation.**
Runbook covering rollout order, secret generation and rotation, the
compromised-proxy blast radius from §5, the mode comparison table from §1, and
the topology ladder from §9. Docs only.

PR 2 and PR 4 are the only ones that change behaviour. PR 3 is additive on both
sides. The tests in PR 3 and PR 4 live with the hook, which is a different
deployable — say so in the PR description so a reviewer does not look for them
in `tests/`.
