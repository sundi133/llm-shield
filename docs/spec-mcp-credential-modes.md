# Spec: upstream credential modes for the MCP gateway

Status: **DRAFT — for approval.** Spec-first per `CLAUDE.md`.

Supersedes `docs/spec-mcp-oauth-brokering.md`, whose tasks 1–2 already shipped
(`3ac7449`, `2f30767`) and are reused unchanged. That spec built the refresh loop
OAuth-auth-code-specific; four of the eight modes below need the same loop, so it
is extracted first rather than written four times.

## 1. Problem & outcome

An enterprise gateway fronts upstreams that authenticate in eight different ways.
Three already work; the rest each need a different *acquisition* story but the
**identical** runtime story.

| # | Mode | Today | Needs |
|---|---|---|---|
| 1 | No-auth / local | ✅ works | — |
| 2 | API key (any header) | ✅ works | — |
| 3 | Static bearer / PAT | ✅ works | — |
| 4 | OAuth auth code + PKCE | 🟡 discovery+connect done | callback, exchange, refresh |
| 5 | OAuth device flow | ❌ | device authorization + polling |
| 6 | OAuth client credentials | ❌ | one token POST, no browser |
| 7 | GitHub App installation | ❌ | RS256 app JWT → installation token |
| 8 | Gateway-issued capability | 🟡 `mint_cap` exists | wire as an outbound header |

**The structural point.** Every mode reduces to *"produce a valid header value now,
refreshing if needed"*, and modes 4–7 all need a refresh loop with a timer, a
distributed lock, single-flight, a status model, and audit. The data plane already
only materializes a `shield://` reference and does not care who keeps it fresh —
that is the seam.

**Outcome.** One provider interface, eight strategies, one refresh loop. Observable
success condition: a route configured in any mode presents a valid credential on
every `tools/call`, survives its credential's natural expiry without operator
action, and the guard path gains no network call in the steady state.

**Non-goals**
- Per-user credentials — needs verified identity first
  (`docs/spec-mcp-verified-identity.md`). All modes are per-route/per-tenant.
- No change to how agents authenticate **to** Shield.
- Not replacing `api/routes_oauth.py` (Shield as authorization *server*; inbound).

## 2. Plane & latency contract

**Admin plane acquires and refreshes. Data plane only materializes.**

**Budget: zero new network calls on the guard path in the steady state.** The
provider writes the current credential into the vault; the gateway resolves the
existing `shield://` reference. Reactive refresh in the gateway is the
timer-missed fallback only, and must be single-flighted.

## 3. Data model

Reuses `mcp_oauth:{tenant_id}:{route}` from the shipped store, generalized: the
record gains `mode` (one of the eight) and `config` (mode-specific, secrets by
reference only). Vault entry names stay derived from the route
(`oauth-{route}-access` / `-refresh` / `-client`).

Static modes (1–3) keep **no** broker record — they need no acquisition and no
refresh, and inventing one would imply a lifecycle they do not have.

```jsonc
{
  "mode": "client_credentials",
  "issuer": "https://idp.example",
  "token_endpoint": "https://idp.example/oauth2/token",
  "client_id": "svc-shield",
  "client_secret_ref": "shield://oauth-payments-client",
  "scopes": ["mcp.invoke"],
  "access_token_ref": "shield://oauth-payments-access",
  "refresh_token_ref": "",          // absent for modes that re-acquire instead
  "expires_at": 1785400000,
  "status": "connected",
  "last_error": ""
}
```

`refresh_token_ref` empty is meaningful: modes 6, 7 and 8 **re-acquire** rather
than refresh (a fresh client-credentials grant, a fresh installation token, a
freshly minted cap). `CredentialProvider.renew()` covers both so the loop does not
branch on mode.

## 4. Interface

```python
class CredentialProvider(Protocol):
    mode: str
    interactive: bool          # True only for 4 and 5 (needs a human)

    async def begin(self, ctx) -> dict:   # interactive: returns authorize/verification info
    async def complete(self, ctx, **kw) -> dict:   # interactive: finish (callback / poll)
    async def renew(self, ctx) -> dict:   # refresh OR re-acquire; returns {token, expires_at}
    async def revoke(self, ctx) -> None
```

Non-interactive modes implement `renew` only; `begin`/`complete` raise. Static
modes (1–3) have no provider at all — the absence of a broker record *is* the
mode, which keeps existing routes untouched.

Endpoints generalize the shipped OAuth ones (`/oauth/connect` becomes
`/credential/connect`, with the OAuth paths kept as aliases so nothing already
configured breaks).

## 5. Security & backward compatibility

Every property from the OAuth spec carries over and applies to all modes: tokens
only in the vault, `state` single-use and TTL-bounded, fixed non-request
`redirect_uri`, SSRF-guarded discovery, allowlist-based status responses, secrets
never logged or returned.

New, per mode:

- **6, client credentials:** the client secret is a standing machine credential —
  vault, bound to the token-endpoint host, never in the record.
- **7, GitHub App:** the RSA private key is the crown jewel (it mints tokens for
  every installation). Vault, and the app JWT is minted with a **60-second**
  lifetime because that is all it needs.
- **8, capability tokens:** the upstream must verify against Shield's JWKS. This
  is the only mode with **no vendor credential at all**, which makes it the right
  default for in-cluster upstreams — and it pairs with `isolation_ack`.

**Escape hatch:** `SHIELD_MCP_CREDENTIAL_MODES=0` disables acquisition and the
timer; existing vault entries keep working as static credentials.

## 6. Packaging

New: `core/mcp_credentials.py` (frame + strategies). **`Dockerfile.admin` COPY
line in the same commit.** No new dependency — `httpx` and `PyJWT[crypto]` are
already in `requirements-admin.txt`.

**`core/signers.py` cannot serve mode 7:** it is Ed25519-only
(`LocalEd25519Signer`, PKCS11, Vault Transit `ed25519`), and GitHub Apps require
RS256. Mode 7 uses PyJWT directly over the app's PEM. Stated here so nobody
wastes time trying to extend `build_signer`.

## 7. Failure modes

Inherits every row from the OAuth spec §7. Additional:

| Condition | Behavior |
|---|---|
| Mode 6 token request rejected (`invalid_client`) | `needs_consent` equivalent → `status: error`, no retry storm; the secret is wrong and only a human fixes it |
| Mode 7 installation revoked | `status: needs_consent`; the app was uninstalled |
| Mode 7 clock skew on the app JWT | `iat` backdated 30 s; GitHub rejects future-dated JWTs |
| Mode 8 signer unavailable | Fail closed — a route expecting a minted cap must not fall back to no auth |
| Any mode, `renew` raises | Existing token left in place until expiry; `status: error`, backoff |

**Fail-closed** on credential materialization, unchanged.

## 8. Test plan

Per mode: acquire (or mint), renew, revoke, and the failure row above. Shared:
single-flight under concurrency, no secret in any response or log, cross-tenant
isolation, `SHIELD_MCP_CREDENTIAL_MODES=0` restores static behavior, and static
routes untouched by the timer.

Plus an **integration harness** (§9 task 8): a local MCP server that can demand
each credential mode, so the modes are exercised end to end rather than only
against stubs.

## 9. Tasks

| # | Task | Guard path? |
|---|---|---|
| 1 | Extract `CredentialProvider` frame + refresh loop (auth-code as first strategy) | No |
| 2 | Finish auth-code: callback + exchange (mode 4) | No |
| 3 | Mode 6 — client credentials | No |
| 4 | Mode 8 — gateway-issued capability tokens | No |
| 5 | Mode 7 — GitHub App installation | No |
| 6 | Mode 5 — device flow | No |
| 7 | Reactive single-flight renew in the gateway | **Yes** |
| 8 | Test MCP server (`examples/mcp_credential_lab`) exercising all modes | No |
| 9 | Docs: credential-modes table in `mcp-gateway.md` | No |

Order is by enterprise value, not by mode number: 6 and 8 cover most real
upstreams; 5 is last because few providers implement it and Higgsfield's
device-auth host 404s on discovery, so it cannot be tested there.
