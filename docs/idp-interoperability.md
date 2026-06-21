---
title: Identity Provider Interoperability
layout: default
nav_order: 20
permalink: /idp-interoperability/
description: How Votal Shield interoperates with your existing IdP/IAM over OIDC/OAuth — what's supported, what's a validated standard, what's on the roadmap, and how to prove it against your own IdP in one command.
---

# Identity provider interoperability
{: .no_toc }

Shield secures autonomous AI agents **on top of** your existing identity
infrastructure — it does not replace your IdP/IAM. Agents authenticate using the
same standards (OIDC / OAuth 2.0) your IdP already speaks, and Shield then adds
agent-specific controls (task-scoped capabilities, RBAC, provenance, and
[continuous identity / auto-revoke](/continuous-identity/)).
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

![Votal agentic identity interoperability with leading identity platforms](/assets/images/idp-interop-overview.png)

## 1. The model in one line

> **Keep your front desk.** Your IdP (Okta, Microsoft Entra, Google, Ping, …)
> keeps issuing and checking identities. Shield trusts those identities over
> OIDC/OAuth and gives each agent **one-time, least-privilege passes**, logs
> every action, and can **cancel an agent instantly** — speaking the identity
> standards your IdP already uses. No rip and replace.

## 2. How to read our interop claims

We label maturity honestly so nothing gets over-claimed in a security review:

| Label | Meaning | Your action |
|---|---|---|
| **Supported (OIDC/OAuth)** | Works via the shared standard. Every listed IdP uses the **same** OIDC code path. | Confirm against your tenant with the [verify command](#5-prove-it-against-your-own-idp). |
| **Supported (OIDC); SCIM roadmap** | OIDC authentication works today; user/agent lifecycle provisioning (SCIM) is planned. | Use OIDC auth now; track SCIM on the roadmap. |
| **Validated** *(standards table)* | Tested end-to-end in CI. | Rely on it. |
| **Roadmap** | Not built yet. | Plan around it. |

{: .note }
> "Supported (OIDC/OAuth)" is not a weaker claim than a per-vendor integration —
> it's a *stronger* one: because interop is by the standard, **every** OIDC IdP
> works through one code path rather than a brittle one-off connector per vendor.
> [Keycloak](https://www.keycloak.org/) is our **CI reference IdP** (free,
> scriptable), so it's the one wired into automated tests — but it exercises the
> identical path every other IdP uses.

## 3. Identity platforms

All platforms below interoperate via **OIDC / OAuth 2.0**.

| Identity platform | Interop via | Status |
|---|---|---|
| Keycloak | OIDC, OAuth 2.0 | Supported (OIDC/OAuth) — CI reference IdP |
| Microsoft Entra ID | OIDC, OAuth 2.0 | Supported (OIDC/OAuth) |
| Okta Workforce Identity | OIDC, OAuth 2.0 | Supported (OIDC/OAuth) |
| Okta Auth0 | OIDC, OAuth 2.0 | Supported (OIDC/OAuth) |
| Ping Identity | OIDC, OAuth 2.0 | Supported (OIDC/OAuth) — SAML on roadmap |
| Google Cloud Identity / Workspace | OIDC, OAuth 2.0 | Supported (OIDC/OAuth) |
| AWS IAM Identity Center | OIDC, OAuth 2.0 | Supported (OIDC/OAuth) — SAML on roadmap |
| Oracle IAM | OIDC, OAuth 2.0 | Supported (OIDC/OAuth) |
| IBM Security Verify | OIDC, OAuth 2.0 | Supported (OIDC/OAuth) |
| JumpCloud | OIDC, OAuth 2.0 | Supported (OIDC/OAuth) |
| CyberArk Workforce Identity | OIDC (auth) | Supported (OIDC); SCIM roadmap |
| SailPoint Identity Security | OIDC (auth) | Supported (OIDC); SCIM roadmap |
| Saviynt Enterprise Identity | OIDC (auth) | Supported (OIDC); SCIM roadmap |

Discovery + JWKS reachability has been verified live against **Google** and
**Microsoft Entra**. Any IdP that publishes a standard
`/.well-known/openid-configuration` works the same way.

## 4. Standards

| Standard | Status | Notes |
|---|---|---|
| OIDC | **Validated** | `id_token` validation against the IdP JWKS; provider registration |
| OAuth 2.0 | **Validated** | Token exchange (RFC 8693), dynamic client registration |
| JWT / JWS / EdDSA | **Validated** | Signed, build-bound agent identity + capability tokens |
| SPIFFE / WIMSE + mTLS | **Validated** | Workload identity for agents |
| CAEP / SSF | **Validated** | Continuous signals — emit on revoke, consume to revoke ([details](/continuous-identity/)) |
| SAML 2.0 | Roadmap | Planned |
| SCIM | Roadmap | User/agent provisioning + lifecycle; planned |
| Enterprise directory integration | Via standards | Through OIDC / OAuth claims |

## 5. Prove it against your own IdP

`scripts/verify_oidc_interop.py` runs **Shield's own OIDC validator**
(`core/oauth/oidc_client`) against any IdP: it fetches the OpenID discovery
document, resolves and fetches the JWKS, and (optionally) validates a real
`id_token` — signature, issuer, audience, expiry. This is what turns
"Supported" into "validated for *my* IdP."

```bash
# discovery + JWKS reachability (no login required) — works for any public IdP
python3 scripts/verify_oidc_interop.py --issuer https://accounts.google.com

# full end-to-end validation of a real login token (gold-standard proof)
python3 scripts/verify_oidc_interop.py \
  --issuer https://<tenant>.okta.com \
  --audience <client_id> --id-token "<paste id_token>"
```

It prints `PASS`/`FAIL` per check plus a copy-paste evidence line, and exits
non-zero on any failure (so it drops straight into CI).

{: .tip }
> Run it from the repo root so `core/` is importable. Verified live against
> Google (RS256, multiple keys) and Microsoft Entra; Keycloak is validated
> end-to-end via `setup_keycloak.py` + `test_local_oidc.py`.

## 6. What Shield adds on top of your IAM

| Capability | Plain English |
|---|---|
| **Task-scoped identities** | Single-use, short-TTL capability tokens scoped to one tool + resource — a one-time key for one door, not a master key. |
| **Delegated authority** | An agent can hand a helper agent a **narrower** pass, never a wider one. |
| **Provenance** | Tamper-evident audit lineage from prompt to tool execution. |
| **Runtime authorization** | RBAC + per-action capability verification at the tool boundary. |
| **Continuous identity** | [CAEP/SSF auto-revoke](/continuous-identity/): a detection — or an EDR/IdP signal — revokes the agent in real time. |

## See also

- [Continuous Identity & Auto-Revoke](/continuous-identity/) — closed-loop
  revoke and CAEP/SSF signal exchange with your IdP/EDR.
- [Agentic Integration Guide](/agentic-integration-guide/) — mint agent
  identity tokens and capability tokens.
- [Guard an External Agent](/guard-external-agent/) — put Shield in front of a
  hosted agent over a proxy.
