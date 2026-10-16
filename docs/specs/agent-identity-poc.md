---
title: "Spec: Agent identity client helper and POC"
layout: default
nav_exclude: true
permalink: /specs/agent-identity-poc/
description: A Python client for key-bound agent tokens and capabilities, and a scripted nine-scenario proof of concept that runs in a customer's environment or in-process.
---

# Spec: Agent identity client helper and POC

> Status: **BUILT 2026-10-16**, on the user's request ("build the client helper
> and the scripted demo scenarios poc") after the plan in the conversation that
> led to it; recorded here for the repo's spec-first trail. Branch
> `spec/agent-cert-identity`, with `docs/specs/agent-cert-identity.md`, on which
> scenarios 4 and 5 depend.

## 1. Problem & outcome

Every customer integrating agent identity wrote their own Ed25519 key handling
and DPoP proofs (RFC 9449) to call `cap/mint`; `packages/shield-py` covered the
partner guard API only. And a proof of concept was a list of curl commands.

Outcome:
- `packages/shield-py/shield_agent.py`: `AgentKey`, `dpop_proof`, `ShieldAgent`
  (token fetch and refresh, auth headers, `mint` with `ApprovalRequired` /
  `CapabilityDenied`, `delegate`, `revoke`), `CapabilityVerifier` for tool
  servers. Optional extra `votalai-shield[agent]` adds `cryptography`.
- `examples/agent-identity-poc/poc.py`: nine scenarios (stolen token, wrong
  role, human approval, impersonation, revoked certificate, sandbox escape,
  stale sandbox, incident response, evidence), each ending in a refusal and an
  audit record, with a Markdown/JSON report; against a customer's Shield (and
  mTLS proxy) or `--local` in-process.

Non-goals: a non-Python client; OIDC token exchange for `user_sub` (a server
gap, listed in the enterprise gaps); changing any server behavior.

## 2. Plane & latency contract

Client-side code and an example script. No server change, nothing on the guard
path. The POC calls existing data-plane and tenant routes.

## 3. Data model

None new. The POC creates, under a run prefix, and removes: three registry
agents, one approval rule (appended to the tenant's rules, since
`PUT /v1/tenant/me/agentic/config` replaces whole sections), one runtime profile,
and for scenarios 4 and 5 a trust anchor, a mapping rule (appended) or a
registered certificate.

## 4. API / interface

The helper's public API is listed in its module docstring. It uses
`POST /v1/tenant/me/agent-auth/agent-token`, `/v1/shield/cap/mint`,
`/v1/shield/cap/verify`, `/v1/tenant/me/agent-auth/revoke`; headers
`X-Agent-Token`, `X-Agent-DPoP`, `X-API-Key`, `X-User-Role`.

## 5. Security & backward compatibility

- The agent's private key is generated in memory and never serialized unless
  the caller asks (`to_pem`); `jwk` carries the public part only.
- Proofs are single use (random `jti`), bound to method and URL (scheme, host,
  path).
- `CapabilityVerifier` fails closed: transport errors and non-200s raise.
- The POC never replaces a tenant's approval or certificate mapping rules, uses
  its own tool names for the kill switch, and cleans up unless `--keep`.
- Additive package change: `py-modules` gains `shield_agent`.

## 6. Packaging & deploy

`packages/shield-py/pyproject.toml`: module added, extra `agent =
["cryptography>=42"]`. No server image changes.

## 7. Failure modes

Each scenario reports PASS / FAIL / SKIP with the reason; a missing server
setting is a FAIL that names the setting. Revocation propagation across servers
is handled with `--propagation-wait`.

## 8. Tests

- `tests/test_shield_agent.py`: proofs and thumbprints checked with the
  server's `core/dpop.py`; wrong method, URL, age and key fail; token refresh;
  approval and denial exceptions; unreachable Shield; delegation; revoke;
  verifier fails closed; bearer mode.
- `tests/test_agent_identity_poc.py`: the POC in `--local` mode, in a
  subprocess, all nine scenarios PASS, report written; it appends rather than
  replaces tenant rules.
