---
title: "Spec: agent identity parity, discovery, Cross App Access, IdP-bound principals, push approvals, flow rules"
layout: default
nav_order: 69
permalink: /spec-okta-parity-agent-identity/
description: "Shield governs the content plane of agentic tool calling; Okta governs the identity plane. This spec closes the five places where the identity plane's absence weakens Shield: agents Shield never sees, MCP connectors the IdP already authorized, agent principals the IdP already issued, approvers nobody notifies, and tool-to-tool flows nobody can express. Six scoped tasks, each opt-in."
---

# Spec: agent identity parity
Status: DRAFT, awaiting approval. No code written.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 0. Why, in one paragraph

Okta's agent story (Okta for AI Agents, Cross App Access, Auth0 for AI Agents,
Agent Gateway) is the identity plane: discover every agent from the OAuth grants
it makes, register it as an identity with an owner, authorize its MCP connectors
once through the IdP, broker its downstream credentials, push a human approval
to a phone, and audit which tool's output fed which tool's input. Shield is the
content plane: it judges what the prompt, the tool result and the response
contain. The two do not compete, but five things the identity plane provides are
things Shield today either cannot see or cannot express, and a buyer with Okta
will ask for each. This spec makes Shield the consumer of that identity plane
rather than a substitute for it.

**The five gaps, each confirmed against the code:**

| # | Gap | What exists today | Where |
|---|---|---|---|
| G1 | **Discovery stops at Shield's own door.** An agent that never calls Shield is invisible. | Shadow tracking records only callers of guarded endpoints, from two writers with two record shapes and no TTL. | `core/middleware.py:150-185`, `admin_app.py:416-481`, key `unregistered:{tenant_id}` |
| G2 | **No Cross App Access.** Shield cannot consume an IdP-authorized MCP connector, and Shield-guarded MCP servers cannot be authorized from the IdP console. | RFC 8693 exists only at Shield's own authorization server, exchanging an external id_token for a Shield token. Upstream MCP tokens are brokered once per route, never per user. | `api/routes_oauth.py:251-398`, `core/mcp_oauth.py`, `docs/spec-mcp-oauth-brokering.md` §5.3 and §10 |
| G3 | **The agent principal is Shield-asserted, not IdP-issued.** `agent_id` comes from the request body or `X-Agent-Key`; the registry gate only checks that the id exists. | Agent tokens and capabilities bind the `IdentityTuple` from a Shield-minted agent token. No registry field ties an agent to an IdP subject. | `core/identity_resolution.py:542`, `core/agent_tokens.py:312`, `core/capabilities.py:208-225`, `api/routes_agent_auth.py:294` |
| G4 | **Nobody is told an approval is pending.** | Approval requests are created and stored, and the approver discovers them by polling the portal. No `approval_*` webhook event exists. Approver identity is a header, method `asserted` unless SSO. | `api/routes_webhooks.py:46-55`, `api/routes_agentic_control_plane.py:151-157`, `storage/agentic_control_plane.py:159` |
| G5 | **No tool-to-tool flow rule.** "May Tool A's output feed Tool B?" cannot be written. | Taint tracking is clearance-gated only: the consuming agent's clearance against inherited tags. Source tool names are recorded but never consulted. | `guardrails/agentic/taint/taint_tracking.py:80-140`, `taint_store.py:22-70` |

One prerequisite defect blocks G3 for Okta specifically: no call site passes
`tenant_id` into `resolve_identity`, so the per-tenant role claim config is
unreachable and the role claim is effectively the Keycloak default
(`docs/spec-idp-role-claim-config.md` §1, decision D1). Task 1 below fixes it.

---

## 1. Problem & outcome

**For whom.** A tenant that runs Okta (or Entra, Auth0, Keycloak) as the
identity plane and Shield as the content plane, and wants one inventory, one
authorization decision per MCP connector, one agent principal, approvals that
reach a human, and a flow policy between tools.

**Observable success, per gap.**

1. **G1.** The governance inventory (`GET /v1/governance/agents`) lists agents
   discovered from the IdP's own logs and from a generic ingest feed, each with
   `discovered_via`, alongside agents Shield observed itself. The two shadow
   writers produce one record shape.
2. **G2.** A user's call through the MCP gateway to an upstream that advertises
   `urn:ietf:params:oauth:grant-profile:id-jag` obtains a per-user upstream token
   through the IdP with no consent screen, and Shield's own authorization server
   accepts an ID-JAG so an IdP admin can authorize a Shield-guarded MCP server
   once for a group.
3. **G3.** An agent presents an IdP-issued assertion to `POST /v1/shield/auth/agent-token`;
   Shield resolves the registry entry by (issuer, subject), and every downstream
   agent token, capability, audit row and CAEP event carries `idp_iss` and
   `idp_sub`. An inbound `session-revoked` for that IdP subject revokes the
   agent's instances.
4. **G4.** An approval request fires `approval_requested` to webhooks and SIEM,
   and, when the tenant configures a CIBA-capable IdP, a push to the approver's
   device; the recorded approver is the `sub` of the token the IdP returns,
   method `ciba`. Decisions fire `approval_decided`.
5. **G5.** A tool data policy can say which tools may or may not feed this one,
   and which sensitivity tags it may never receive; `data_taint_tracking`
   enforces it from the taint graph it already keeps.

**Non-goals, explicitly.**
- Being an IdP. Shield issues no user identities and hosts no directory.
- Discovering agents by network inspection or SaaS API crawling beyond the
  IdP log connector and the ingest endpoint. Okta's Secure Access Monitor
  browser plugin has no Shield equivalent here; the ingest endpoint is where
  such a signal would arrive.
- XAA for non-MCP upstreams (plain REST APIs). Same protocol, later spec.
- CIBA `push` delivery mode (Shield hosting a client notification endpoint).
  This spec ships `poll`; `ping` is a small follow-up.
- Automatic linking of `input_sources` between tool calls. The ids stay
  caller-supplied, as today; this spec only adds the rule that judges them.
- SCIM provisioning of agents, and Okta's ISPM AI-agent API, whose availability
  and license terms could not be verified from this environment. The connector
  uses the System Log API every Okta tenant has.

---

## 2. Plane & latency contract

| Task | Plane | Guard path? | Budget and justification |
|---|---|---|---|
| 1. `tenant_id` into `resolve_identity` | data | Yes, every guarded call. | Zero added I/O: the tenant is already on `request.state`; the 30 s cached config read already exists and is currently skipped. |
| 2. Discovery sources | admin | No. | Background poller on the admin plane; writes to `unregistered:{tenant}` exactly as the existing flusher does. Off hot path, no guarded-traffic impact. |
| 3. IdP-bound agent principal | data | Token issuance (`/auth/agent-token`), not `/guardrails/*` or `tools/call`. | One JWKS-cached signature verification per mint, the same cost `delegation.verify_user_token` pays today. Caps and `tools/call` carry two extra string claims; no added I/O. |
| 4. XAA resource server | data | `/oauth/token` only. | One JWKS verification plus one jti-replay `SET NX` per exchange. Not a guarded endpoint. |
| 5. XAA client in the MCP gateway | data | Yes: `tools/call` on a route in `xaa` mode. | First call per (user, route) pays two round trips (IdP token exchange, upstream jwt-bearer); the token is vaulted until expiry and refreshed in the background at the existing `refresh_margin_seconds()`, so steady state is the same one vault read the `auth_code` mode pays. Opt-in per route. |
| 6. Approval notifications and CIBA | admin | No. | The pending request is created on the guard path today, unchanged. The webhook fires through the existing fire-and-forget dispatcher; the CIBA initiation and polling run on an admin-plane background task. |
| 7. Flow rules | data | Yes: `tools/call` and `/v1/shield/tool/check` when `input_sources` is present. | The taint guardrail already reads the source records for the clearance check; the rule evaluation is a glob match over data already in hand. No added I/O. |

---

## 3. Data model

All keys are tenant-prefixed; `tenant_id` resolves from `X-API-Key` via
`core.auth.get_tenant_from_request` on the admin routes and from
`request.state.tenant_id` on the data plane, as today. No cross-tenant read
exists because no key omits the tenant.

### 3.1 Discovery (G1)

**Unified shadow record.** `unregistered:{tenant_id}` keeps its shape
`{"agents": {...}, "tools": {...}}`; each agent value becomes

```json
{"first_seen": 1726000000, "last_seen": 1726090000, "call_count": 12,
 "endpoints": ["/v1/shield/tool/check"], "roles": ["support"],
 "sources": [
   {"kind": "shield", "first_seen": 1726000000, "last_seen": 1726090000},
   {"kind": "idp:okta", "source_id": "okta-prod", "first_seen": 1725990000,
    "last_seen": 1726080000, "detail": {"app": "Claude", "client_id": "0oa…",
    "actor": "jane@acme.com", "scopes": ["okta.users.read"]}},
   {"kind": "ingest", "source_id": "casb", "first_seen": …, "detail": {…}}
 ]}
```

Both existing writers (`core/middleware.py:_flush_shadows_to_redis`,
`admin_app.py:_track_unregistered`) write this shape; a record without
`sources` is read as `[{"kind": "shield"}]` so nothing stored today changes
meaning. The key gains a TTL of `SHIELD_SHADOW_TTL_DAYS` (default 180) refreshed
on every write, so a dismissed-and-silent shadow ages out.

**Source config.** `shield:discovery:sources:{tenant_id}` → JSON list:

```json
[{"source_id": "okta-prod", "kind": "okta_syslog", "enabled": true,
  "org_url": "https://acme.okta.com",
  "token_ref": "shield://discovery-okta-prod",
  "poll_interval_s": 300, "page_limit": 200,
  "filter": "eventType eq \"app.oauth2.as.token.grant\" or eventType eq \"app.oauth2.token.grant\"",
  "created_at": …, "updated_at": …, "last_poll_at": …, "last_error": ""}]
```

The Okta API token lives in the secret vault under `token_ref`, never in the
record, the same rule the OAuth broker follows (`storage/mcp_oauth_store.py:1-25`).

**Cursor.** `shield:discovery:cursor:{tenant_id}:{source_id}` → the Okta
`after` cursor string (or the last `published` timestamp), no TTL.

**Poll lock.** `shield:discovery:lock:{tenant_id}:{source_id}` → `SET NX`
with TTL `poll_interval_s`, so two admin replicas never poll the same source
concurrently.

**Agent identity from a grant event.** The discovered agent id is the OAuth
client id from the event's `client.id` (or `target[type=App].id`), rendered as
`idp:{issuer_host}:{client_id}`; it fails the strict `_VALID_ID_RE` and is
adopted through the existing observed-shadow rule
(`api/routes_agents_registry.py:93-127`), stored byte-identical.

### 3.2 IdP-bound agent principal (G3)

Registry entry (`agents:{tenant_id}`) gains one optional field:

```json
"idp_binding": {"issuer": "https://acme.okta.com/oauth2/default",
                "subject": "0oa1b2c3d4",
                "kind": "client",          // client | user
                "bound_at": 1726000000, "bound_by": "jane@acme.com"}
```

Lookup index `shield:idp_binding:{tenant_id}` → HASH `"{issuer}\x1f{subject}"`
→ `agent_id`, rebuilt on every registry write, so mint resolves in one `HGET`.

Agent token claims (`core/agent_tokens.py:mint_agent_token`) gain `idp_iss`,
`idp_sub` (omitted when unbound, for byte-compat with the existing omission
rule). Capability claims (`core/capabilities.py:mint_cap`) carry the same two.
`audit_fields()` and the `agent_auth_stats` recent entry carry them too.

Inbound CAEP: `core/caep.py:_subject_ids()` learns the `iss`+`sub` subject
format and maps it through the index above to `agent_id`, then revokes all
instances of that agent via the existing revocation store.

### 3.3 XAA, both directions (G2)

**IdP client config** (Shield as a confidential client at the IdP):
`shield:xaa:idp:{tenant_id}` →

```json
{"issuer": "https://acme.okta.com/oauth2/default",
 "token_endpoint": "…/v1/token",          // discovered, cached
 "client_id": "0oaShield…",
 "client_secret_ref": "shield://xaa-idp-client",
 "subject_token_source": "delegation"}     // delegation (X-On-Behalf-Of) | oidc_session
```

**Per-user upstream token** for a route in `xaa` mode:
`mcp_oauth:{tenant_id}:{route}:users:{sub_hash}` (sub_hash = sha256 of
`user_sub`, first 32 hex) →

```json
{"mode": "xaa", "user_sub": "…", "resource_as": "https://mcp.vendor.com",
 "access_token_ref": "shield://oauth-{route}-u-{sub_hash}-access",
 "refresh_token_ref": "shield://oauth-{route}-u-{sub_hash}-refresh",
 "expires_at": 1726003600, "scope": "…", "status": "connected", "last_error": ""}
```

TTL = `expires_at` + 7 days, so an idle user's record ages out. The route's
broker record (`mcp_oauth:{tenant_id}:{route}`) gains `mode: "xaa"` and the
credential mode registry (`core/mcp_credentials.py:37-54`) gains
`xaa (9)`, an `INTERACTIVE_MODES` member.

**Shield as resource authorization server.** Authorization server metadata
(`core/oauth/authz_server.py:218`) adds
`"authorization_grant_profiles_supported": ["urn:ietf:params:oauth:grant-profile:id-jag"]`
and `urn:ietf:params:oauth:grant-type:jwt-bearer` to `grant_types_supported`.
Replay guard `shield:idjag:jti:{jti}` → `SET NX` with TTL = the assertion's
remaining lifetime. Trusted issuers are the tenant's OIDC providers
(`shield:oidc:providers:{tenant_id}`), no new allowlist.

### 3.4 Approvals (G4)

`api/routes_webhooks.py:VALID_EVENTS` gains `approval_requested`,
`approval_decided`, `approval_expired`, `agent_discovered`. Payloads:

```json
{"request_id": "apr_…", "tool_name": "…", "agent_key": "…", "session_id": "…",
 "params_hash": "…", "rule_id": "…", "required_approvals": 1, "expires_at": …,
 "approve_url": "https://portal/…/approvals/apr_…"}
```

`approval_decided` adds `{"decision": "approved"|"denied", "approver": {"sub", "method"}}`.

CIBA config `shield:ciba:{tenant_id}` →

```json
{"issuer": "…", "backchannel_authentication_endpoint": "…/v1/bc/authorize",
 "token_endpoint": "…/v1/token", "client_id": "…",
 "client_secret_ref": "shield://ciba-client",
 "delivery": "poll", "approver_hint": "login_hint",
 "approvers": {"default": ["sec-oncall@acme.com"], "by_rule": {"rule-42": ["cfo@acme.com"]}}}
```

Each approval request (`agentic_cp:approvals:{tenant_id}` item) gains

```json
"ciba": {"auth_req_id": "…", "started_at": …, "expires_in": 300,
         "interval": 5, "status": "pending"|"approved"|"denied"|"expired",
         "last_poll_at": …}
```

Poll lock `shield:ciba:lock:{tenant_id}` → `SET NX`, TTL 30 s.

### 3.5 Flow rules (G5)

`ToolDataPolicy` and `GlobalDataPolicy` (`api/routes_data_policies.py`) gain

```python
class FlowRule(BaseModel):
    allow_from: List[str] = []      # tool-name globs; empty = any
    deny_from: List[str] = []       # tool-name globs; wins over allow_from
    deny_tags: List[str] = []       # sensitivity tags this tool may never receive
    action: str = "block"           # block | warn
```

stored under `"flow"` on the policy. No new key: `data_policies:{tenant_id}`
already carries the policy, and `guardrails/agentic/tool/payload_risk._load_data_policies`
already returns it per tool, global layer first.

The taint record already stores `tool_name` per `tool_call_id`
(`taint_store.py:41-47`); the guardrail reads it with `get_taint_labels`, which
it already calls for the flow graph.

---

## 4. API / interface

Auth on every endpoint below is the tenant `X-API-Key` (or the SSO'd human for
`created_by` fields), exactly as the sibling routes. Unless stated, a route is
mounted where its sibling is mounted today.

**Task 1.** No API change. `resolve_identity(request, …, tenant_id=…)` is
called with the tenant at the five call sites the identity spec lists.

**Task 2, discovery (admin plane, `/v1/tenant/me/discovery`).**

| Method | Path | Body / result |
|---|---|---|
| GET | `/sources` | `{sources: [config minus token_ref value, plus last_poll_at, last_error]}` |
| POST | `/sources` | `{source_id, kind: "okta_syslog", org_url, api_token, poll_interval_s?, filter?}` → stores the token in the vault, returns the record. 422 without a configured vault. |
| DELETE | `/sources/{source_id}` | removes config, cursor, vault entry |
| POST | `/sources/{source_id}/poll` | runs one poll now; returns `{events: n, agents_seen: n, new_agents: [...]}` |
| POST | `/ingest` | `{source_id, agents: [{agent_id, seen_at, detail}]}`, at most 1000 per call; merges into the shadow record with `kind: "ingest"`. For a SIEM, a CASB, or a CSV export. |

`GET /v1/governance/agents` rows gain `discovered_via: ["shield", "idp:okta", "ingest"]`.
The portal's Unregistered card shows the sources and the IdP `detail.app`.

**Task 3, IdP-bound principal.**

- `PUT /v1/agents/registry/{agent_id}` accepts `idp_binding` (`kind`, `issuer`,
  `subject`). `issuer` must be one of the tenant's OIDC providers; 422 otherwise.
- `POST /v1/shield/auth/agent-token` accepts `Authorization: Bearer <IdP-issued JWT>`
  as an alternative to `agent_id` in the body. Shield verifies it against the
  provider's JWKS (`core/oauth/oidc_client.validate_id_token` rules: `iss`,
  `aud` = Shield's registered client id at that IdP or the value in
  `idp_binding.audience`, `exp`, `iat`, `sub`), resolves `agent_id` through the
  binding index, refuses with 403 `agent_not_bound` if no entry matches, and
  mints the agent token with `idp_iss` and `idp_sub`. Body `agent_id`, when also
  present, must equal the resolved one or the call is refused with 409.
- `POST /v1/shield/ssf/events` (existing) accepts subjects of format `iss_sub`.

**Task 4, XAA resource server.** `POST /oauth/token` accepts
`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` with `assertion=<ID-JAG>`.
Validation, in order: header `typ` is `oauth-id-jag+jwt`; `iss` is a configured
OIDC provider and the signature verifies against its JWKS; `aud` equals Shield's
issuer identifier; `client_id` equals the authenticated client (the caller's
`client_id` from DCR or the tenant key's client mapping); `exp`, `iat`, `jti`
present and `jti` unseen; `scope` and `resource` intersected with what the client
is registered for. Success returns Shield's normal access token shape with
`issued_token_type: urn:ietf:params:oauth:token-type:access_token` and the
user's `sub` bound as `user_sub`. The Shield MCP server and any guarded MCP
server accept that token as they accept any Shield access token today.

**Task 5, XAA client (admin config plus gateway behaviour).**

- `PUT /v1/tenant/me/xaa/idp` → `{issuer, client_id, client_secret, subject_token_source}`;
  discovers `token_endpoint` from `{issuer}/.well-known/openid-configuration`,
  vaults the secret, returns the config without it.
- `POST /v1/tenant/me/mcp/servers/{route}/oauth/connect` accepts
  `{"mode": "xaa"}`; discovery (`core/mcp_oauth.discover`) must find
  `urn:ietf:params:oauth:grant-profile:id-jag` in the upstream authorization
  server's `authorization_grant_profiles_supported`, else 422 `xaa_unsupported`.
- On `tools/call` for an `xaa` route: the user's subject token comes from the
  verified delegation (`X-On-Behalf-Of`, `core/delegation.py`) or the OIDC
  session; no verified user means 401 `xaa_subject_required` before any upstream
  contact. Shield then performs the token exchange at the IdP
  (`grant_type=…:token-exchange`, `requested_token_type=…:id-jag`,
  `audience=<upstream RAS issuer>`, `subject_token`, `subject_token_type=…:id_token`,
  `scope`), then `jwt-bearer` at the upstream token endpoint with the ID-JAG as
  `assertion`, vaults the result per user, and forwards the call with that
  bearer. The `shield` block of the response carries `credential_mode: "xaa"`.

**Task 6, approvals.**

- Webhook and SIEM events as in 3.4, dispatched from
  `storage/agentic_control_plane.create_approval_request` (requested),
  `update_approval_request` (decided) and the expiry sweep (expired).
- `PUT /v1/tenant/me/approvals/ciba` → config as in 3.4; secret vaulted.
- When CIBA is configured and a request is created, the admin-plane task calls
  the backchannel endpoint with `client_id`, `scope=openid`, `login_hint` =
  the approver for the rule, `binding_message` = `"{tool_name} {params_hash[:8]}"`,
  and `requested_expiry` = min(`request_ttl_seconds`, 600); stores `auth_req_id`;
  polls the token endpoint with `grant_type=urn:openid:params:grant-type:ciba`
  every `interval` seconds; on success verifies the returned id_token, records
  the approval with `approver.sub` = its `sub`, `method: "ciba"`, and mints the
  grant exactly as the portal path does (`_mint_request_grant`). `access_denied`
  denies the request; `expired_token` expires it.
- The portal path is unchanged and remains available alongside.

**Task 7, flow rules.** `POST /v1/data-policies/tools/{tool}/policy` and
`/global/policy` accept `flow`. Validation: globs compile, `action` in
`{block, warn}`. `data_taint_tracking` evaluates, when `input_sources` is
present: for each source record, `deny_from` match → violation; `allow_from`
non-empty and no match → violation; inherited tag in `deny_tags` → violation.
Global `flow` applies beneath the tool's, same precedence as every other field.
Result details gain `flow_violations: [{source_tool, source_tool_call_id, rule, tags}]`.

---

## 5. Security & backward compatibility

Every task is opt-in. Nothing changes for a tenant that configures none of it.

| Task | Default | Escape hatch | Authz and threat notes |
|---|---|---|---|
| 1 | Behaviour-preserving: with no per-tenant config the resolved claim is the same env default as today. A tenant that already saved a role-binding config will start being honoured, which is the documented intent of that config. | `SHIELD_ROLE_BINDING=off` already exists. | Migration note: "your saved role claim config now applies". |
| 2 | Off until a source or an ingest call exists. | `SHIELD_DISCOVERY_SOURCES=off` stops the poller and refuses ingest. | Okta token: read-only System Log scope, vaulted, never echoed. Ingest is tenant-key authenticated and rate-limited to 1000 agents per call; it can only add shadow rows, never register or block. A hostile ingest can spam the inventory, not escalate. |
| 3 | Off until a registry entry carries `idp_binding`. Unbound agents mint exactly as today. | `SHIELD_IDP_AGENT_BINDING=off` ignores bindings and refuses IdP-assertion mints. | The assertion is verified against the provider's JWKS with `iss` allowlisted to configured providers and `aud` pinned; a token for another audience is refused. A bound agent can no longer mint with a bare `agent_id` when `SHIELD_IDP_AGENT_BINDING=enforce` (default `prefer`, which allows both and records the source). |
| 4 | Off: the grant type is refused until an OIDC provider exists for the tenant, and metadata advertises the profile only then. | `SHIELD_XAA=off` refuses the grant type and hides the metadata. | Validates `typ`, `iss`, signature, `aud` = Shield issuer (audience injection), `client_id` = authenticated client, `jti` replay, lifetime. Only confidential clients (a registered `client_secret` or private_key_jwt); a public client gets 400 `unauthorized_client`, per the draft's recommendation. |
| 5 | Off until a route is connected in `xaa` mode. | `SHIELD_XAA=off`; a route can be switched back to `auth_code`. | The user's subject token is only ever the verified delegation or OIDC session token; the header path (`X-User-Role`) can never trigger an exchange. Per-user tokens are vault-bound to the upstream host, as static credentials are today. A leaked Shield IdP client secret lets an attacker mint ID-JAGs for users they can already present tokens for, so the secret has the same rotation posture as the OAuth broker client secret. |
| 6 | Webhook events fire only to subscriptions that list them (the existing per-subscription `events` filter). CIBA is off until configured. | `SHIELD_CIBA=off`. | The approver identity is the IdP-verified `sub` from the CIBA token, which is stronger than the current `X-Approver-Sub` header. `binding_message` carries the tool name and a hash prefix, never parameter values, so nothing sensitive reaches a phone. The grant minted on CIBA success is the same params-hash-bound grant the portal mints. |
| 7 | Off until a policy carries `flow`. With no `input_sources` in the call, nothing runs, as today. | `SHIELD_FLOW_RULES=off`. | Fail-closed only where a rule exists and a source is named; an unknown source tool (no taint record) is treated as `source_tool: null` and matches `deny_from: ["*"]` only, so a policy can choose to refuse unrecorded lineage. |

No default changes to existing guardrail actions. No new external egress
without tenant configuration: the Okta poll, the IdP token endpoint, and the
CIBA endpoint are all URLs the tenant supplied, validated through
`validate_outbound_url` like webhooks.

---

## 6. Packaging & deploy

- **No new pip dependencies.** `httpx` and `PyJWT[crypto]` cover JWKS, token
  exchange, System Log paging and CIBA.
- **New modules and the admin image.** `core/discovery/` (connector, poller),
  `storage/discovery_store.py`, `core/ciba.py`, `api/routes_discovery.py`,
  `api/routes_xaa_admin.py` are imported by `admin_app.py` at boot and go into
  `Dockerfile.admin`'s COPY list in the same PR; `tests/test_admin_dockerfile_imports.py`
  catches an omission. `core/xaa.py` (ID-JAG verify and client exchange) is
  imported by `api/routes_oauth.py` and `core/mcp_credentials.py`; whether the
  admin image needs it depends on which of those it copies, and the guard test
  decides. New admin routers follow the `if _router is not None:` guarded-import
  pattern (`admin_app.py:1042-1092`).
- **Background tasks on the admin plane.** The discovery poller and the CIBA
  poller start from `admin_app.py`'s lifespan, each guarded by its env flag and
  a Redis lock, so multiple admin replicas do not double-poll.
- **Env flags introduced.** `SHIELD_DISCOVERY_SOURCES`, `SHIELD_SHADOW_TTL_DAYS`,
  `SHIELD_IDP_AGENT_BINDING` (`off|prefer|enforce`), `SHIELD_XAA`, `SHIELD_CIBA`,
  `SHIELD_FLOW_RULES`. All read live.
- **Images to rebuild.** `Dockerfile` (data plane) for tasks 1, 3, 4, 5, 7;
  `Dockerfile.admin` for 2, 3 (registry field and index), 5 (config route), 6.
- **Docs in the series.** `docs/non-human-identity.md` and
  `docs/idp-interoperability.md` gain the binding and XAA sections;
  `docs/hitl-approvals.md` gains notifications and CIBA;
  `docs/tool-data-policies.md` gains `flow`; `docs/agent-governance.md` gains
  discovery sources. `API_SPEC.md` is not the home of these routes today and
  stays out.

---

## 7. Failure modes & edge cases

| Case | Behaviour | Open or closed |
|---|---|---|
| Okta System Log unreachable or 401 | Poll skipped, `last_error` set, cursor unchanged, webhook `discovery_source_error` once per hour, inventory unaffected. | Open, by design: discovery is visibility, never enforcement. |
| System Log page larger than `page_limit`, or a burst of thousands of grants | Pages followed up to 10 per poll (2000 events); the cursor advances only past processed pages; the rest waits for the next poll. | n/a |
| Two admin replicas | `SET NX` lock per source and per CIBA tenant; the loser skips. | n/a |
| Ingest with an `agent_id` already registered | Recorded as a `sources` entry on the registered agent's governance row (`discovered_via`), not as a shadow. | n/a |
| IdP assertion at agent-token mint: unknown issuer, wrong audience, expired, or no binding | 403 with a specific reason, `token_rejected` recorded in `agent_auth_stats`, nothing minted. | Closed |
| IdP JWKS fetch fails during mint | 503 `idp_unavailable`; the bare `agent_id` path stays available in `prefer` mode. | Closed for the assertion path |
| ID-JAG at `/oauth/token` replayed | Second use refused, `cap_replay`-style audit row. | Closed |
| ID-JAG `aud` is another server's issuer | Refused: audience injection is exactly what the check exists for. | Closed |
| XAA exchange fails at the IdP (user not in the authorized group) | 403 to the caller with the IdP's error code, no upstream contact; recorded in `mcp_oauth_*` audit. | Closed |
| Upstream token expires mid-session | The background refresh at `refresh_margin_seconds()` renews with the refresh token when the upstream issued one; otherwise the next call re-runs the exchange (the ID-JAG itself is single-use, a fresh one is minted). | n/a |
| No verified user on an `xaa` route | 401 before any upstream contact. A route in `xaa` mode with `SHIELD_DELEGATION=off` is a misconfiguration the connect endpoint refuses with 422. | Closed |
| CIBA endpoint unreachable | Request stays `pending`; the portal path still works; `approval_requested` webhook still fired. | Open for delivery, closed for the action |
| CIBA `slow_down` | Interval doubled, per the spec. | n/a |
| CIBA success but the returned `sub` is not a listed approver for the rule | Refused, recorded as `approval_rejected_wrong_approver`; the request stays pending. | Closed |
| Request expires while a CIBA poll is in flight | The poll result is discarded; `approval_expired` fires. | Closed |
| Flow rule names a tool whose taint record is gone (TTL 3600) | Source is `null`; only `deny_from: ["*"]` matches. Details say `source_unknown: true`. | Policy's choice |
| Redis down | Discovery and CIBA pollers skip the tick; the binding index falls back to a registry scan (one `agents:{tenant}` read, which the mint already performs); XAA per-user records fall back to a fresh exchange; flow rules see no taint and behave as today. | Open, matching each subsystem's existing posture |
| Empty or null `input_sources` | Nothing runs, as today. | n/a |

---

## 8. Test plan (Definition of Done)

Existing suites that must stay green: `tests/test_identity_resolution*.py`,
`tests/test_agent_auth*.py`, `tests/test_capabilities*.py`, `tests/test_oauth_*.py`,
`tests/test_mcp_oauth*.py`, `tests/test_mcp_credential*.py`, `tests/test_approvals*.py`,
`tests/test_agentic_control_plane*.py`, `tests/test_taint_tracking.py`,
`tests/test_taint_armed.py`, `tests/test_global_data_policy.py`,
`tests/test_admin_dockerfile_imports.py`, `tests/test_caep*.py`, `tests/test_webhooks*.py`.

**Task 1.** A tenant with a saved `role_claim` of `["https://acme/roles"]`
resolves roles from that claim on each of the five call sites; with no saved
config the resolved role is byte-identical to today; `SHIELD_ROLE_BINDING=off`
still wins.

**Task 2.** Unified record: both writers produce the same shape from one
fixture; a legacy record without `sources` reads as `[{"kind": "shield"}]`.
Okta connector against a recorded System Log fixture: two grant events for one
client id produce one shadow with `call_count` 2 and `detail.app`; the cursor
advances; a 401 sets `last_error` and leaves the cursor. Ingest: 1001 agents
is 400; an already-registered id lands on the governance row's
`discovered_via`. Lock: a second poll while the lock is held is a no-op.
Governance row carries `discovered_via`. TTL is set on every write.

**Task 3.** Binding index rebuilt on write; mint with a valid assertion resolves
the bound agent and the minted token and a subsequently minted cap both carry
`idp_iss`/`idp_sub`; wrong `aud`, unknown `iss`, expired, and unbound `sub` each
refuse with their reason; body `agent_id` disagreeing with the resolution is
409; `enforce` refuses a bare-id mint for a bound agent, `prefer` allows it and
records `agent_source`; an inbound SSF `session-revoked` for `iss_sub` revokes
the agent's instances and a later cap verify fails with `instance revoked`.

**Task 4.** Metadata advertises the profile only when a provider exists and
`SHIELD_XAA` is on; a well-formed ID-JAG yields an access token bound to its
`sub`; each of `typ`, `aud`, `client_id`, `jti` replay, expiry, unknown issuer,
and public client refuses with the draft's error code; the Shield MCP server
accepts the resulting token.

**Task 5.** Against a fake IdP and fake upstream AS (httpx `MockTransport`):
first call performs exchange then jwt-bearer and vaults per user; second call
performs neither; a second user gets a separate token; no verified user is 401
with no upstream contact; IdP `access_denied` is 403 with no upstream contact;
`connect` refuses an upstream without the grant profile; `SHIELD_XAA=off`
refuses at connect and at call time; the route's `auth_code` behaviour is
untouched when mode is not `xaa`.

**Task 6.** `approval_requested` reaches a subscription that lists it and not
one that does not, with no parameter values in the payload; `approval_decided`
and `approval_expired` fire once each; CIBA happy path records `method: "ciba"`
and the IdP `sub`, and mints a grant that `verify_grant` accepts for the same
`params_hash`; `slow_down` doubles the interval; wrong-approver `sub` is
refused; expiry during poll discards the result; the portal approve path is
unchanged; the poller lock prevents double polling.

**Task 7.** `deny_from` glob blocks, `allow_from` empty allows any, `allow_from`
non-empty blocks an unlisted source, `deny_tags` blocks on an inherited tag,
`action: warn` warns, global beneath tool, unknown source matches only `["*"]`,
no `input_sources` runs nothing, `SHIELD_FLOW_RULES=off` runs nothing; API
rejects a bad glob and a bad action; details carry `flow_violations`.

**Gate.** Full suite `python -m pytest tests -q` green in a clean venv
(`python -m venv /tmp/x && /tmp/x/bin/pip install -r requirements-test.txt`),
and the `pytest` job in `.github/workflows/test.yml` passes.

---

## 9. Task breakdown, in order

| PR | Title | Files | Size |
|---|---|---|---|
| 1 | Pass `tenant_id` into `resolve_identity` at its five call sites (unblocks IdP role claims) | `core/identity_resolution.py`, the five routes, tests | Small |
| 2 | Discovery sources: unified shadow shape with `sources` and TTL, ingest endpoint, Okta System Log connector, governance `discovered_via` | `core/middleware.py`, `admin_app.py`, `core/discovery/`, `storage/discovery_store.py`, `api/routes_discovery.py`, `api/routes_governance.py`, `static/tenant.html`, `Dockerfile.admin`, tests | Medium; may split 2a (shape + ingest) and 2b (Okta connector) |
| 3 | IdP-bound agent principal: `idp_binding`, index, assertion-based mint, claims through caps and audit, CAEP subject mapping | `api/routes_agents_registry.py`, `api/routes_agent_auth.py`, `core/agent_tokens.py`, `core/capabilities.py`, `core/caep.py`, tests | Medium |
| 4 | XAA resource server: jwt-bearer with ID-JAG at `/oauth/token`, metadata, replay guard | `core/xaa.py`, `api/routes_oauth.py`, `core/oauth/authz_server.py`, tests | Small |
| 5 | XAA client: credential mode `xaa`, IdP client config, per-user upstream tokens in the MCP gateway | `core/xaa.py`, `core/mcp_credentials.py`, `core/mcp_oauth.py`, `api/routes_mcp_admin.py`, `api/routes_xaa_admin.py`, `Dockerfile.admin`, tests | Medium |
| 6 | Approval notifications (webhook and SIEM events) and CIBA push approvals with poll delivery | `api/routes_webhooks.py`, `storage/agentic_control_plane.py`, `core/ciba.py`, `api/routes_agentic_control_plane.py`, `admin_app.py` lifespan, `Dockerfile.admin`, tests | Medium; may split 6a (events) and 6b (CIBA) |
| 7 | Tool-to-tool flow rules on data policies, enforced by `data_taint_tracking` | `api/routes_data_policies.py`, `guardrails/agentic/taint/taint_tracking.py`, `static/tenant.html`, tests | Small |
| 8 | Docs | five docs named in §6 | Small |

Dependencies: 3 needs 1 for Okta role claims to resolve; 5 needs 4 only for
the round-trip test (a Shield-guarded upstream), not for the client itself; 6b
needs 6a; everything else is independent.

---

## 10. Open decisions for the approver

1. **Okta discovery source.** This spec uses the System Log API, which every
   Okta tenant has. If you have access to Okta's ISPM AI-agent inventory API
   and its terms, a second connector kind (`okta_ispm`) is a small addition to
   task 2b, and would carry Okta's own ownership and risk fields.
2. **`SHIELD_IDP_AGENT_BINDING` default.** `prefer` (both paths allowed, source
   recorded) is proposed so no bound agent breaks on upgrade. `enforce` is the
   secure end state and could be the default for new tenants only.
3. **XAA client subject source.** Delegation (`X-On-Behalf-Of`) is proposed
   because it is verified per call. If your deployments run the OIDC portal
   session as the user context instead, say so and task 5 reads from it first.
4. **CIBA delivery.** `poll` ships first. `ping` needs Shield to expose a
   client notification endpoint on the admin plane; small, but a new inbound
   surface, so it is deferred until asked for.
5. **Flow rule default when lineage is unknown.** Proposed: unknown sources
   match only `deny_from: ["*"]`, so a tenant opts into refusing unrecorded
   lineage. The stricter alternative, treating unknown as denied whenever any
   `allow_from` is set, is one line if you want it.
