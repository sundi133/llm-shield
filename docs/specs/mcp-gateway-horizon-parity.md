# Spec: MCP gateway parity with Prefect Horizon

Status: DRAFT, awaiting approval. Program spec: it sets scope, order and the
shape of each phase. **Each phase gets its own full spec (docs/spec-template.md)
and approval before any code**, because each one changes identity, data model or
the guard path.

Sources: Horizon's documentation (docs.horizon.prefect.io, the pages on
authorization, external authentication, remix, data handling, observability,
the MCP registry, networking and plans) and its product page, read 2026-10-04;
Shield's code on `feat/tenant-enforce-mode` the same day.

## 1. Problem & outcome

Prefect Horizon is the MCP platform from the makers of FastMCP. Enterprise
buyers evaluating Shield's MCP gateway will hold it up against Horizon's
gateway, so the comparison has to be answered feature by feature.

The two products overlap in the **gateway** and differ elsewhere: Horizon also
**hosts** MCP servers (build from Git, previews, rollback, custom domains), while
Shield goes much deeper on **what a call may do and what a result may contain**
(content guardrails, injection detection, tool policies, flow control, kill
switch, tamper-evident audit, SIEM, a self-hosted gateway).

Outcome: Shield matches Horizon on every gateway and governance capability a
buyer checks, keeps its security lead, and states plainly that hosting is out
of scope (customers run servers anywhere and register them).

### Gap matrix (verified on both sides)

| Area | Horizon | Shield today | Gap |
|---|---|---|---|
| **Who is calling** | Every request is an authenticated **user or service account** (bearer credential); SSO via SAML/OIDC (WorkOS), SCIM directory sync, members, teams; personal and service-account API keys with rotation | Tenant API key identifies the **tenant**; agent and role come from `X-Agent-Key` / `X-User-Role` headers the caller sets itself. Shield can act as an OAuth server for MCP clients (dynamic registration, JWT with tenant and subject), but the role is still not derived from it. Verified identity is specced (`docs/spec-mcp-verified-identity.md`), not built | **Large.** Every grant below is only as strong as this |
| **Server access** | Org roles (admin, member, resource-user); server roles (admin, editor, viewer; custom on Enterprise); team grants; server default role; cross-org blocked | Tenant isolation; servers are tenant-wide; no per-server roles or team grants | **Medium** |
| **Capability policy** | Tools, **resources and prompts**; default permissions by role plus per-capability overrides; uncovered capabilities denied once a policy exists; hidden from lists; 401 / 403 / 404 (concealment) | Tools: role-to-tool allowlist (Agent Registry), tools/list filtered by role, server floor (allow/deny), kill switch. **Resources: content DLP-checked but not access-controlled. Prompts: passed through.** Errors as JSON-RPC | **Medium.** Resources and prompts are the hole |
| **Upstream credentials** | **Per-user** OAuth (each user authorizes; tokens refreshed per user), **per-user** API-key headers, or a shared key; delegated authorization into hosted servers; client never sees the provider token. Credential exchange **fails open** | Per-route (shared) only: OAuth broker (now including Google), static headers, client credentials, device code, GitHub App, gateway-signed capability; client never sees the token; vault-bound to the destination host | **Large: per-user.** Shared-only means every user acts as one account |
| **Composition** | **Remix**: one curated endpoint from selected capabilities across servers; namespacing; description overrides; its own access policy; partial lists when a backend is down; logs show which backend served each call | None | **Medium** |
| **Registry** | Publishes an MCP Registry catalog URL for GitHub Copilot ("Allow all" / "Registry only"); discovery only | None (AI BOM inventories servers, but there is no registry endpoint) | **Small** |
| **Observability** | Request log (method, tool, actor, client, status, latency, payloads with per-project toggles, plugin decisions); usage (calls, unique actors, error rate, p95, by actor and tool); duration p50/p95/p99; 3 days (30 on Enterprise); REST API. No SIEM, OTel or webhooks | Decision audit (tamper-evident), telemetry, guardrail metrics, SIEM and webhook alerts (`check_unavailable` and others). No per-server usage view by actor and tool with latency percentiles | **Small to medium** (views and metrics, not plumbing) |
| **Data protection** | Experimental response-only PII redaction (auto detection plus up to 10 regexes), block or redact, fails closed; "not a compliance control"; no injection detection | Deterministic DLP floor plus model-judged sanitization on results and resources; injection scanning of results and tool descriptions; tool policies with a fail-safe choice; cross-app flow control; runtime profiles; monitor then enforce | **Shield leads.** Keep and say so |
| **Networking** | Static egress addresses documented | Not documented | **Small** (operations and docs) |
| **Hosting** | Build from GitHub or upload, preview deployments, rollback, custom domains, encrypted env vars, compute and limits | None by design: customers run servers anywhere and register them (`docs/mcp-hosting-upstreams.md`) | **Non-goal** |
| **Self-hosting** | Not documented | Self-hosted gateway enforcing through the hosted Shield; on-premises deployment | **Shield leads** |

### Non-goals
- **Hosting MCP servers** (builds, previews, rollback, custom domains, compute).
  Shield governs servers wherever they run. Customers can host on Horizon, Cloud
  Run or their own platform and register the endpoint; the hosting guide covers
  how.
- Horizon's **Agents** pillar (end-user agent interfaces).
- Copying Horizon's **fail-open** credential exchange: Shield fails closed when a
  per-user credential is missing (phase 3).

## 2. Plane & latency contract (all phases)

- Identity, roles, grants, registry and analytics configuration live on the
  **admin plane**.
- The **data plane** gains reads on the guard path (`tools/call`, `tools/list`,
  `resources/*`, `prompts/*` through `/gateway/{route}/mcp`). Budget for the
  whole program: **no new network round trip per call in the steady state.**
  - Identity: local JWT verification against cached keys.
  - Grants and capability policy: the route document and one tenant document,
    cached with the existing TTLs (the same pattern as tenant config).
  - Per-user credentials: one vault read, replacing the current per-route one.
  - Composition: `tools/list` fans out to backends (already per route);
    `tools/call` goes to exactly one backend.
- Each phase's spec states its own measured budget before code.

## 3. Phases

Ordered by dependency and value. Each line is the outcome its spec must deliver.

### Phase 1: Verified identity at the gateway (prerequisite)
Adopt and finish `docs/spec-mcp-verified-identity.md`, extended to people:
- every gateway request resolves to a **user or service account** of the tenant,
  from a verified credential (Shield-issued OAuth access token for MCP clients
  such as Claude connectors and Cursor, or a personal / service-account API
  key), never from `X-User-Role`;
- **SSO**: OIDC first (Okta, Entra ID, Google Workspace), SAML second; group
  claims map to Shield roles; **SCIM** deprovisioning (later in the phase);
- personal and service-account **API keys** with rotation and revocation;
- header-asserted identity remains only behind an explicit tenant setting, for
  migration, and the audit records `role_source` (already partly there).

### Phase 2: Server access and capability policy
- Per-server roles (admin, editor, viewer, plus custom), team and user grants,
  and a server default role.
- **Capability policy for tools, resources and prompts**: defaults by role plus
  per-capability overrides; once a policy exists, uncovered capabilities are
  denied; denied capabilities are **hidden** from list responses and refused on
  use.
- Close the current holes: `resources/read` and `prompts/get` go through the
  same access check as `tools/call`; `prompts/get` results go through the
  injection screen (the existing follow-up).
- Clear denials: authentication failure, access denied and (optionally)
  concealment are distinguishable to clients, matching Horizon's 401 / 403 /
  404 split.
- The existing role-to-tool allowlist and server floor keep working; this adds
  to them.

### Phase 3: Per-user upstream credentials
- A route chooses **shared** (today) or **per user**.
- Per-user OAuth: each user authorizes once ("Connect your account"); tokens are
  stored per tenant, route and user, refreshed by the existing broker, bound to
  the upstream host in the vault (the binding fixed in PR #467).
- Per-user header credentials: each user enters their own values for the
  headers the route declares.
- **Fails closed**: a call by a user who has not connected gets a clear
  "connect your account" error with the link, never the shared or no credential.
- Depends on phase 1 (a verified user to key the token by).

### Phase 4: Composite servers
- A composite route publishes chosen tools, resources and prompts from several
  routes as one endpoint.
- Namespaced names, optional description overrides, its own access policy and
  tool policies, partial list results when a backend is down, and audit entries
  naming the backend that served each call.
- New capabilities upstream are not exposed until added (the same rule as
  Horizon's, and the safer one).

### Phase 5: MCP Registry endpoint
- Publish a tenant catalog of selected routes in the MCP Registry format at an
  unguessable, regenerable URL, for GitHub Copilot and other registry clients.
- Discovery only: access is still decided at the gateway.

### Phase 6: Usage and request observability
- Per server: calls, unique actors, error rate and p50 / p95 / p99 latency, by
  tool and by actor; a request log with method, tool, actor, client, status,
  latency and Shield's decision.
- Payload capture is **off by default** and, when on, stores the redacted form
  (unlike Horizon, which stores raw payloads by default with indefinite
  retention). Retention by plan; export through the existing SIEM path.
- Built on the existing metrics and decision-audit stores, written off the
  guard path.

### Phase 7: Operations and documentation
- Publish the hosted gateway's static egress addresses (or document that there
  are none and recommend secret headers).
- A limits page (timeouts, payload sizes, session lifetimes) and a
  Horizon-to-Shield comparison page for buyers.

## 4. Data model (direction, settled per phase)

Proposed key families, each to be confirmed in its phase spec:

| Phase | Proposal |
|---|---|
| 1 | `principal:{tenant}:{id}` (user or service account, groups, status); `apikey:{hash}` gains `principal_id`; `sso:{tenant}` (IdP configuration); group-to-role map on the tenant document |
| 2 | `mcp_gateway:upstream:{tenant}:{route}` gains `access` (default role, grants) and `capability_policy`; teams at `team:{tenant}:{id}` |
| 3 | Broker records and vault refs keyed per user: `mcp_oauth:{tenant}:{route}:{principal}`, refs `oauth-{route}-{principal}-access`; route gains `credential_scope: shared \| per_user` |
| 4 | A composite is a route with `transport: composite` and `members: [{route, capability, name, description}]` |
| 5 | `mcp_registry:{tenant}` (slug, selected routes, published at) |
| 6 | Existing metrics and decision-audit keys gain `principal`, `client` and `latency_ms` |

Tenant scoping is unchanged: every key carries the tenant, resolved from the
verified credential.

## 5. Security & backward compatibility

- **Nothing changes for an existing tenant until it opts in.** Header-asserted
  identity keeps working by default in phase 1; capability policies apply only
  once defined (phase 2, like Horizon); routes stay shared until switched
  (phase 3).
- Defaults that tighten security are opt-in per tenant, with an environment
  escape hatch per phase and a migration note in each PR.
- Per-user credentials and composite servers never expose an upstream token to
  the client (already true for shared credentials).
- The existing security lead (guardrails, policies, flow control, kill switch,
  audit) applies to every new surface: composite servers, resources and prompts
  run through the same guard chain as tools.

## 6. Packaging & deploy

Per phase. Expected: new admin-plane modules for principals, SSO and teams (each
added to `Dockerfile.admin`, enforced by `tests/test_admin_dockerfile_imports.py`);
an OIDC/SAML library decision in phase 1 (dependency added to `requirements*.txt`
in the same PR); no new data-plane dependency.

## 7. Failure modes (program level)

| Case | Rule |
|---|---|
| Identity provider unreachable at sign-in | Existing sessions and API keys keep working; new sign-ins fail with a clear message |
| Cached grants stale | Bounded by the existing cache TTL, stated in each phase |
| Per-user token missing or revoked | Fail closed with "connect your account" (never fall back to shared) |
| Composite backend down | Its capabilities are omitted from lists and its calls fail; the rest keep working |
| Registry URL leaked | Exposes names and endpoint URLs only; regenerate; access still enforced |

## 8. Test plan (program)

Each phase's Definition of Done includes the template's items plus:
- the matching rows of the gap matrix move to "matched", each with a test;
- an end-to-end gateway test in `tests/test_production_outcomes.py` style
  (real HTTP route, fake upstream, policy decides);
- no regression in the existing MCP gateway, tool policy and flow-control
  suites; full suite green in a clean venv.

## Tasks (program)

1. **Phase 1 spec**: revise `docs/spec-mcp-verified-identity.md` for users,
   service accounts, OIDC SSO and API keys; then its tasks.
2. Phase 2 spec, then tasks.
3. Phase 3 spec, then tasks.
4. Phase 4 spec, then tasks.
5. Phase 5 spec and build (small).
6. Phase 6 spec, then tasks.
7. Phase 7 docs.

Phases 5 and 7 have no dependency on phase 1 and can run in parallel with it.
