# Target reference: MCP Gateway Product & Engineering Spec (external draft v0.1)

> Imported 2026-10-12 from MCP_Gateway_Specification.docx (Votal AI draft v0.1).
> This is the TARGET we are aligning the existing gateway to. Our own spec +
> gap analysis is docs/specs/spec-mcp-gateway-enterprise.md.


## MCP Gateway Product and Engineering Specification
Votal AI  |  Draft v0.1  |  12 October 2026
Build a multi tenant gateway that lets administrators define users and agent identities or resolve them through an enterprise identity provider, then enforce permissions on MCP discovery and every tool invocation. Codex, Claude Code and compatible open source clients connect to a standard MCP endpoint. Custom applications can use a separate REST API backed by the same authorization pipeline.

## Core product decisions
Use one canonical principal model for local, federated and workload identities. Authentication proves identity; gateway policies decide what that identity may do.
Separate principal, acting agent and client application. A client name such as Codex or Claude is not a user identity and cannot confer permissions.
Default deny. Filter the tool catalog and independently authorize each call, including calls that bypass discovery or reuse an existing session.
Keep downstream credentials at the gateway. Use explicit user delegation or narrowly scoped service credentials; never forward incoming bearer tokens blindly.
Expose native MCP and REST as equivalent enforcement surfaces. The REST API is a gateway feature, not part of the MCP standard.

## Scope and boundaries

## Architecture
Clients enter an MCP or REST ingress. Authentication resolves a tenant and principal, then a shared policy engine evaluates the registered tool and arguments. The connector manager obtains the correct downstream credential and invokes the approved MCP server. Responses pass through configured inspection and audit stages before returning to the client.
A separate control plane manages identities, issuer mappings, servers, tool catalog versions, policies, credentials and audit access. The data plane uses signed, versioned configuration snapshots and cannot change its own authorization rules.

## 1 Principal model and identity resolution

## Canonical entities

## Administrator defined identities
An authorized administrator creates a principal, assigns tenant scoped roles and issues a credential separately. Agent and service identities may use short lived OAuth credentials or scoped API keys. Local human accounts, when enabled, authenticate through the authorization service with MFA; the gateway does not build its own password authentication stack. Creating a principal alone does not authenticate any request.
API keys have a visible identifier plus a cryptographically random secret. Display the secret once, store only a keyed hash, enforce expiry, and support rotation and immediate revocation. Bind each key to one tenant and principal with a permission ceiling that can only narrow the principal’s current permissions.

## Federated identities and mapping
After token validation, resolve the configured issuer and immutable subject to an existing principal. Just in time provisioning is optional and disabled by default. If enabled, a newly created principal has no privileges until an allowlisted mapping grants a role. Never auto link accounts by email or accept a tenant identifier merely because it appears in a request.
An issuer specific mapping may read configured roles, groups or custom claims. OIDC does not define a universal roles claim. For example, map group eng-readers to gateway role repo-reader; map an explicitly approved application role to deploy-operator. Unknown values grant nothing. Reject malformed authorization claims and deny operations whose required attributes are missing.
Effective roles are the union of approved local role bindings and allowlisted mapped roles, bounded by tenant policy, credential scopes and explicit denies. Local grants to federated principals require an audited administrator action. Preserve claim provenance and mapping version so each grant can be explained.

## Agent acting for a user
Record both the user subject and the authenticated agent actor only when a trusted delegation mechanism proves the relationship. Permissions are the intersection of subject permissions, actor permissions and the delegation grant. A service principal without verified delegation acts only as itself. Reject user supplied principal IDs, role headers and “on behalf of” arguments as identity evidence.

## 2 Authentication and enterprise federation

## Recommended deployment
Place a standards compliant authorization service or identity broker in front of the gateway. It federates enterprise sign in through OIDC and issues OAuth access tokens for the gateway resource. The gateway acts as the resource server. This separates enterprise login differences from MCP client interoperability. A direct enterprise issuer integration is allowed only when it satisfies the gateway token and client compatibility requirements.

## Interactive authentication flow
A client reaches the protected MCP endpoint. An unauthenticated response advertises protected resource metadata and the authorization service.
The client completes authorization code flow with PKCE. The authorization service performs enterprise OIDC login, validates the login response and binds the external identity to a gateway principal.
The authorization service issues an access token whose audience is the configured gateway resource. The client presents it on every HTTP request. An OIDC ID token is not accepted as an API bearer token.
The gateway validates the token, resolves current principal status and evaluates current permissions. The existence of an MCP session does not replace authentication.
Use the MCP authorization profile [1] for metadata discovery and resource binding. Implement OAuth and OIDC using maintained libraries rather than custom cryptographic or redirect handling.

## Token validation requirements
For JWT access tokens, require an allowlisted issuer, correct audience, approved signature algorithm, valid signature, expiry and not-before checks with bounded clock skew. Enforce the issuer’s access-token profile and tenant binding. Refresh JWKS on an unknown key ID with rate limits; never fetch a URL supplied by an untrusted token. Opaque tokens require authenticated introspection against a configured endpoint and an active result.
Access tokens should expire within 5 to 15 minutes as a proposed default. Refresh token storage and rotation belong to the authorization service and client. API keys, client credentials and workload federation are optional client-specific authentication profiles; they must not be represented as universally supported MCP login flows.

## Client registration and trust
Support pre-registered clients and the registration mechanisms required by the chosen MCP compatibility profile. Restrict dynamic registrations and validate callback URLs, state, PKCE and issuer binding. Public desktop clients cannot safely hold a client secret. A client ID or self reported client name alone does not attest that a request came from an unmodified approved binary.

## Revocation and identity changes
Check disabled principals and revoked credentials on every call through a bounded cache, targeting propagation within 30 seconds. Policy changes invalidate decision and catalog caches. Federated group removal cannot be detected instantly from a previously issued JWT: use short token lifetime plus refresh, introspection, lifecycle events or directory synchronization. Document the selected freshness bound for each issuer.
If token validation, required introspection, principal status or policy freshness cannot be established within the configured bound, deny new execution. Existing upstream work may already have side effects and must be reported accurately.

## 3 Permissions and policy evaluation

## Permission hierarchy

## Decision algorithm
Validate the request and resolve an immutable tool ID, connector version and normalized arguments. Reject disabled entities first. Evaluate tenant boundaries and credential or delegation ceilings. Apply explicit denies before allows. Combine applicable allow rules as a union of complete grants: all conditions within at least one grant must hold. Required obligations from applicable policies must all succeed; incompatible obligations produce a deny.
Return allow, deny or approval_required. An allow requires an explicit matching grant, all ceilings satisfied and no matching deny. Evaluation errors and unavailable mandatory inspection fail closed. Bind every decision to principal, tenant, credential, action, resource, normalized argument hash, policy version and tool schema version.

## Illustrative policy format
version: 1
id: engineering-repo-read
tenant_id: tenant_acme
effect: allow
subjects:
roles_any: [repo-reader]
actions: [mcp.tools.list, mcp.tools.call]
resource:
server_id: github-prod
tool_ids: [github.get_file]
conditions:
arguments.repository.in: [acme/platform, acme/docs]
arguments.path.prefix: docs/
obligations:
audit: metadata
response_inspection: pii-standard
This YAML defines the proposed gateway policy language, not an MCP standard. The policy compiler validates field types and known resource IDs and rejects ambiguous conditions. For listing, only discovery grants and known identity conditions apply; argument constraints remain attached to the invocation grant. Tool visibility never guarantees a future call is allowed.

## Fine grained enforcement limits
Match security relevant arguments after schema validation and canonicalization. Use structured repository IDs and parsed URLs rather than substring checks. Reject traversal, malformed encodings and ambiguous values. A general shell or SQL tool cannot be made safe using simple command-prefix rules; deny it by default or route it to a purpose-built constrained backend.
Treat upstream readOnly and destructive annotations as hints. Administrators classify tools independently. A tool that advertises read access may still write; downstream permissions and isolation must enforce the actual boundary.

## 4 MCP transport and client connectivity

## Native MCP interface
Expose HTTPS Streamable HTTP at https://gateway.example.com/mcp. Select an explicit tested protocol baseline; use the 2025-11-25 authorization profile [1] as the initial documented baseline and add later profiles only after conformance testing. Do not advertise capabilities that the gateway cannot proxy securely.
Support initialization, negotiated protocol versions, tools/list with pagination, tools/call, ping, cancellation and transport notifications required by the selected profile. Authenticate POST, streaming GET and session termination as applicable. Bind sessions and resumable event IDs to tenant, principal and credential context. Session IDs are routing handles, never credentials.
Namespaced public tool names such as github__get_file resolve through an immutable catalog mapping to server and upstream tool name. Enforce uniqueness and client name limits. Filter discovery and validate direct calls independently. Bind pagination cursors to tenant, principal and catalog/policy version; invalidate them after authorization changes.

## Codex and Claude Code setup
The following connection templates target clients supporting remote HTTP MCP. Validate exact CLI syntax and OAuth registration support against the release pinned in the compatibility test suite [3, 4]. Replace the example domain with the deployed gateway.
# Codex CLI
codex mcp add votal --url https://gateway.example.com/mcp
codex mcp login votal
# Claude Code
claude mcp add --transport http votal \
https://gateway.example.com/mcp
# Open /mcp inside Claude Code to authenticate.
Publish copyable client setup in the admin console after an administrator enables the connector profile. Include endpoint, login instructions, expected tools and a connection test. Do not embed long lived secrets in shared repository configuration.

## Open source clients and custom applications

## Capability restrictions
MVP exposes tools only. Reject resource, prompt, sampling, elicitation, roots and task extensions unless explicitly implemented, authorized and negotiated. Do not forward upstream requests to the client automatically. Enforce Origin validation for HTTP when present, explicit CORS rules, transport size limits and bounded streaming duration.

## 5 Public APIs and invocation contract

## Data plane API

## Invocation example
POST /api/v1/tool-calls
Authorization: Bearer <gateway-access-token>
Idempotency-Key: 05d893a0-unique-per-logical-operation
Content-Type: application/json
{
"tool_id": "github.get_file",
"server_id": "github-prod",
"arguments": {
"repository": "acme/docs",
"path": "docs/onboarding.md"
}
}
{
"call_id": "call_123",
"status": "succeeded",
"decision_id": "dec_456",
"result": {"content": [{"type": "text", "text": "..."}]}
}
The caller cannot set its tenant, principal, role or downstream credential in the body. Infer identity from the validated credential. Return 200 for a completed call or 202 plus a status URL when queued; clients poll only through authenticated endpoints. Apply the same authorization to REST and MCP response retrieval.

## Errors and retry behavior
REST uses 400 for invalid input, 401 for invalid or missing credentials, 403 for denied access, 404 for hidden or unknown resources, 409 for an idempotency conflict, 429 for limits, 502 for upstream failures, and 504 for timeout. Responses include stable code, safe message and request ID; never leak tokens, internal addresses or hidden tool names.
MCP uses transport authentication challenges where required and valid JSON-RPC/MCP envelopes for method results and errors. Define policy denial as a documented gateway error in the permitted server error range, with code GATEWAY_POLICY_DENIED in error data. Do not claim this is a standard MCP error. Map upstream tool failures to the negotiated tool result format.
Deduplicate REST invocations by tenant, principal, tool and idempotency key; bind the key to the argument hash and reject mismatches. Retain records for a proposed 24 hours. Do not retry writes after uncertain delivery. A timeout may mean the action executed; return outcome_unknown when appropriate. Exactly once execution requires upstream support and is not guaranteed by gateway caching.

## 6 Administration and downstream execution

## Admin console and control plane APIs
Separate tenant administrator, policy administrator, connector administrator, auditor and caller roles. Control plane privileges never automatically grant tool execution. Prevent administrators from assigning rights beyond their delegated administration boundary. Require strong authentication for secret issuance and policy publication; audit every mutation with before/after references.

## Connector and secret management
Register an MCP server with tenant, connector ID, endpoint, transport, authentication mode, secret reference, allowed tools, timeout and network policy. Store secrets in a vault with encryption and least privilege access. Use per-user downstream OAuth where available, or explicitly scoped service credentials where the integration requires it. Obtain tokens for the upstream audience; do not reuse the gateway bearer token [2].
Pool connections only within the same tenant and downstream authorization context. Reinitialize upstream sessions as required and map request IDs to prevent cross-client confusion. Strip untrusted forwarding headers and propagate only allowlisted tracing metadata. A service account may have broader upstream privileges than the caller; enforce all caller constraints before using it.

## Server registration and catalog safety
Only privileged administrators can register destinations. Validate DNS and resolved addresses on connection, restrict redirects, and block unapproved loopback, link local and metadata endpoints. Explicitly allow private enterprise destinations when needed. Apply equivalent fetch restrictions to OAuth discovery and remote client metadata.
Store schema and description hashes. New tools start denied; changed schemas or material metadata changes require review before publication. Pin approved catalog versions and disable changed tools while review is pending. This detects visible metadata changes, not an upstream server silently changing behavior under an unchanged schema.

## Approval workflow for the next release
When a policy requires approval, create a pending call without executing. Return a safe approval reference to the client. A designated human reviews the exact normalized arguments in the admin application. Bind approval to tenant, subject, actor, tool and schema version, argument hash, expiry and one-time execution. The requesting principal cannot approve its own call.
On execution, reauthenticate and reevaluate current policy. Deny if arguments, tool version or authorization changed. Use gateway-side approval state so ordinary MCP clients do not need a proprietary approval protocol. Publish retry guidance to prevent duplicate approval requests.

## 7 Operations observability and delivery

## Audit and tracing
Emit a structured event for authentication failures, discovery, policy decisions, dispatch, completion, cancellation, approval and admin changes. Include timestamp, tenant, subject, actor if verified, credential identifier, client registration and trust level, session, call ID, tool/schema version, argument hash, policy version, decision reason, matched rule IDs, upstream outcome and latency.
Never log bearer tokens, API secrets or refresh tokens. Default to argument and result metadata; payload capture is opt-in, redacted, encrypted and tenant controlled. Keep audit records append-only with restricted access and retention settings. Link OpenTelemetry spans across auth, policy, connector and inspection; distinguish upstream execution from gateway result delivery.

## Limits and failure behavior
Enforce per-tenant, principal and tool rate limits plus concurrent-call limits. Proposed defaults are a 1 MiB request ceiling, 10 MiB response ceiling and 60 second tool timeout, with per-tool overrides. Bound streaming buffers and page counts. A client disconnect triggers best effort cancellation and an accurate final audit outcome.
Use a durable audit outbox before dispatch. If the outbox cannot accept a record, deny new execution. If an upstream action completes but response inspection or audit delivery fails, record execution separately and report a delivery failure; do not imply that the side effect was prevented.

## Deployment proposal
Use containerized ingress, authentication middleware, an embedded deterministic policy evaluator, connector workers and a separate control plane. PostgreSQL stores versioned configuration and invocation records; a bounded cache supports status checks and quotas; a vault stores credentials. Object storage may retain approved audit exports. Use workload identities, tenant isolation and managed encryption keys where available.
Run remote MCP workers with restricted egress. Future stdio connectors run in separate sandboxes with pinned packages, non-root users, minimal filesystem mounts and resource limits. A local bridge does not make untrusted server code safe. Keep the runtime and administrative network paths separately authorized.

## Proposed service objectives

## Delivery sequence
Milestone 1: principal model, local credentials and connector registry. Milestone 2: policy enforcement, audit and REST/MCP parity. Milestone 3: OIDC broker integration, Codex and Claude certification and admin UX. Milestone 4: isolation, reliability and adversarial testing. Follow with approvals, bridge, lifecycle synchronization and inspection integrations. Estimates depend on team size and selected identity infrastructure.

## 8 Acceptance criteria and references

## Release acceptance tests

## Implementation decisions to confirm
Choose the authorization broker and first enterprise IdP; pin client and MCP versions; choose the first two upstream servers; decide whether private network access and API keys are required at launch. These choices affect adapters and deployment, while the principal and policy contracts remain consistent.

## Reference sources
Sources checked 12 October 2026. The design, API paths, policy syntax, default limits, roadmap and service targets in this document are proposed product requirements. They are not existing Votal AI capabilities or universal MCP requirements.
[1] MCP authorization profile, 2025-11-25. https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
[2] MCP security best practices. https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices
[3] Codex MCP documentation. https://developers.openai.com/codex/mcp
[4] Claude Code MCP documentation. https://code.claude.com/docs/en/mcp

### Table 0
| Release | Capabilities |
| MVP | Local principals and API credentials; enterprise OIDC federation; RBAC and attribute conditions; remote MCP routing; tool discovery and call enforcement; admin UI and APIs; audit logs; REST calls. |
| Next | Human approvals; stdio compatibility bridge; isolated stdio connectors; SCIM lifecycle synchronization; additional policy conditions; DLP and prompt injection inspection hooks. |
| Excluded from gateway guarantees | Blocking tools executed outside the gateway, endpoint shell activity, or direct upstream access. These need network, credential or endpoint controls. |

### Table 1
| Entity | Required fields and meaning |
| Tenant | id, name, status, trusted issuers, policy version and credential namespace. |
| Principal | id, tenant_id, kind [human, agent, service], source [local, federated], status, display_name, role bindings and administrator controlled attributes. |
| External identity | tenant_id, issuer, subject and principal_id. Uniqueness is tenant plus exact issuer plus subject; email is a display attribute. |
| Client registration | client_id, allowed flows, redirect URIs, trust level and credential restrictions. MCP clientInfo is untrusted telemetry. |
| Credential | id, principal_id, type, scope ceiling, audience, expiry, revocation status and secret reference or one way hash. |
| Delegation | subject principal, acting principal, allowed actions, resource restrictions, expiry and verifiable issuance context. |

### Table 2
| Layer | Examples of controls |
| Gateway and tenant | May connect; tenant membership; allowed authentication strength; credential expiry. |
| Server | May discover or access the registered GitHub, Jira or internal MCP connector. |
| Tool and method | May list github__get_file; may invoke it; may not invoke github__delete_repository. |
| Arguments and resources | Repository allowlist; environment equals staging; path prefix; maximum records; approved destination domain. |
| Context | Trusted workload identity; network zone; verified device posture; time window; call budget. |
| Response | Required DLP inspection; permitted data classification; response size and redaction policy. |

### Table 3
| Client capability | Connection path |
| Remote HTTP plus OAuth | Native MCP endpoint and interactive OAuth; test the client’s registration and callback behavior. |
| Remote HTTP plus custom headers | Native MCP endpoint with a scoped bearer API key or access token, obtained outside the MCP flow. |
| Stdio only | Next release: local stdio bridge translates MCP to authenticated HTTPS; credentials remain in an OS keychain or protected environment. |
| No MCP implementation | REST tool catalog and invocation endpoints; the gateway creates and manages downstream MCP sessions. |

### Table 4
| Method and path | Contract |
| GET /api/v1/me | Return authenticated principal, tenant and non-sensitive effective identity context. |
| GET /api/v1/tools | Return the authorized catalog with public name, input schema, tool version and pagination cursor. |
| POST /api/v1/tool-calls | Invoke a registered tool through the same evaluator used by MCP tools/call. |
| GET /api/v1/tool-calls/{id} | Read own call status and authorized result; tenant audit role may access according to policy. |
| POST /api/v1/tool-calls/{id}/cancel | Best effort cancellation for an owned call. Cancellation is not rollback. |

### Table 5
| Resource family | Required operations |
| /admin/v1/principals | Create, inspect, disable and bind roles; view identity provenance and effective permissions. |
| /admin/v1/identity-providers | Configure issuer, audience, JWKS or introspection, mapping rules and provisioning; preview mappings on sanitized claims. |
| /admin/v1/credentials | Issue, rotate and revoke scoped credentials; return new secrets once. |
| /admin/v1/servers and tools | Register allowlisted endpoints; test connectivity; discover schemas; approve tool versions and risk classification. |
| /admin/v1/policies | Draft, validate, simulate, publish atomically, compare and roll back versioned rules. |
| /admin/v1/audit-events | Filter and export tenant scoped call, decision and administrative events. |

### Table 6
| Measure | Initial target to benchmark before launch |
| Authorization overhead | p95 below 20 ms with warm local policy and identity caches, excluding network and external inspection. |
| Gateway added latency | p95 below 50 ms for small non-streaming calls, excluding upstream tool and remote authentication latency. |
| Availability | 99.9 percent monthly for a redundant production deployment. |
| Revocation and policy changes | Within 30 seconds for local principal, credential and policy changes; document issuer-specific group freshness separately. |
| Capacity baseline | Demonstrate 100 concurrent calls per data-plane instance on a published hardware and payload profile. |

### Table 7
| Test | Pass condition |
| Local identity | A newly created principal has no tool access until assigned a grant; a scoped key cannot exceed that grant. |
| Federated roles | Trusted issuer and subject resolve correctly; approved claim mappings grant access; missing or forged roles do not. |
| Token misuse | Reject ID tokens, incorrect audiences, wrong issuers, expired tokens, invalid signatures and cross-tenant credentials. |
| Tool enforcement | Hidden tools cannot be invoked by guessing a name; valid read calls succeed; write and out-of-scope arguments are denied before dispatch. |
| API parity | Identical identity, tool and arguments yield equivalent authorization in REST and MCP. |
| Session isolation | Cross-user session IDs, pagination cursors, stream resumption tokens and call IDs disclose no data and grant no execution. |
| Policy changes | A revoked key or disabled principal loses access within the stated bound, including through an already open MCP session. |
| Client interoperability | Pinned Codex and Claude Code releases complete login, initialize, list and invoke; one open source HTTP client passes token authentication. |
| Upstream safety | Incoming access tokens never reach upstream tools; credential pools stay isolated; SSRF and unapproved redirects are blocked. |
| Reliability | Timeouts, lost responses and duplicate requests cannot silently cause automatic write retries; uncertain execution is visible. |
| Audit and secrets | Every execution has correlated decision and outcome records; secret scanning finds no credentials in logs. |
| Catalog and failure | Unapproved tools remain denied; schema changes trigger review; mandatory policy or inspection failure prevents new dispatch. |