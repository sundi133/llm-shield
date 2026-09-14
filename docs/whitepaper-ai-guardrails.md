---
title: "Whitepaper: The Guardrail Layer"
layout: default
nav_order: 25
permalink: /whitepaper-guardrail-layer/
description: "Technical whitepaper on AI guardrails. Why existing controls do not reach a non-deterministic caller, the standards each control implements, the two-tier enforcement architecture, measured latency and detection, and the evidence an auditor can reproduce."
---

# The Guardrail Layer
{: .no_toc }

Every control an enterprise owns assumes a deterministic caller. A language
model is not one. This paper describes the enforcement layer that closes the
gap, mapped throughout to the security standards your auditors already use.
{: .fs-6 .fw-300 }

<details open markdown="block">
<summary>Table of contents</summary>
{: .text-delta }
1. TOC
{:toc}
</details>

---

## 1. Why existing controls do not reach

A classical application is a deterministic translator. Alice presents a token,
the app decides what that means, the database enforces a row-level ACL.
Authorization is binary and the question is always the same: may Alice do X?

Insert a language model between Alice and the tool and four properties break at
once. None of them is a bug in the model. They are consequences of putting a
probabilistic actor inside a control path designed around a deterministic one.

**The caller is not the user.** A human asked a question, the model chose a
tool, an agent runtime issued the HTTP request. Three principals, one bearer
token in the header. By the time the request reaches the tool server, the
identity that authorized it has been flattened into a credential that says
nothing about which prompt produced the call.

**The authorization signal is in the content, not the headers.** Whether
`send_email` should be permitted depends on what is in the email: whether it
carries PII, whether its body was tainted by a prior tool's output, whether the
recipient is outside the tenant. No header carries that.

**One session fans out to thousands of calls.** Session-scoped audit is right
for a human clicking through a web app. For an agent in a loop the interesting
event is a single tool call out of several thousand, and a session record cannot
isolate it.

**Agents call agents.** A sub-agent typically inherits the parent's full
privileges, because the simplest way to spawn one is to hand over the same
credential. Least privilege ends at the first delegation.

Giving the agent a service account reproduces every property you were trying to
avoid: it lives for months, it is shared by every process, it asserts its own
role, and it is a bearer credential equally useful to whoever steals it.

**Risks named by:** OWASP LLM03 Excessive Agency, OWASP ASI03 Agent Identity and
Privilege Abuse, ASI07 Insecure Inter-Agent Communication, NIST AI RMF MAP 3.4.

---

## 2. The standards this layer is built to

Nothing in this paper asks you to accept a vendor's private taxonomy. Every
control described below maps to a published framework, and every protocol used
to carry identity is an IETF standard with a specification number you can read.

### Governance and control frameworks

| Framework | Scope applied |
|---|---|
| **NIST AI RMF 1.0** | GOVERN, MAP, MEASURE and MANAGE functions, mapped control by control |
| **OWASP Top 10 for LLM Applications** | 2026 edition, LLM01 through LLM10 |
| **OWASP Top 10 for Agentic Applications** | 2026 edition, ASI01 through ASI10 |
| **NIST SP 800-53 Rev 5** | AC, AU, IA, SC and SI control families |
| **EU AI Act** | High-risk provisions, Articles 9 through 61 |
| **ISO/IEC 42001:2023** | AI management system, clauses 6 through 10 |

### Protocol and cryptographic standards

The identity mechanisms in section 5 are not proprietary tokens. They are
standard constructions, which is what makes them verifiable by any library your
team already trusts, and what keeps the exit cost low.

| Standard | Used for |
|---|---|
| **RFC 7519** | JSON Web Token, the agent principal wire format |
| **RFC 7517 / 7638** | JSON Web Key Set and JWK thumbprints, for key distribution and confirmation claims |
| **RFC 9449** | DPoP, demonstrating proof of possession, so a stolen token is not a bearer credential |
| **RFC 8693** | OAuth 2.0 Token Exchange, carrying the delegation chain in the `act` claim |
| **RFC 9728** | OAuth 2.0 Protected Resource Metadata, so an unauthenticated client learns it must authenticate |
| **OAuth 2.1** | The authorization framework the integration follows |
| **RFC 8032** | EdDSA and Ed25519 signatures on agent tokens and capabilities |
| **OIDC** | Federation with the identity provider that already authenticates your humans |
| **Elastic Common Schema** | Telemetry field naming, so events land in your SIEM without a translation layer |
| **Model Context Protocol** | The open protocol by which agents reach tools, and the boundary enforcement is applied at |

{: .note }
> **Read this precisely.** Shield **implements controls defined by** these
> frameworks and **conforms to** these protocol specifications. It is not itself
> a standard, and no product is. Where a mechanism below is an engineering
> choice rather than a standardized one, such as the two-tier inspection
> pipeline, this paper says so rather than dressing it in a control ID.

---

## 3. What a guardrail is

A guardrail is a named check that runs at a defined point in the request
lifecycle, returns a verdict with a reason, and is enforced by something outside
the model. That last clause is the load-bearing one. A system prompt asking the
model to behave is not a guardrail, because the component being asked is the
same component under attack.

Shield ships 22 across four families. Three run on text. The fourth runs on
actions, which is the one that matters once a system stops answering questions
and starts doing things.

### Input guardrails

| Tier | Guardrail | What it checks | Control |
|---|---|---|---|
| Fast | `keyword_blocklist` | Aho-Corasick keyword matching | SI-3, SI-10 |
| Fast | `length_limit` | Character and token ceilings | SI-10 |
| Fast | `regex_pattern` | Configurable rules: SSN, passwords, account numbers | SI-10 |
| Fast | `pii_detection` | Presidio-backed detection of phone, email, SSN, card | SC-28 |
| Fast | `language_detection` | Rejects languages outside the allowed set | AC-4 |
| Fast | `sentiment` | Flags extreme negative affect | MEASURE 2.6 |
| Fast | `rate_limiter` | Per-client sliding window | AC-7 |
| Slow | `adversarial_detection` | Jailbreaks and prompt injection, 16 attack families | SI-3, SI-4 |
| Slow | `topic_restriction` | Topic blacklist and whitelist | AC-4 |
| Slow | `topic_enforcement` | Confidence-scored enforcement with a standalone API | MAP 2.3 |

### Output guardrails

| Tier | Guardrail | What it checks | Control |
|---|---|---|---|
| Fast | `role_redaction` | Redacts PII by the caller's clearance level | SC-28 |
| Slow | `hallucinated_links` | Fabricated URLs | MEASURE 2.3 |
| Slow | `tone_enforcement` | Brand voice compliance | MEASURE 2.11 |
| Slow | `factual_grounding` | Claims unsupported by provided context | MEASURE 2.3 |
| Slow | `bias_detection` | Gender, racial and age bias | MEASURE 2.11 |

### Agentic guardrails, which run on actions rather than text

| Guardrail | What it checks | Control |
|---|---|---|
| `rbac_guard` | Role-based tool and data access | AC-2, AC-3, AC-6 |
| `data_access_guard` | Clearance level enforcement | AC-3, AC-4 |
| `mcp_guard` | MCP server validation and trust scoring | SC-7, MANAGE 3.1 |
| `action_guard` | Per-session action limits and approval gates | AC-6, MANAGE 2.4 |
| `data_taint_tracking` | Sensitive data flow across tool chains | AC-4 |
| `goal_drift_detection` | Deviation from the agent's assigned goal | ASI01, ASI10 |
| `cert_identity` | Certificate-backed agent identity gating tool access | IA-2, IA-8 |

A fifth group covers operational controls rather than detection: a tool kill
switch that disables a capability globally in one API call, runtime decision
audit, webhook fan-out to Slack, PagerDuty or a SIEM, policy versioning with
rollback, policy-as-code export and import, and org-level baseline policies that
child tenants cannot weaken. All are opt-in and disabled by default.

---

## 4. Two tiers, because latency is the real constraint

Inspection sits on the critical path of every request. A guardrail layer that is
thorough and slow gets switched off in production, which makes it worth nothing.
The design problem is not how to detect the most attacks. It is how to spend
deep inspection only where cheap inspection is inconclusive.

| Tier | What runs | Cost |
|---|---|---|
| **Tier 1, CPU** | Keyword and regex rules, PII detection, rate limiting, language checks, system prompt leak, then a probe classifier over model hidden states | Under 5 ms for the rules, about 18 ms for the classifier |
| **Tier 2, GPU** | Adversarial detection, topic restriction, safety and toxicity, dispatched concurrently | Only for traffic Tier 1 could not call |

The classifier routes on confidence. Above **0.92** it blocks immediately. Below
**0.60** it allows and skips Tier 2 entirely. Only the uncertain middle band
reaches the GPU, and when it does the checks are dispatched together, so the
tier costs the slowest check rather than the sum of all three. On the
benchmarked configuration that distinction is the difference between roughly
180 ms and roughly 400 ms per request.

{: .note }
> **Engineering choice, not a standard.** No framework prescribes a tiered
> pipeline. It is how this implementation meets NIST AI RMF MEASURE 3.1, which
> asks that approaches to testing, evaluation, verification and validation be
> identified, at a latency a production system will actually tolerate. Judge it
> on the measurements in section 6, not on a control ID.

**Two planes.** Shield separates a GPU data plane, serving the guard endpoints,
from a CPU admin plane serving the portal, policy management and analytics. The
separation is an operational rule, not just a diagram: governance and reporting
features are built so they cannot add latency to the guard path.

**Controls implemented:** NIST AI RMF MEASURE 3.1 and 2.5, SP 800-53 SC-7,
ISO 42001 8.3.

---

## 5. Enforcement on actions

Text guardrails answer whether a message is safe. They do not answer whether an
agent may act. Once tools enter the picture, two independent questions arise,
and the most common integration failure is conflating them.

**Authorization** asks whether this role may call this tool with these
parameters. **Data policy** asks what sensitive content may cross the tool
boundary in either direction. They run at different endpoints. An integration
that calls only the authorization endpoint gets no content inspection on
arguments or results.

| # | Stage | Enforces | Control |
|---|---|---|---|
| 1 | Authorization, before execution | RBAC, data-access scope, injection and payload validation | AC-3, AC-6 |
| 2 | Arguments, before execution | Content policy on the arguments: redact, mask or block | SC-28, SI-10 |
| 3 | Execution | The tool runs, only if 1 and 2 both permitted it | SI-7 |
| 4 | Result, after execution | Content policy on what the tool returned | SC-28 |

### Identity, in five independently switchable layers

Authorization is only as good as the identity underneath it. A capability scoped
to `billing-bot` proves nothing if `billing-bot` was asserted in a header. Each
layer is a standard construction, named by its specification.

| Layer | Question | Mechanism | Default |
|---|---|---|---|
| **L0** | What process is asking? | Workload attestation: SPIFFE, mTLS, OIDC service account. SP 800-53 IA-2 | on |
| **L1** | Which agent, build, model, session? | RFC 7519 JWT, EdDSA per RFC 8032, 15 minutes maximum. IA-5 | on |
| **L2** | Is the presenter the party it was issued to? | DPoP per RFC 9449, `cnf.jkt` per RFC 7638 | **off** |
| **L3** | Whose authority is it borrowing? | RFC 8693 token exchange, `act` claim. AC-5 | **off** |
| **L4** | May it do this, to this resource, right now? | Ed25519 capability, 30 second lifetime, nonce burned on use. AC-6 | on |

A tenant key mints a short-lived agent token; that token mints a capability
bound to one action on one resource, valid for seconds and single-use. Replay
fails because the nonce is burned at first verification, and revocation is one
API call rather than a key rotation that breaks legitimate traffic.

**Controls implemented:** SP 800-53 AC-2, AC-3, AC-5, AC-6, IA-2, IA-5, IA-8.
OWASP LLM03, ASI02, ASI03. EU AI Act Art. 14.

---

## 6. Measured behavior

Figures are from the published benchmark: an NVIDIA H100 80GB running a 9B
guardrail model at FP8 weights and FP8 KV cache, served by vLLM with prefix
caching and chunked prefill, 8,192-token context, up to 128 concurrent
sequences.

| Metric | c = 1 | c = 5 | c = 10 |
|---|---|---|---|
| Server p50 | 181 ms | 342 ms | 657 ms |
| Server p95 | 375 ms | 657 ms | 1,195 ms |
| Server p99 | 397 ms | 768 ms | 1,270 ms |
| End-to-end p50 | 251 ms | 552 ms | 1,016 ms |
| Throughput | not measured | 8.9 req/s | 9.2 req/s |

Latency scales sub-linearly: ten times the concurrency costs 3.6 times the p50,
and throughput holds near 9 requests per second, which indicates efficient
batching rather than saturation. Read the concurrency columns as a capacity
planning input, not as a single headline number.

### Detection by attack category, 200 requests at c=1

| Category | n | p50 | p95 | Outcome |
|---|---|---|---|---|
| Prompt injection | 25 | 184 ms | 399 ms | 25/25 blocked |
| Harmful content | 25 | 355 ms | 394 ms | 25/25 blocked |
| Toxic content | 14 | 157 ms | 178 ms | 14/14 blocked |
| PII | 17 | 207 ms | 284 ms | 17/17 blocked |
| Unicode obfuscation | 22 | 135 ms | 201 ms | 22/22 blocked |
| Off-topic | 18 | 150 ms | 185 ms | 18/18 blocked |
| Mixed noise | 15 | 202 ms | 290 ms | 15/15 blocked |
| Benign, on-topic | 15 | 171 ms | 193 ms | 4/15 allowed |

{: .warning }
> **The benign row is the important one.** Eleven of fifteen harmless prompts
> were blocked because the test tenant runs a strict healthcare topic allowlist,
> so recipes, poems and coding questions are correctly rejected as off-scope.
> That is policy behaving as configured, not a false-positive rate. Any
> evaluation that quotes a detection number without quoting the policy that
> produced it is not telling you anything.

**Corpus.** Detection is regression-tested against 13 industry suites, each
carrying 1,850 adversarial and 250 safe prompts, giving 24,050 adversarial and
3,250 safe prompts in total, built from 185 named techniques at 10 variants
each.

**Cost.** At roughly 9 requests per second on an H100 at $2 to $3 per hour, a
check costs between $0.00006 and $0.00009, against $0.001 to $0.01 at 500 to
2,000 ms for API-based guardrail services. The self-hosted figure assumes a GPU
you are keeping busy.

**Controls evidenced:** NIST AI RMF MEASURE 2.5, 2.13, 4.2. ISO 42001 9.1.
EU AI Act Art. 15.

---

## 7. Control mapping

### OWASP Top 10 for LLM Applications, 2026

| ID | Risk | Enforcing guardrails |
|---|---|---|
| LLM01 | Prompt injection | `adversarial_detection`, `payload_risk`, `memory_injection_detection`, `chain_of_thought_monitoring` |
| LLM02 | Sensitive information disclosure | `pii_detection`, `pii_leakage`, `memory_pii_scrubbing`, `data_access_guard`, `role_redaction` |
| LLM03 | Excessive agency | `action_guard`, `rbac_guard`, `sensitive_action_confirmation`, `scope_boundaries`, `delegation_control` |
| LLM04 | Supply chain | `mcp_guard` with server trust scoring |
| LLM05 | Data and model poisoning | **Out of scope**, requires model training controls |
| LLM06 | Unbounded consumption | `rate_limiter`, `length_limit`, `budget_controls`, `tool_call_rate_limiting`, `loop_detection` |
| LLM07 | Misinformation | `factual_grounding`, `hallucinated_links`, `chain_of_thought_monitoring` |
| LLM08 | Hidden context exposure | `system_prompt_leak`, `role_redaction`, `tool_output_sanitization` |
| LLM09 | Vector and embedding weaknesses | `data_access_guard`, `memory_access_control`, `memory_injection_detection` |
| LLM10 | Improper output handling | `tool_output_sanitization`, `pii_leakage`, `role_redaction`, `regex_pattern` |

### OWASP Top 10 for Agentic Applications, 2026

| ID | Risk | Enforcing guardrails |
|---|---|---|
| ASI01 | Agent goal hijack | `adversarial_detection`, `goal_drift_detection`, `chain_of_thought_monitoring` |
| ASI02 | Tool misuse and exploitation | `tool_allowlist`, `tool_use_control`, `tool_call_validation`, `action_guard` |
| ASI03 | Agent identity and privilege abuse | `rbac_guard`, `cert_identity`, `scope_boundaries`, `data_access_guard` |
| ASI04 | Agentic supply chain | `mcp_guard` with server trust scoring |
| ASI05 | Unexpected code execution | `tool_call_validation`, `tool_output_sanitization`, `action_guard` |
| ASI06 | Memory and context poisoning | `memory_injection_detection`, `memory_pii_scrubbing`, `memory_access_control`, `memory_retention_policies` |
| ASI07 | Insecure inter-agent communication | `delegation_control`, `cert_identity`, agent-key impersonation checks |
| ASI08 | Cascading agent failures | `loop_detection`, `budget_controls`, `tool_call_rate_limiting` |
| ASI09 | Human-agent trust exploitation | **Partial**: `sensitive_action_confirmation` only. Approval fatigue and induced over-trust are not screened |
| ASI10 | Rogue agents | `goal_drift_detection`, `action_classification`, `data_taint_tracking`, agent disable |

### NIST SP 800-53 Rev 5

| ID | Control | Coverage |
|---|---|---|
| AC-2 | Account management | `rbac_guard`, tenant key management |
| AC-3 | Access enforcement | `rbac_guard`, `scope_boundaries`, `data_access_guard` |
| AC-4 | Information flow enforcement | `data_access_guard`, `scope_boundaries`, taint tracking |
| AC-5 | Separation of duties | `rbac_guard` per-role tool and data restrictions |
| AC-6 | Least privilege | `tool_allowlist`, `action_guard`, per-role clearance |
| AC-7 | Unsuccessful logon attempts | `rate_limiter`, per-agent |
| AU-2 | Event logging | Telemetry middleware to SIEM |
| AU-3 | Content of audit records | Full ECS-compliant schema |
| AU-6 | Audit review and reporting | SIEM dashboards, alerts on high-risk events |
| AU-9 | Protection of audit information | Authenticated SIEM, append-only stores. **Cryptographic tamper-evidence is roadmap** |
| AU-12 | Audit record generation | Audit log, decision audit, SIEM exporter |
| IA-2 | Identification and authentication | Auth middleware, `agent_key` identity |
| IA-5 | Authenticator management | SHA-256 hashed keys, rotation |
| IA-8 | Non-organizational users | Per-tenant keys, tenant-scoped identities |
| SC-7 | Boundary protection | `scope_boundaries`, `rbac_guard`, multi-tenant isolation |
| SC-8 | Transmission confidentiality | HTTPS required for telemetry exporters |
| SC-28 | Protection of information at rest | `memory_pii_scrubbing`, `role_redaction` |
| SI-3 | Malicious code protection | `keyword_blocklist`, `regex_pattern`, `adversarial_detection` |
| SI-4 | System monitoring | `chain_of_thought_monitoring`, `context_window_guardrails`, telemetry |
| SI-7 | Software and information integrity | `tool_call_validation`, `memory_guardrails` |
| SI-10 | Information input validation | `regex_pattern`, `length_limit`, `keyword_blocklist`, `tool_call_validation` |
| SI-11 | Error handling | Per-guardrail exception handling, fail-closed |

### NIST AI RMF 1.0, EU AI Act and ISO/IEC 42001

| ID | Requirement | Coverage |
|---|---|---|
| GOVERN 1.4 | Legal and regulatory requirements managed | `pii_detection`, `data_access_guard`, per-tenant isolation |
| GOVERN 4.1 | Accountability structures | `rbac_guard`, `agent_key` tracing, audit trail |
| MAP 3.4 | Risks mapped to business context | `data_access_guard`, `action_classification`, `tool_allowlist` |
| MEASURE 2.7 | Secure and resilient | `adversarial_detection`, `system_prompt_leak`, `rate_limiter` |
| MEASURE 2.10 | Privacy-enhanced | `pii_detection`, `memory_pii_scrubbing`, `role_redaction` |
| MANAGE 2.4 | Mechanisms to deactivate | `action_guard`, `rbac_guard`, tool kill switch |
| MANAGE 3.1 | Third-party risk | `mcp_guard` with trust scoring |
| Art. 9 | Risk management system | Guardrail pipeline, SIEM telemetry, audit logs |
| Art. 12 | Record-keeping | Append-only audit logs. **Tamper-evidence is roadmap** |
| Art. 14 | Human oversight | `sensitive_action_confirmation`, `action_guard`, approval gates |
| Art. 15 | Accuracy, robustness, cybersecurity | `adversarial_detection`, `rate_limiter`, `budget_controls` |
| ISO 6.1.2 | AI risk assessment | Per-event risk score, per-guardrail risk tiers |
| ISO 8.4 | Third-party relationships | `mcp_guard`, `tool_allowlist`, per-tenant isolation |
| ISO 9.2 | Internal audit | Audit log with query API |

Three entries say out of scope, partial, or roadmap. They are load-bearing. A
mapping that claims full coverage of every row in a published taxonomy is
describing a marketing position rather than an enforcement surface, and an
auditor will find the gap faster than the vendor will admit it.

---

## 8. The evidence an auditor can reproduce

A control mapping is a claim. Evidence is what closes a finding. Each item is
produced on demand from the running system, not assembled by hand for an audit.

| # | Evidence item | Answers |
|---|---|---|
| 1 | Control inventory, the guardrail to framework matrix | All frameworks |
| 2 | Live policy bundle export, versioned | ISO 8.3, Art. 17 |
| 3 | Policy change history with rollback points | AU-12, ISO 10 |
| 4 | Enforcement decisions: every block and warn with agent, tool, policy, reason, timestamp | AU-2, AU-3, Art. 12 |
| 5 | Full audit trail for an arbitrary period, tenant-scoped | AU-12, ISO 9.2 |
| 6 | Blocked-attack samples filtered by risk score | MEASURE 2.7, LLM01 |
| 7 | Per-control effectiveness: block rate and latency, 90-day retention | MEASURE 2.13, ISO 9.1 |
| 8 | Identity and least privilege: role to tool matrix, token binding, capability scoping | AC-2, AC-6, IA-2 |
| 9 | Incident response: kill-switch history, alert config, instance revocation | MANAGE 2.4, Art. 61 |
| 10 | Data protection: detection and redaction config, clearance map, residency posture | SC-28, Art. 10 |
| 11 | Integrity of the trail itself (**roadmap**: chain verification and signed offline-verifiable export) | AU-9, Art. 12 |

**Change management.** New controls can run in monitor mode first, recording
what they would have blocked without blocking it. The decision audit then
evidences "tuned before enforced" for a change-management review, which is
usually the difference between a control that ships and one that stalls.

---

## 9. Where the layer sits

| Shape | How it attaches | Use when |
|---|---|---|
| Endpoint substitution | Client points its OpenAI `base_url` at the layer | You own the app and want zero code change |
| Gateway plugin | Guardrail hook inside an existing AI gateway or proxy | Traffic already flows through a gateway |
| MCP gateway | Agents connect to the layer, which fronts the real MCP server | You do not control the tool server |
| Direct API | Stateless guardrail calls from your code or an API gateway policy | You want enforcement inside an existing policy layer |
| Managed browser extension | Pushed by MDM, enforces before the prompt leaves the page | Users reach AI tools through a browser |
| Web gateway over ICAP | RFC 3507 REQMOD at the proxy you already run | You need coverage beyond the browser |

The last two are covered in [Endpoint enforcement](/endpoint-enforcement/).

{: .warning }
> **Failure mode.** A gateway only protects what cannot be reached around it. If
> the upstream tool server remains directly reachable, an agent pointed at its
> real address bypasses every control in this paper. Network-level restriction
> of the upstream to the gateway is the precondition that makes the deployment
> meaningful. SP 800-53 SC-7 is the control, and it is yours to implement.

Guardrails fail closed. If an inspection pipeline errors, the request is refused
rather than proxied unguarded, per SP 800-53 SI-11.

---

## 10. What this does not solve

A guardrail layer is a runtime control. It constrains what a model is given and
what is done with what it produces. Several classes of risk sit outside that
boundary, and pretending otherwise is how security programs acquire false
confidence.

- **Training-time integrity.** Data and model poisoning, OWASP LLM05, are addressed by controls over the training pipeline, not by inspecting inference traffic.
- **Human factors.** Approval fatigue and induced over-trust, OWASP ASI09, are behavioral risks. A confirmation prompt a tired operator approves by reflex has not enforced anything.
- **Policy quality.** Enforcement is exactly as good as the policy it enforces. A permissive allowlist inspected perfectly is still a permissive allowlist.
- **Detection is probabilistic.** The deep tier uses a model, and models are wrong sometimes. The tiered design bounds the cost of that and the audit trail makes it reviewable; neither eliminates it.
- **The precision trade-off is a policy decision.** Tightening a topic allowlist raises blocks on harmless traffic. That dial belongs to the risk owner, not to a vendor default.
- **Tamper-evidence of the audit trail is roadmap.** Append-only storage and authenticated transport ship today; cryptographic chain verification for SP 800-53 AU-9 and EU AI Act Art. 12 does not yet. For hard immutability now, stream to write-once storage with object lock.

The honest position is that this layer moves a set of failures from undetectable
to enforced and recorded. It does not make a non-deterministic system
deterministic.

---

## References

Framework references: NIST AI Risk Management Framework 1.0; OWASP Top 10 for
Large Language Model Applications, 2026 edition; OWASP Top 10 for Agentic
Applications, 2026 edition, published by the OWASP GenAI Security Project; NIST
SP 800-53 Rev 5; Regulation (EU) 2024/1689, the AI Act; ISO/IEC 42001:2023.
Protocol references are the IETF RFCs cited in section 2.

Figures are sourced from the guardrail catalog, the published H100 benchmark
with FP8 serving, the red-team suite, the compliance mapping, the customer
threat model, and the non-human identity specification. Latency, cost and
detection figures describe the benchmarked configuration and will differ on
other hardware, other policy sets and other traffic mixes. Benchmark on your own
workload before committing to a latency budget.
