---
title: Compliance Mapping
layout: default
nav_order: 16
permalink: /compliance-mapping/
---

# Compliance Mapping — Votal Shield Guardrails

This document maps Votal Shield guardrails to industry compliance frameworks to help security, risk, and audit teams evidence control coverage.

Frameworks covered:
- NIST AI Risk Management Framework (AI RMF 1.0)
- OWASP Top 10 for LLM Applications
- NIST SP 800-53 (Security and Privacy Controls)
- EU AI Act (High-Risk AI Systems)
- ISO/IEC 42001 (AI Management System)

## 1. NIST AI Risk Management Framework (AI RMF 1.0)

### GOVERN Function — Organizational Controls

| Control ID | Requirement | Votal Shield Coverage |
|---|---|---|
| **GOVERN 1.4** | Legal and regulatory requirements are understood, managed, and documented | `pii_detection`, `pii_leakage` (GDPR/HIPAA/CCPA), `data_access_guard`, per-tenant data isolation |
| **GOVERN 1.5** | Ongoing monitoring and periodic review of risk management | Telemetry to Elasticsearch SIEM, Kibana dashboards, audit logs |
| **GOVERN 1.6** | Mechanisms are in place to inventory AI systems and assess risk | Tenant registry, `agent_key` → role mapping, guardrail registry |
| **GOVERN 4.1** | Organizational accountability structures exist | `rbac_guard`, `agent_key` tracing, per-tenant isolation, audit trail |
| **GOVERN 4.3** | Organizational practices for testing and evaluation | Per-guardrail latency/block rate metrics in telemetry |
| **GOVERN 5.1** | Engagement with external stakeholders | Exportable telemetry events (ECS-compliant) for compliance reporting |
| **GOVERN 6.1** | High-risk AI systems managed with appropriate controls | `budget_controls`, `rate_limiter`, `sensitive_action_confirmation`, `action_guard` |

### MAP Function — Context and Risk Identification

| Control ID | Requirement | Votal Shield Coverage |
|---|---|---|
| **MAP 2.3** | AI system purpose and use are documented | `topic_enforcement` (system purpose enforcement), `scope_boundaries` per role |
| **MAP 3.4** | Risks mapped to business context | `data_access_guard`, `action_classification`, `tool_allowlist` per role |
| **MAP 4.1** | Impact assessment of AI system risks | `action_classification` with `max_risk_per_role` |
| **MAP 5.1** | Likelihood and impact of identified risks assessed | `event.risk_score` (0-100) computed per event, severity mapping |
| **MAP 5.2** | Risks and benefits characterized | Full telemetry schema with `attack_type`, `blocked_guardrails`, `risk_score` |

### MEASURE Function — Trustworthiness Characteristics

| Control ID | Characteristic | Votal Shield Coverage |
|---|---|---|
| **MEASURE 2.3** | Valid and Reliable | `safety_check`, `adversarial_detection`, `factual_grounding`, `hallucinated_links` |
| **MEASURE 2.5** | AI system performance is evaluated | Per-guardrail latency metrics, block rates via telemetry |
| **MEASURE 2.6** | Safe | `safety_check`, `keyword_blocklist`, `toxicity`, `topic_restriction`, `topic_enforcement` |
| **MEASURE 2.7** | Secure and Resilient | `adversarial_detection`, `system_prompt_leak`, `regex_pattern`, `rate_limiter`, `memory_injection_detection` |
| **MEASURE 2.8** | Accountable and Transparent | Telemetry with `trace.id` + `agent.key`, `audit_log`, `chain_of_thought_monitoring` |
| **MEASURE 2.9** | Explainable and Interpretable | `guardrail_results` with reasoning, telemetry events tagged with `attack_type` |
| **MEASURE 2.10** | Privacy-Enhanced | `pii_detection`, `pii_leakage`, `memory_pii_scrubbing`, `role_redaction` |
| **MEASURE 2.11** | Fair, with Harmful Bias Managed | `bias_detection`, `tone_enforcement` |
| **MEASURE 2.13** | Effectiveness | Per-guardrail metrics via telemetry (latency, block rate, false positive tracking) |
| **MEASURE 3.1** | Approaches identified for TEVV | Guardrail pipeline with tiered execution (fast/medium/slow) |
| **MEASURE 4.2** | Measurement results are captured | Elasticsearch SIEM stores all events with ECS-compliant schema |

### MANAGE Function — Risk Response

| Control ID | Requirement | Votal Shield Coverage |
|---|---|---|
| **MANAGE 1.3** | AI risks are treated based on priority | Guardrail `action` field (`block`/`warn`/`log`) + `event.risk_score` tiering |
| **MANAGE 2.3** | Mechanisms exist to sustain AI system value | Runtime config updates via `/v1/shield/config`, `/v1/admin/tenants` |
| **MANAGE 2.4** | Mechanisms to supersede, disengage, or deactivate AI | `sensitive_action_confirmation`, `action_guard`, `rbac_guard` block capabilities |
| **MANAGE 3.1** | AI risks and benefits from third-party resources | `mcp_guard` with trust scoring, `tool_allowlist` |
| **MANAGE 4.1** | Post-deployment AI monitoring | Full telemetry pipeline to Elasticsearch/SIEM, `chain_of_thought_monitoring`, `loop_detection` |
| **MANAGE 4.2** | Measurable continuous improvement | Audit logs, per-guardrail metrics, Kibana dashboards |
| **MANAGE 4.3** | Incidents and errors communicated | ES alerts on `event.kind: "alert"` + `event.severity: "critical"` |

## 2. OWASP Top 10 for LLM Applications

| OWASP ID | Risk | Votal Shield Guardrails |
|---|---|---|
| **LLM01** | Prompt Injection | `adversarial_detection`, `memory_injection_detection`, `system_prompt_leak`, `chain_of_thought_monitoring` |
| **LLM02** | Insecure Output Handling | `tool_output_sanitization`, `pii_leakage`, `role_redaction`, `regex_pattern` |
| **LLM03** | Training Data Poisoning | (out of scope — requires model training controls) |
| **LLM04** | Model Denial of Service | `rate_limiter`, `length_limit`, `budget_controls`, `tool_call_rate_limiting`, `loop_detection` |
| **LLM05** | Supply Chain Vulnerabilities | `mcp_guard` with MCP server trust scoring |
| **LLM06** | Sensitive Information Disclosure | `pii_detection`, `pii_leakage`, `memory_pii_scrubbing`, `data_access_guard`, `system_prompt_leak` |
| **LLM07** | Insecure Plugin Design | `tool_allowlist`, `tool_use_control`, `tool_call_validation`, `mcp_guard` |
| **LLM08** | Excessive Agency | `action_guard`, `sensitive_action_confirmation`, `scope_boundaries`, `delegation_control` |
| **LLM09** | Overreliance | `factual_grounding`, `hallucinated_links`, `chain_of_thought_monitoring` |
| **LLM10** | Model Theft | `rate_limiter`, `rbac_guard`, `audit_log`, `budget_controls` |

## 3. NIST SP 800-53 Rev 5 (Security and Privacy Controls)

### Access Control (AC)

| Control ID | Requirement | Votal Shield Coverage |
|---|---|---|
| **AC-2** | Account Management | `rbac_guard`, tenant API key management via `/v1/admin/tenants` |
| **AC-3** | Access Enforcement | `rbac_guard`, `scope_boundaries`, `data_access_guard` |
| **AC-4** | Information Flow Enforcement | `data_access_guard`, `scope_boundaries`, per-role resource access |
| **AC-5** | Separation of Duties | `rbac_guard` with per-role tool/data restrictions |
| **AC-6** | Least Privilege | `tool_allowlist`, `action_guard`, per-role data clearance |
| **AC-7** | Unsuccessful Logon Attempts | `rate_limiter` (per-agent rate limiting) |

### Audit and Accountability (AU)

| Control ID | Requirement | Votal Shield Coverage |
|---|---|---|
| **AU-2** | Event Logging | `TelemetryMiddleware` → Elasticsearch SIEM |
| **AU-3** | Content of Audit Records | Full event schema (ECS-compliant) with timestamp, source, action, outcome |
| **AU-6** | Audit Record Review, Analysis, and Reporting | Kibana dashboards, alerts on high-risk events |
| **AU-9** | Protection of Audit Information | SIEM with API key auth, immutable log storage |
| **AU-12** | Audit Record Generation | `audit_log` SQLite + ES exporter |

### Identification and Authentication (IA)

| Control ID | Requirement | Votal Shield Coverage |
|---|---|---|
| **IA-2** | Identification and Authentication | API key auth (`AuthMiddleware`), `agent_key` identity |
| **IA-5** | Authenticator Management | SHA-256 hashed API keys, rotation via env vars |
| **IA-8** | Identification and Authentication (non-organizational) | Per-tenant API keys, tenant-scoped identities |

### System and Communications Protection (SC)

| Control ID | Requirement | Votal Shield Coverage |
|---|---|---|
| **SC-7** | Boundary Protection | `scope_boundaries`, `rbac_guard`, multi-tenant isolation |
| **SC-8** | Transmission Confidentiality and Integrity | HTTPS required for telemetry exporters (ES, Splunk, OTLP) |
| **SC-28** | Protection of Information at Rest | `memory_pii_scrubbing`, `role_redaction` |

### System and Information Integrity (SI)

| Control ID | Requirement | Votal Shield Coverage |
|---|---|---|
| **SI-3** | Malicious Code Protection | `keyword_blocklist`, `regex_pattern`, `adversarial_detection` |
| **SI-4** | System Monitoring | `chain_of_thought_monitoring`, `context_window_guardrails`, telemetry pipeline |
| **SI-7** | Software, Firmware, Information Integrity | `tool_call_validation`, `memory_guardrails` |
| **SI-10** | Information Input Validation | `regex_pattern`, `length_limit`, `keyword_blocklist`, `tool_call_validation` |
| **SI-11** | Error Handling | Graceful guardrail failure handling (pipeline catches exceptions per guardrail) |

## 4. EU AI Act (High-Risk AI Systems)

| Article | Requirement | Votal Shield Coverage |
|---|---|---|
| **Art. 9** | Risk Management System | Full guardrail pipeline + SIEM telemetry + audit logs |
| **Art. 10** | Data and Data Governance | `pii_detection`, `data_access_guard`, `memory_pii_scrubbing` |
| **Art. 12** | Record-Keeping | Audit logs (SQLite) + ES telemetry (immutable event log) |
| **Art. 13** | Transparency and Provision of Information | `guardrail_results` in API responses with reasoning |
| **Art. 14** | Human Oversight | `sensitive_action_confirmation`, `action_guard`, workflow approval gates |
| **Art. 15** | Accuracy, Robustness, and Cybersecurity | `adversarial_detection`, `rate_limiter`, `budget_controls`, `regex_pattern` |
| **Art. 17** | Quality Management System | Per-guardrail metrics, continuous monitoring via SIEM |
| **Art. 61** | Post-Market Monitoring | Telemetry pipeline, incident alerts, Kibana dashboards |

## 5. ISO/IEC 42001 (AI Management System)

| Clause | Requirement | Votal Shield Coverage |
|---|---|---|
| **6.1.2** | AI risk assessment | `event.risk_score`, per-guardrail risk tiers |
| **6.1.3** | AI risk treatment | Guardrail `action` field (block/warn/log), runtime config updates |
| **8.2** | AI system impact assessment | `action_classification` with risk scoring per role |
| **8.3** | AI system design and development | Guardrail pipeline with three-tier execution (fast/medium/slow) |
| **8.4** | Third-party relationships | `mcp_guard`, `tool_allowlist`, per-tenant isolation |
| **9.1** | Monitoring, measurement, analysis, evaluation | Full telemetry pipeline to SIEM |
| **9.2** | Internal audit | `audit_log` with query API |
| **10** | Improvement | Runtime guardrail config updates, continuous metrics |

## 6. Guardrail → Control Reverse Index

Quick lookup: given a guardrail, what controls does it cover?

| Guardrail | NIST AI RMF | OWASP LLM | NIST 800-53 |
|---|---|---|---|
| `keyword_blocklist` | MEASURE 2.6 | LLM06 | SI-3, SI-10 |
| `length_limit` | MEASURE 2.7 | LLM04 | SI-10 |
| `regex_pattern` | MEASURE 2.7 | LLM01, LLM06 | SI-10 |
| `pii_detection` | MEASURE 2.10, GOVERN 1.4 | LLM06 | SC-28 |
| `rate_limiter` | MEASURE 2.7 | LLM04, LLM10 | AC-7 |
| `system_prompt_leak` | MEASURE 2.7 | LLM01, LLM06 | SI-4 |
| `toxicity` | MEASURE 2.6 | — | SI-3 |
| `safety_check` | MEASURE 2.3, 2.6 | LLM01 | SI-4 |
| `adversarial_detection` | MEASURE 2.7 | LLM01 | SI-3, SI-4 |
| `topic_restriction` | MEASURE 2.6 | — | AC-4 |
| `topic_enforcement` | MAP 2.3 | — | AC-4 |
| `role_redaction` | MEASURE 2.10 | LLM02 | SC-28 |
| `hallucinated_links` | MEASURE 2.3 | LLM09 | — |
| `tone_enforcement` | MEASURE 2.11 | — | — |
| `bias_detection` | MEASURE 2.11 | — | — |
| `pii_leakage` | MEASURE 2.10, GOVERN 1.4 | LLM02, LLM06 | SC-28 |
| `competitor_mention` | GOVERN 5.1 | — | — |
| `rbac_guard` | GOVERN 4.1 | LLM08 | AC-2, AC-3, AC-6 |
| `data_access_guard` | GOVERN 1.4, MAP 3.4 | LLM06 | AC-3, AC-4 |
| `mcp_guard` | MANAGE 3.1 | LLM05, LLM07 | SC-7 |
| `action_guard` | MANAGE 2.4 | LLM08 | AC-6 |
| `tool_allowlist` | MAP 3.4 | LLM07 | AC-6 |
| `tool_use_control` | MAP 3.4 | LLM07 | AC-3 |
| `tool_call_rate_limiting` | MEASURE 2.7 | LLM04 | AC-7 |
| `tool_call_validation` | MEASURE 2.7 | LLM07 | SI-7, SI-10 |
| `tool_output_sanitization` | MEASURE 2.10 | LLM02 | SC-28 |
| `sensitive_action_confirmation` | MANAGE 2.4 | LLM08 | AC-6 |
| `action_classification` | MAP 3.4, MAP 5.1 | LLM08 | AC-6 |
| `scope_boundaries` | GOVERN 4.1 | LLM08 | AC-3, AC-4, SC-7 |
| `loop_detection` | MEASURE 2.7 | LLM04 | SI-4 |
| `budget_controls` | GOVERN 6.1 | LLM04, LLM10 | — |
| `delegation_control` | GOVERN 4.1 | LLM08 | AC-5, AC-6 |
| `memory_guardrails` | MEASURE 2.7 | — | SI-7 |
| `memory_pii_scrubbing` | MEASURE 2.10 | LLM06 | SC-28 |
| `memory_injection_detection` | MEASURE 2.7 | LLM01 | SI-3, SI-4 |
| `memory_retention_policies` | GOVERN 1.4 | — | AU-11 |
| `memory_access_control` | GOVERN 4.1 | LLM06 | AC-3 |
| `chain_of_thought_monitoring` | MEASURE 2.8 | LLM01, LLM09 | SI-4 |
| `context_window_guardrails` | MEASURE 2.7 | LLM04 | SI-4 |

## 7. Evidencing Compliance

For auditors asking "how do you demonstrate control X?", point to:

| Evidence Type | Location |
|---|---|
| **Guardrail config** | `config/default.yaml` + per-tenant configs in Redis |
| **Event logs** | Elasticsearch index `votal-shield-logs*` |
| **Audit trail** | SQLite `audit.db` (queryable via `/v1/shield/audit`) |
| **Per-guardrail metrics** | `votal.guardrail.latency_ms`, `votal.guardrail.passed` in ES |
| **Risk scoring** | `event.risk_score`, `event.severity` in every event |
| **Trace correlation** | `trace.id`, `agent.key`, `votal.session_id` across all events |
| **Blocked attack samples** | Query ES for `event.kind: "alert" AND event.risk_score >= 90` |
| **RBAC enforcement** | `rbac_guard` decisions logged with `agent.key` + `votal.role_name` |

## 8. Kibana Queries for Compliance Reports

```
# LLM01 (Prompt Injection) — all blocked attacks
votal.attack_type: ("prompt_injection" OR "jailbreak") AND event.outcome: "failure"

# LLM06 (Sensitive Info Disclosure) — all PII events
votal.guardrail.name: ("pii_detection" OR "pii_leakage") AND votal.guardrail.passed: false

# MEASURE 2.10 (Privacy) — PII blocks by tenant
agent.key: acme-* AND votal.guardrail.name: pii_*

# MANAGE 4.3 (Incidents) — critical alerts last 24h
event.kind: "alert" AND event.severity: "critical" AND @timestamp >= "now-24h"

# AC-2 (Account Management) — new agent activity
agent.key: * AND event.action: "request"

# SI-4 (Monitoring) — all guardrail activity
NOT url.path: ("/health" OR "/ping")
```

## References

- [NIST AI RMF 1.0](https://www.nist.gov/itl/ai-risk-management-framework)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [EU AI Act](https://artificialintelligenceact.eu/)
- [ISO/IEC 42001:2023](https://www.iso.org/standard/81230.html)
