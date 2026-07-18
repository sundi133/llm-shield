# Guardrails Gap Analysis and Implementation Plan

Date: 2026-07-18
Input: customer document "AI Guardrails Coverage Plan" (phased checklist of guardrail
categories beyond a runtime guardrail platform).
Method: every item in the customer plan was verified against this codebase with
file-level evidence. Verdicts: IMPLEMENTED, PARTIAL, or MISSING.

Bottom line: the baseline the customer plan assumes (prompt injection, PII/secrets,
toxicity, tool authorization, MCP validation, taint tracking, HITL, budgets, audit
chain) is genuinely implemented here. The major gaps that need work are:

1. Model-output sanitization (HTML/XSS, markdown, SQLi) - MISSING
2. PII redaction of telemetry/log bodies before storage - MISSING
3. AI disclosure and regulated-domain disclaimers (EU AI Act) - MISSING
4. Per-user probing / near-miss bypass detection - MISSING
5. Right-to-be-forgotten workflow and deletion propagation - MISSING
6. Image OCR / multimodal input scanning - MISSING (PDF/DOCX/XLSX exist)
7. Multi-model eval matrix + scheduled red-team cadence - MISSING (corpus exists)
8. Governance instrumentation (disparate-impact rates, regurgitation checks,
   CSAM/CBRN/election runtime categories, NIST/ISO/EU evidence packs) - PARTIAL

Each proposed task below must get its own spec (`/spec`, `docs/spec-template.md`)
before implementation, one scoped task per PR, per CLAUDE.md.

---

## 1. Verified coverage vs. the customer plan

### Already implemented (no work needed, cite these to the customer)

| Customer plan item | Evidence |
|---|---|
| Prompt injection / jailbreak detection | `guardrails/input/adversarial.py` (LLM classifier, 40+ categories, ROT13/base64/hex/URL decode), `guardrails/input/system_prompt_leak.py` |
| Indirect injection in retrieved docs | `guardrails/agentic/tool/indirect_injection_detection.py:41` (provenance-driven scan of tool/retrieved/web/file content), `tests/test_indirect_injection.py` |
| PII/secrets detection, input and output | `guardrails/input/pii_detection.py`, `guardrails/output/pii_leakage.py:13-45` (SSN, CC, API keys, AWS keys, passwords, bank, passport; optional Presidio) |
| Toxicity / hate / harassment / sexual | `guardrails/input/toxicity.py:44`, `guardrails/input/adversarial.py:205` |
| Hallucination / groundedness | `guardrails/output/factual_grounding.py:37`, `guardrails/output/hallucinated_links.py` |
| Schema/format validation | `core/llm_backend.py:458,566,619` (strict `json_schema` response_format) |
| Tool authorization + allowlists | `guardrails/agentic/tool/tool_allowlist.py:49-133` (deny-by-default, agent AND role intersection), `core/rbac.py:49`, `api/routes_agents_registry.py:71-99` |
| MCP validation + taint tracking | `core/mcp/enforcement.py`, `core/mcp/proxy_server.py` (`_scan_for_poisoning`), `guardrails/agentic/taint/taint_tracking.py` |
| Goal-drift detection | `guardrails/agentic/intent/goal_drift_detection.py`, `tests/test_goal_drift.py` |
| Human-in-the-loop for high-risk actions | `core/approvals.py:159-309` (signed single-use Ed25519 grants bound to tool+params+instance+session), gates at `api/routes_tool.py:425-471` and `api/routes_agent_auth.py:249-315`; `core/risk.py:41-47` auto-flags payment/refund/delete/exec as HIGH |
| Token budgets, cost caps, alerts at 80% | `guardrails/agentic/scope/budget_controls.py:38-85` (hourly/daily tokens, `max_cost_daily_usd`, `warning_threshold_pct`), `storage/rate_limiter.py:63-68` (per-tenant daily) |
| Tool-call depth / loop limits | `guardrails/agentic/scope/delegation_control.py:44-49` (max_depth, circular-delegation block), `guardrails/agentic/scope/loop_detection.py` |
| Per-tool / per-session rate limits | `guardrails/agentic/tool/tool_call_rate_limiting.py:27-59`, `guardrails/input/rate_limiter.py` |
| Memory injection detection + TTLs | `guardrails/agentic/memory/memory_injection_detection.py:33-99`, `memory_retention_policies.py:29-81`, `memory_pii_scrubbing.py` |
| CSP / security headers | `core/security_headers.py:41-50,129-174` (CSP, X-Frame-Options, HSTS, cookie hardening) |
| Tamper-evident audit trail | `storage/audit_log.py:33` + `storage/audit_chain.py` (Ed25519-signed hash chain), `tests/test_audit_chain.py` |
| Per-tenant policy, RBAC, mTLS | `core/policy_inheritance.py`, `core/rbac.py:17`, `core/mtls_middleware.py:27` |
| Red-team corpus | `guardrails-red-team-suite/` (13 industries, ~1,850 adversarial + 250 safe prompts each, 185-technique taxonomy) |
| MCP supply chain | `.github/workflows/mcp-registry.yml` (weekly scheduled scan, pinned versions, checksum-verified binary) |
| File upload scanning (text formats) | `api/routes_classify.py:375-437` (`POST /guardrails/file`: PDF/DOCX/XLSX extraction through the input pipeline) |

### Verified gaps

| Customer plan item | Verdict | What is actually missing |
|---|---|---|
| Insecure output handling | MISSING | No HTML/markdown sanitization of model output, no SQLi/exec detection on generated content. Only agent-registration input is sanitized (`api/routes_agents_registry.py:36-44`); `tool_output_sanitization.py` covers PII only |
| Log hygiene | MISSING (core part) | `core/telemetry.py:72-74,148,208-209` ships raw prompt/response/tool bodies with only truncation and header redaction (`:629-640`); no PII scrub of bodies, no time-based retention (size rotation only, `:460-480`) |
| User disclosure / disclaimers | MISSING | No AI-disclosure banner, no legal/medical/financial disclaimer injection; confidence is computed but never surfaced to users |
| Bypass/probing detection | MISSING | `core/auto_revoke.py:140-175` fires on a single trigger block; no per-user near-miss counters, no persistent per-user anomaly score |
| Session USD cap, e2e timeout | PARTIAL | Per-session caps are tokens/calls only (`budget_controls.py:60-73`); timeouts are per-tier/per-call, no end-to-end wall clock |
| Row-count caps on DB reads | MISSING | Bulk retrieval detected heuristically (`payload_risk.py:62,128`) but no numeric ceiling |
| RAG hardening | PARTIAL | Injection scan of retrieved docs exists; no vector DB integration at all, so no cross-tenant vector isolation or document provenance/signing |
| Memory write consent | MISSING | No consent gate in `guardrails/agentic/memory/` |
| Multimodal | PARTIAL | PDF/DOCX/XLSX yes; no OCR, no image/audio ingestion, no image-injection detection |
| Model-swap testing | PARTIAL | Backends switchable (`core/llm_backend.py:202-230`: vLLM/LiteLLM/Ollama/OpenRouter) but no multi-model eval matrix or drift tracking |
| Red-team cadence | PARTIAL | Rich corpus, manual bash runners only; no scheduled CI red team |
| Bias / disparate impact | PARTIAL | Content-level `guardrails/output/bias_detection.py` exists; no protected-class sampling or approval/denial-rate tracking |
| IP / copyright | PARTIAL | `competitor_mention.py` keyword filter only; no regurgitation/n-gram check, no license scanning, no trademark blocklist |
| Wellbeing red lines | PARTIAL | self-harm/harmful/sexual live in `adversarial.py:202-205`; CSAM and CBRN exist only in finetune dataset scripts; election integrity absent everywhere |
| Multilingual coverage | PARTIAL | Language detection yes (`language_detection.py`); no per-language safety evals or thresholds |
| Model supply chain | PARTIAL | MCP side covered; no model SBOM, provenance verification, or HF review workflow; `model_version` is a self-reported string (`api/routes_agent_auth.py:74`) |
| Data lifecycle / RTBF | PARTIAL | Memory TTLs and `retention_days` config exist; no right-to-be-forgotten workflow, no deletion propagation across logs/stores |
| At-rest encryption, residency | PARTIAL | mTLS in transit; at-rest and residency are deployment concerns, not enforced in code |
| Compliance evidence packs | PARTIAL | Audit + evidence packs implemented, but `storage/evidence_pack.py:281` covers only HIPAA/PCI/GDPR/generic; NIST AI RMF, OWASP LLM Top 10, ISO 42001, EU AI Act are doc-only (`docs/compliance-mapping.md`) |

---

## 2. Implementation plan

Ordering follows customer risk: exploitable-today first, then compliance-blocking,
then governance instrumentation. Each row is one spec + one PR.

### P0: critical, weeks 1-3

| # | Task | Plane | Scope sketch |
|---|---|---|---|
| P0-1 | Output-content safety guardrail: HTML/script escaping or stripping, markdown sanitization, SQLi/exec-pattern detection on model output. New `guardrails/output/content_safety.py` (fast tier, regex + allowlist), opt-in per tenant, XSS/SQLi payloads added to test suite | Data | New output guardrail registered in `guardrails/registry.py`; escape-hatch env flag per repo invariant |
| P0-2 | Telemetry/log PII redaction: reuse `pii_leakage` patterns to scrub `votal.input_text`, `request.body`, `response.body`, tool payloads in `core/telemetry.py` before buffer/SIEM/file export; add time-based retention to FileExporter | Both | Must be off the hot path: redact at export, not in-request; benchmark before/after |
| P0-3 | Probing/bypass detection: per-user/agent sliding-window counters of blocks and near-misses (scores just under threshold) in Redis; threshold flags feed `core/risk.py` and optionally `core/auto_revoke.py`; surfaced in telemetry | Data | Counter write must be async/fire-and-forget off the guard path |
| P0-4 | AI disclosure + disclaimer injection: output guardrail that prepends/appends tenant-configured disclosure text and legal/medical/financial disclaimers (topic-triggered via existing topic classification); low-confidence flag passthrough in response metadata | Data + Admin (config UI) | EU AI Act Art. 50 driver; opt-in, non-breaking |

### P1: high value, weeks 4-8

| # | Task | Plane | Scope sketch |
|---|---|---|---|
| P1-1 | RTBF workflow: `DELETE /governance/subject-data` admin endpoint that propagates deletion to memory store, telemetry files, audit metadata (chain-safe tombstones), with completion report per SLA | Admin | Ties into existing `retention_days` config; evidence-pack entry |
| P1-2 | Image OCR pipeline: extend `POST /guardrails/file` to images (OCR text through existing input pipeline), and flag non-OCRable content; audio out of scope for v1 | Data | New deps declared in all three requirements files; Dockerfile allowlist check |
| P1-3 | Hard blast-radius caps: numeric row-count/result-size ceiling on tool results, per-session USD cost cap, end-to-end request wall-clock timeout | Data | Small additions to `budget_controls.py` / `tool_call_validation.py` |
| P1-4 | Scheduled red team + model matrix: GitHub Actions cron running a sampled red-team suite against configured backends (vLLM default + Nemotron + any LiteLLM target), storing scored results and diffing pass rates over time (drift) | CI | Reuses `guardrails-red-team-suite/`; report artifact per run |
| P1-5 | Wellbeing red lines as runtime categories: promote CSAM, CBRN, election-integrity to first-class categories in `adversarial.py` taxonomy with fail-closed defaults; port prompts from finetune dataset into tests | Data | Fail-closed is a behavior change: ship behind default-on-with-escape-hatch flag |

### P2: governance and enterprise asks, weeks 9+

| # | Task | Plane | Scope sketch |
|---|---|---|---|
| P2-1 | Evidence packs for NIST AI RMF, OWASP LLM Top 10, ISO 42001, EU AI Act: extend `storage/evidence_pack.py` FRAMEWORKS using mappings already written in `docs/compliance-mapping.md` | Admin | Doc-to-code lift, low risk, high sales value |
| P2-2 | Disparate-impact monitoring: sampled decision logging by tenant-declared cohort attribute, approval/denial-rate report in board report | Admin | Analytics only, off hot path |
| P2-3 | IP/copyright: n-gram verbatim-overlap check against tenant-supplied corpora, trademark blocklist (extend competitor_mention), license-header scan on generated code | Data | Fast-tier where possible |
| P2-4 | Per-language safety evals: run red-team sample per served language, per-language thresholds in config | CI + Data | Builds on P1-4 |
| P2-5 | Model supply chain: pinned model manifest with checksums verified at `start_vllm.sh` boot, SBOM for inference stack, HF model review checklist | Data + CI | |
| P2-6 | Memory-write consent flag + per-tenant namespacing of remaining non-prefixed state keys (`retention:*`, `budget:*`) | Data | Small, closes tenant-isolation nit |
| P2-7 | RAG/vector-DB hardening | Depends | No vector DB integration exists in Shield today. Decide first whether this is in product scope or customer-stack guidance; if in scope, spec a retrieval proxy with tenant-namespace enforcement and document provenance tags |

### Explicitly out of scope for the platform (tell the customer)

- Shadow-AI network DLP, org policy: organizational controls, not Shield features.
- At-rest encryption and data residency: satisfied by self-host/air-gap deployment
  (`docs/on-premises-deployment-guide.md`); no code change planned.
- Training-data controls (consent tracking, memorization audits): only relevant if
  the customer fine-tunes; revisit if that lands.

## 3. Cross-cutting metrics (customer plan section, mostly available today)

Block rate, false-positive rate, p95 guardrail latency, and cost per call are already
emitted via `core/telemetry.py` / SIEM export; "unique attack patterns" and "mean
time to patch a bypass" become reportable once P0-3 (probing detection) and P1-4
(scheduled red team) land. A small board-report addition can surface all six weekly.
