# Votal Shield — Sales Battle-Card

A one-page reference for live customer calls. Each entry: the **objection**,
the **mechanism-first answer**, the **follow-up jab** they'll throw, and a
**⚠️ verify** note where you must confirm shipped-vs-roadmap before promising.

**Two rules that win every call:**
1. **Lead with the mechanism, not the conclusion.** Say "No/Yes" then
   immediately "...because here's how it works."
2. **Calibrated honesty beats overclaiming.** "That's roadmap" / "that's
   policy-driven" / "no one's 100% on injection" builds more trust with
   security and compliance buyers than a confident claim that gets caught.

**The one-sentence frame:** *Your IdP authenticates your humans; Shield sits
downstream and governs what your agents are allowed to actually do — per
action, short-lived, scoped, revocable, and audited.*

---

## Personas & what they probe

| Persona | Cares about | Favorite trap |
|---|---|---|
| 🛡️ Security Architect | Trust model, key handling, blast radius | "What happens when X is stolen?" |
| ⚙️ Platform Engineer | Latency, throughput, failure modes | "What breaks at scale / when you're down?" |
| 📋 Compliance / GRC | Audit, residency, standards | "Prove it for my auditor." |
| 💰 Skeptical CTO / Buyer | Differentiation, lock-in | "Why not just use Okta / my gateway?" |
| 👩‍💻 Integrating Developer | How to wire it up | "Show me the 3 calls my code makes." |

---

## ROUND 1 — Foundations

### Q1 · Developer — "What do I give you, what changes in my code?"
**Three things, only the first is one-time:**
- **One-time:** register your Keycloak with us — issuer URL + client ID. We auto-discover the rest.
- **Per process:** take the user's existing IdP login, call us once to mint a short-lived **agent token** (proves *who*, ~15 min, cached & reused).
- **Per action:** right before a real action (send email, move money), mint a **capability**; the tool verifies it. SDK wraps all three.

*Jab — "Days or weeks?"* → "Hours. Pip-installable SDK, three methods; Keycloak registration is one API call or a portal form."

### Q2 · Security Architect — "Do you ever see passwords or our private keys?"
**No — and structurally impossible, not just policy:**
- Your **LDAP/AD never touches us** — it stays behind Keycloak, in your network. We don't speak LDAP.
- We only hold your IdP's **public** keys, pulled from your standard **JWKS** endpoint. Public keys *verify* signatures, can never *forge* or decrypt.
- We see a *signed badge* your Keycloak already issued, and we check the signature. That's the whole trust relationship.

*Jab — "If YOU get breached?"* → "Attacker gets our public keys (already public) and tokens that expire in minutes. They can't impersonate your users — that needs your IdP's private key, which we never have."

### Q3 · Platform Eng — "A round-trip on every LLM call? That's latency + a SPOF."
**Premise is wrong — we do NOT touch your LLM calls:**
- Agent token minted **once per process**, cached ~15 min, reused across thousands of calls — effectively free.
- We're only in the path on an **action** (send_email, transfer_funds). Even there, crypto is ~50µs vs an LLM call of ~1s+ — ~30,000× faster than what it protects.
- Tool servers can verify capabilities **locally** with our public key — no call to us. You decide which tools even need a cap; trivial reads skip it.

*Jab — "And if you're down during a dangerous action?"* → bridges to Q4.

---

## ROUND 2 — The hard round

### Q4 · Platform Eng — "If Shield is down, does the payment go through or block?"
**You choose, per tool — fail-closed vs fail-open:**
- **Fail-closed** = can't authorize → action **blocked** (safe).
- **Fail-open** = unreachable → action **allowed** (available).
- Set **fail-closed** for payments/deletes, **fail-open** for low-risk reads. Dangerous actions stay protected even during an outage. Local cap verification means a dead control plane doesn't stop already-issued caps.

*Jab — "Default if I configure nothing?"* → "Fail-closed on anything that mutates state. Secure by default; opt into fail-open."
⚠️ **Verify** your deployment actually defaults fail-closed for state-changing tools before promising it.

> ❌ Never say "your apps can run unauthorized calls." Say "fail-closed by default, configurable per tool."

### Q5 · CTO — "Why not just use my Okta OAuth scopes?"
**Agents break three OAuth assumptions:**
1. **One token = one principal.** An agent action has a human + an agent + often a delegating parent. OAuth carries one subject; we carry the whole chain.
2. **Permission = identity only.** OAuth can't say "send_email *but only internal, only once, only if no PII leaks*." Safety depends on *what's in* the action, not just who calls. We decide per-action with context.
3. **Static & long-lived.** OAuth access token = broad, ~1hr. Our cap = one tool, one resource, one use, 60s. If injection hijacks the agent, OAuth is a skeleton key; our cap opens one door once.

"Keep Okta — it authenticates your *humans*. We sit downstream and govern what the *agent* does. We federate with your IAM, we don't replace it."

*Jab — "Isn't a layer on top just more complexity?"* → "The alternative is hard-coding tool perms into every agent and hoping nobody injects them. We make it policy — auditable and revocable in one place."

### Q6 · Compliance — "Show every action by this user Tuesday, and prove no tampering."
**Two parts — answer both:**
1. **Produce it:** one signed audit row **per action** (not per session), tagged `trace.id`, `agent.key`, `tenant_id`, `user_sub`. Filter by user + date is a query. Flows to **your SIEM** (Splunk / Elastic / OTLP) — lives in your system of record.
2. **Integrity:** each decision row is **signed** so you can verify/replay the original. For hard immutability, stream to write-once storage (object-lock / append-only).

⚠️ **Verify:** signed per-action rows + SIEM export ship today; **immutable write-once storage is roadmap** in the docs. Say "signed rows + SIEM today; immutable storage on roadmap / available with X." Never demo an overclaim to an auditor.

---

## ROUND 3 — Closing-stage

### Q7 · Security Architect — "Prompt injection emails customer data to an attacker. Where does it die?"
**Defense-in-depth — attacker must beat all of these:**
1. **Exact-scope cap** — bound to specific tool + resource + recipient scope. `attacker@evil.com` is outside scope → mint denied / verify rejects. Can't widen an issued cap.
2. **RBAC + clearance ceiling** — exfiltrating `confidential` data above the role's ceiling is denied before any cap mints.
3. **Output guardrails** — PII detection/redaction catches customer records on the way out, regardless of caller.
4. **Taint tracking** — data tagged by origin; sensitive ("tainted") data is blocked from flowing to an external sink.
5. **Per-action audit** — every denial (even the attempt) is logged and alertable.

**Honest close:** "No one's 100% on prompt injection — it's open research. We make a *single* injection insufficient: the attacker must break multiple independent controls, and every attempt is logged."

*Jab — "Which are on by default?"* → ⚠️ **Verify per tenant.** Scope + RBAC are intrinsic to the cap system. Output redaction & taint tracking exist (`taint_tracking.py`, `data_access_guard.py`, `role_redaction.py`) but are **toggleable per-tenant policy** — say "we enable them during onboarding for an exfiltration threat model." Don't claim all five are on out-of-the-box unless confirmed.

### Q8 · CTO — "How hard to rip you out? Are my agents permanently dependent?"
**Low lock-in by design:**
1. **Standards, not proprietary** — tokens are plain **JWT (RFC 7519)** with a published **JWKS**; integration is standard **OAuth 2.1 / RFC 8693**. Any JWT library reads them.
2. **Your identity stays yours** — root of identity is your Keycloak/LDAP, untouched if you remove us. We're downstream.
3. **Tiny surface** — three SDK calls. Removing us = deleting an integration, not unwinding a dependency. No state stored inside your agents.
4. **On-prem** — you run it; no SaaS we can pull.

*Jab — "What do I lose if I remove you?"* → "Per-action authorization, guardrails, and the audit trail — agents go back to trusted-by-default. You don't lose access, identity, or data. We're additive."

### Q9 · Platform Eng — "Agent swarms: who did what, and can a sub-agent exceed the orchestrator?"
**Two mechanisms — visibility + containment:**
- **Delegation chain (visibility):** every agent has its own `agent_id` + unique `agent_instance_id`; sub-agents carry `parent_agent_id` back to the orchestrator, and caps carry `parent_cap_id`. Reconstruct the whole tree — every action, who delegated it, up to which human.
- **Scope intersection (containment):** a delegated cap is always a **subset** of the parent's authority — never a superset. Downstream can narrow, never widen. A confused/compromised sub-agent is capped at-or-below its parent.
- Plus delegation-depth and budget controls so one orchestrator can't fan out into runaway tool calls.

*Jab — "Kill just sub-agent #7 without taking down the swarm?"* → "Yes — revoke that `agent_instance_id`, dead within ~1s on its next action; others keep running. Three kill switches: one instance, one user (`user_sub`), or one token (`jti`)."
⚠️ **Verify:** primitives exist (`scope/delegation_control.py`, `scope/scope_boundaries.py`, `scope/budget_controls.py`, `parent_agent_id`/`parent_cap_id` claims). Confirm scope-intersection is **enforced at mint time** in your build before saying "mathematically capped" — else say "enforced by policy."

---

## Reflexes to drill
- **Kill-chains beat walls** — for "can attacker do X," list independent layers that must *all* fail.
- **Turn exit/SPOF questions into value** — "how do I leave" → "here's what you'd give up"; "single point of failure" → "here's where we're *not* in the path."
- **Calibrated honesty** — every ⚠️ is a spot where the honest answer wins the security/compliance buyer.

## Glossary (fast)
**AuthN** = who you are · **AuthZ** = what you may do · **LDAP/AD** = your internal user directory · **IdP** (Keycloak/Okta) = login system in front of LDAP · **OIDC** = standard for issuing/checking login badges · **JWT** = the signed badge · **JWKS** = public page of the IdP's public keys (what we "sync") · **Agent token** = Shield badge proving *who* (~15 min, per process) · **Capability/cap** = one-action permit (≤60s, single-use) · **Nonce** = one-time value that blocks replay · **RBAC** = permissions by role (from LDAP group) · **Clearance** = data sensitivity ceiling · **Revocation** = instant kill switch (instance / user / token).
