---
title: Human-in-the-Loop Approvals
layout: default
nav_order: 18
permalink: /hitl-approvals/
---

# Human-in-the-Loop Approvals (non-fakeable) + Break-Glass

High-risk tool calls can require a human to approve them first. The approval is a
**signed, single-use grant** bound to the exact action — not a status flag or a
cleartext token — so it cannot be forged by anyone with Redis/backup access, and
the agent cannot self-assert it.

Design rationale: [spec-hitl-breakglass.md](spec-hitl-breakglass.md).

## Enable

1. Provide a stable signing key (32-byte hex) on the data + admin planes:
   ```bash
   export SHIELD_APPROVAL_TOKEN_PRIVATE_KEY=$(python3 -c "import os;print(os.urandom(32).hex())")
   ```
2. Mark the tools that need approval, per tenant, via the control-plane config
   (`PUT /v1/tenant/me/agentic/config`):
   ```json
   { "approvals": { "enabled": true, "rules": [
       { "rule_id": "delete", "tool_names": ["delete_account"], "min_approvals": 1 }
   ]}}
   ```

## Flow

```
1. agent -> POST /v1/shield/tool/check {tool_name, tool_params, session_id}
      -> 200 {action:"pending_confirmation", guardrail_results:[{details:{request_id}}]}

2. human -> POST /v1/tenant/me/agentic/approvals/{request_id}/approve
      (portal/gateway forwards the SSO-verified approver as X-Approver-Sub)
      -> 200 {status:"approved", approval_grant:"<signed token>"}

3. agent -> POST /v1/shield/tool/check {tool_name, tool_params, session_id, approval_grant}
      -> 200 {allowed:true}   # grant verified: signature + tool + params + session + single-use
```

The grant is bound to `(tool, params_hash, session)` — changing an argument after
approval invalidates it (TOCTOU protection). It is single-use (nonce burned on
first `tool/check`) and dies instantly if the agent instance is revoked.

**Approver identity.** The approver is taken from an authenticated principal: if
your portal/gateway forwards an SSO-verified subject as `X-Approver-Sub`, the grant
records `method:"sso"`; otherwise the asserted value is recorded as
`method:"asserted"` so the audit reflects the trust level. Wire your IdP to set
`X-Approver-Sub` for non-repudiable approvals.

## Break-glass (emergency override)

Admin-only, mandatory reason, loud audit (`breakglass_used`) — mint a time-boxed
grant that `tool/check` accepts like any approval but flagged `breakglass:true`:

```bash
curl -X POST https://<shield>/v1/shield/breakglass \
  -H "X-Admin-Key: $ADMIN_KEY" -H "X-Admin-Sub: oncall@acme.com" \
  -d '{"tenant_id":"acme","agent_id":"bot","agent_instance_id":"pod-1",
       "tool":"delete_account","resource":"cust/1","session_id":"s1",
       "tool_params":{"account_id":"1"},"reason":"SEV1 remediation","ttl_seconds":600}'
# -> {"status":"issued","breakglass":true,"approval_grant":"<token>"}
```

Emergency **deny** is the existing instance/user/jti revocation
(`POST /v1/shield/auth/revoke`).

## Migration note — deprecated cleartext confirmation

The older `confirmation_token` from `sensitive_action_confirmation` is an in-memory
cleartext value and is **not a security control** — treat it as a UX "are-you-sure"
only. For enforcement, use the signed `approval_grant` described here. Existing
`approval_request_id` (status-flag) handling still works for backward compatibility
but is weaker than a signed grant; prefer `approval_grant`.

## Scope / follow-up

Enforcement is wired at the cooperative `tool/check` path (which carries the tool
arguments). Gating `cap/mint` for the non-bypassable L3 executor path is a planned
addition (it needs a `params_hash` on the mint request) — see the spec's open
questions.
