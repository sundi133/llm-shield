---
title: Tool call guardrails
parent: Rafay Integration
nav_order: 5
permalink: /partners/rafay/tools/
description: "Protect every tool call a customer's AI agents make: who may call which tool, what data may go into it, and what may come back, with one default policy that covers all tools."
---

# Tool call guardrails

Prompt screening protects what people type and what the model answers. Agents
also **call tools**: send an email, query a database, open a ticket. Each call is
a way for data to leave, or for an attacker's instructions to come in. Shield
checks tool calls at three points, and one default policy covers every tool a
customer has.

## Where Rafay sees tool traffic

The customer's application runs the tools; Rafay serves the model. Both
directions of tool traffic pass through Rafay's serving path:

```
customer app ── prompt ──► Rafay ──► model
customer app ◄── response with tool calls ── Rafay ◄── model     (1) and (2): check each call
customer app runs the tool
customer app ── next prompt + tool results ──► Rafay ──► model   (3): check each result
```

- **The model asks for a tool call** (`tool_calls` in its response): before
  returning the response, Rafay checks each call (checkpoints 1 and 2).
- **The application sends tool results back** (`role: "tool"` messages in the
  next request): before the model sees them, Rafay checks each result
  (checkpoint 3).

If the customer's tools are MCP servers behind Shield's MCP gateway, the gateway
runs all three checkpoints on every call and Rafay does not need to.

## The three checkpoints

All three use the customer's **serving key** (`runtime` scope) on
`https://api.guardrails.votal.ai`.

### 1 and 2. Before a tool call: `POST /v1/shield/tool/check`

One call checks both whether the call is allowed and whether its arguments
break the customer's data rules.

```json
{
  "agent_key": "rafay-cust-acme-support-bot",
  "tool_name": "send_email",
  "tool_params": { "to": "someone@example.com", "body": "..." },
  "user_role": "support",
  "session_id": "conversation-123",
  "tool_call_id": "call_abc"
}
```

| Field | Notes |
|---|---|
| `agent_key` | Required. A stable id for the customer's agent or app. Use the agent's id if the customer registered it in Shield (then its allowed-tool list applies); otherwise a stable id such as `rafay-cust-acme-default` |
| `tool_name`, `tool_params` | The call exactly as the model produced it. The arguments are what the data rules judge |
| `user_role` | The end user's role, if Rafay knows it. Role rules use it |
| `session_id` | The conversation. Approvals and cross-app flow control are per session |

Response:

```json
{ "allowed": false, "action": "block", "mode": "enforce", "would_block": true,
  "guardrail_results": [ { "guardrail": "tool_call_validation", "passed": false,
                           "action": "block", "message": "..." } ] }
```

| `action` | What Rafay does |
|---|---|
| `pass` (with `allowed: true`) | Return the tool call to the application |
| `block` | Do not return the call. Replace it with a short refusal so the model or application knows the call was stopped, citing the failing result's `message` |
| `pending_confirmation` | The tool needs a person's approval. Hold the call and tell the user it is waiting; the approver acts in the Shield portal, then the call is checked again with `approval_request_id` |

In monitor mode `allowed` is `true` and `would_block` says what enforce mode
would have done.

### Optional: redact arguments instead of blocking

To strip sensitive values from arguments but still let the call run, send the
arguments to `POST /guardrails/output` with
`"context": {"tool_name": "send_email", "stage": "input"}` and use
`sanitized_output` if present. It applies the all-tools default below and the
tool's own rules, the same policies `tool/check` judges.

### 3. After a tool runs: `POST /v1/shield/tool/output`

```json
{
  "tool_name": "crm_lookup",
  "tool_output": "...the result the application sent back...",
  "agent_key": "rafay-cust-acme-support-bot",
  "session_id": "conversation-123",
  "tool_call_id": "call_abc"
}
```

Response: `allowed`, `action` (`pass`, `redact`, `block`) and `sanitized_output`.
Pass `sanitized_output` to the model instead of the original result. On
`block`, replace the result with a short note that it was withheld. This is also
where instructions planted in a web page or document (indirect prompt injection)
are caught before the model reads them.

## One policy for all tools

A tool without its own policy is judged by nothing, so **set the default tool
policy for every customer at onboarding**. It applies to every tool the
customer has, including tools added later. Call it with the customer's
**settings key** (`admin` scope):

```bash
curl -X POST https://api.guardrails.votal.ai/v1/data-policies/global/policy \
  -H "X-API-Key: $SETTINGS_KEY" -H "Content-Type: application/json" \
  -d '{
    "sanitization_rules": [
      {"pattern_id": "us_ssn", "regex": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
       "replacement": "[SSN]", "description": "US social security number",
       "severity": "critical", "action": "redact"},
      {"pattern_id": "card", "regex": "\\b(?:\\d[ -]?){13,16}\\b",
       "replacement": "[CARD]", "description": "Payment card number",
       "severity": "critical", "action": "redact"}
    ],
    "sanitization_intent": "Never let credentials, API keys, or customer account numbers leave any tool, even reworded or split up.",
    "sanitization_mode": "both",
    "fail_closed": false,
    "enabled": true
  }'
```

| Field | Meaning |
|---|---|
| `sanitization_rules` | Patterns to find. Set `action` on each (`detect`, `redact` or `block`): without it, a match in arguments is only recorded and the tool still gets the value |
| `sanitization_intent` | A rule in plain words, judged by Shield's model, for what patterns miss (reworded or split-up data) |
| `sanitization_mode` | `regex`, `ai`, or `both` (patterns first, then the model) |
| `compliance_framework` | Optional: `hipaa`, `pci_dss` or `gdpr` |
| `fail_closed` | `true`: when the check cannot run, the call or result is blocked. No tool policy can turn this back off. Recommended for regulated customers |
| `enabled` | Turn the default off without deleting it |

Read it with `GET /v1/data-policies/global/policy`; remove it with `DELETE`.

**Per-tool policies** add rules for one tool on top of the default:
`POST /v1/data-policies/tools/{tool_name}/policy` (same fields). A tool policy
can only add restrictions; the default applies beneath it, and each keeps its
own allowlist, so a tool's allowlist never exempts a value from the default's
rules. If one tool legitimately handles data the default forbids (for example a
CRM lookup that returns customer emails), set `"inherit_global": false` on that
tool's policy: it is then judged by its own rules alone, and every other tool
keeps the default.

## Controls that cover every tool

| Control | Call (customer's settings key) | Effect |
|---|---|---|
| Kill switch | `POST /v1/shield/tools/{tool_name}/disable` (and `/enable`); `GET /v1/shield/tools/disabled` | The tool is refused for every agent of the customer, immediately |
| Approvals | `PUT /v1/tenant/me/agentic/config` with `{"approvals":{"enabled":true,"rules":[{"rule_id":"outbound","tool_names":["send_email","transfer_funds"],"min_approvals":1}]}}` | Those tools return `pending_confirmation` until a person approves in the portal. The approval is signed and tied to the exact arguments |
| Monitor or enforce | Same switch as prompts (`/v1/tenant/me/policy-mode`) | Monitor records what tool checks would block |

Approvals need `SHIELD_APPROVAL_TOKEN_PRIVATE_KEY` set on the deployment.

## Recommended defaults for every Rafay customer

1. Create the default tool policy above at onboarding, in monitor mode with the
   rest of the customer's policy.
2. Require approval for tools that send, pay or delete (`send_email`,
   `transfer_funds`, `delete_*`): a customer adjusts the list in the portal.
3. Run checkpoint 3 on every tool result, so planted instructions never reach
   the model.
4. For regulated customers, set `"fail_closed": true`.

## Latency

`tool/check` and `tool/output` use Shield's model for the plain-language rules,
so each takes longer than a pattern match (typically hundreds of milliseconds;
read `latency_ms` on each result). Run checkpoint 3 for all results of one turn
in parallel, and give these calls the same timeout and fail-closed or fail-open
choice as prompt screening.
