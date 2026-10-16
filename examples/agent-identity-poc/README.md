# Agent identity proof of concept

Nine scenarios that show, in your own environment, how Votal Shield proves who
an AI agent is, decides what it may do, contains it, and records all of it.
Every scenario ends in a refusal you can see, and an audit record you can show.

| # | Scenario | What it shows |
|---|---|---|
| 1 | Stolen token | A copied agent token is useless without the agent's key; a captured proof works once |
| 2 | Wrong role | A role without a tool gets no permission to call it |
| 3 | Human approval | A sensitive call needs a named person's approval, once; permissions are single use |
| 4 | Impersonation | An agent that must present a certificate cannot be named in a header by someone else |
| 5 | Revoked certificate | A revoked certificate stops identifying the agent |
| 6 | Sandbox escape | A call outside the agent's runtime profile is refused |
| 7 | Stale sandbox | A sandbox running an outdated profile gets no permissions |
| 8 | Incident response | A revoked agent instance, and a killed tool, stop at once |
| 9 | Evidence | The refusals are in the decision audit; the audit chain verifies |

## See it first, anywhere

```bash
python examples/agent-identity-poc/poc.py --local
```

This starts Shield inside the script with every setting on, generates a CA and
an agent certificate, and runs all nine scenarios. Nothing leaves the machine.
It needs a checkout of this repository and its Python requirements.

## Run it in your environment

### What you need

| For | You need |
|---|---|
| Scenarios 1 to 3, 6 to 9 | A Shield URL and a tenant API key. If your tenant enforces the registry write gate, an admin-scoped key |
| Scenarios 4 and 5 | Your mTLS proxy in front of Shield (Envoy, nginx or a load balancer), and a client certificate and key it accepts. Set up as in the agent certificate identity runbook |
| Scenario 5 with your CA | Optionally, a CRL from your CA that lists that client certificate, and the trust anchor id it belongs to. Without them the scenario revokes the certificate in Shield instead |

Shield settings the scenarios check (a scenario that finds one missing fails
and says which):

| Setting | Scenario |
|---|---|
| `SHIELD_AGENT_TOKEN_POP=required` | 1 |
| `SHIELD_MTLS_ENABLED=true`, `SHIELD_TRUSTED_PROXY_ONLY=true`, `SHIELD_TRUSTED_PROXY_SECRET` | 4, 5 |
| `SHIELD_ENABLE_KILLSWITCH=true` | 8 (the kill switch half) |
| `SHIELD_AUDIT_TAMPER_EVIDENT=1` | 9 (the audit chain) |
| `SHIELD_VERBOSE_REASONS=1` | optional: denial reasons in responses, clearer for a demo |

### Run

```bash
pip install httpx cryptography
python examples/agent-identity-poc/poc.py \
  --shield-url https://shield.acme.internal --api-key "$SHIELD_API_KEY" \
  --proxy-url https://shield-mtls.acme.internal \
  --client-cert agent.crt --client-key agent.key \
  --report poc-report.md
```

- `--only 1,4,9` runs some scenarios.
- `--propagation-wait 330` waits for a revocation to reach every Shield server
  (each one caches verified certificates for up to 5 minutes).
- `--crl ca.crl --anchor-id <id>` uses your CA's revocation list in scenario 5.
- `--keep` leaves the POC's agents and rules in place to look at in the portal.

It exits non-zero if any scenario fails, so it can run in CI.

### What it changes in your tenant, and puts back

Everything it creates is named with a run prefix (`poc-xxxxxx`) and removed at
the end: three agents, one approval rule, one runtime profile, and, for
scenarios 4 and 5, one registered certificate. It adds its own approval rule
and certificate mapping rule to yours and removes only those; it never
replaces your existing rules. The kill switch in scenario 8 is used on a tool
named after the run, never on one of yours, and switched back on.

## Use the client helper in your agent

The scenarios use the same helper your agents would: `packages/shield-py/shield_agent.py`.

```python
from shield_agent import ShieldAgent, CapabilityVerifier, ApprovalRequired, CapabilityDenied

agent = ShieldAgent(agent_id="support-bot", user_sub=user.id, session_id=conversation.id,
                    user_role=user.role)                      # SHIELD_URL, SHIELD_API_KEY
try:
    cap = agent.mint("refund_process", resource=f"order/{order_id}",
                     tool_params={"order_id": order_id, "amount": amount})
except ApprovalRequired as e:
    return f"Waiting for approval (request {e.request_id})"
except CapabilityDenied as e:
    return f"Not allowed: {e}"
refund_service.call(order_id, amount, capability=cap.token)

# in the refund service
claims = CapabilityVerifier().verify(capability, expected_tool="refund_process",
                                     expected_resource=f"order/{order_id}")
```

The agent's key is made in memory when it starts and never sent anywhere; its
public half binds the token. Tokens refresh before they expire. Each
permission is good for one call.

## Troubleshooting

| Message | Meaning |
|---|---|
| `a token without its proof was accepted` | Set `SHIELD_AGENT_TOKEN_POP=required` on Shield |
| `cannot register ...` | The key cannot write the agent registry; use an admin-scoped key |
| `cannot set identity.require` | This Shield predates certificate identity; deploy a build that has it |
| `the agent's verified certificate was not accepted` | The proxy is not forwarding the certificate with its secret, or the certificate's CA is not a trust anchor; test it under Agent Identity, then Test a certificate |
| `the revoked certificate still identified the agent` | Several Shield servers: run with `--propagation-wait 330` |
| `kill switch not available here` | Set `SHIELD_ENABLE_KILLSWITCH=true` |
