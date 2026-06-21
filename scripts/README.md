# Shield scripts — live testing & operations

Tooling for testing a **running** Shield deployment (RunPod data plane, Docker,
or local) and for CI. Most scripts are env-driven and need no source checkout of
the server.

## Common environment

| Var | Meaning |
|---|---|
| `SHIELD_URL` | Data-plane base URL (e.g. `https://<host>.api.runpod.ai`). Use the **data plane**, not the admin host. |
| `TENANT_KEY` / `X-API-Key` | Tenant API key (a `sk-test-` key hits the shared sandbox tenant). |
| `ADMIN_KEY` / `X-Admin-Key` | Admin key — needed to mint agent tokens / revoke. |
| `RUNPOD_TOKEN` | Proxy bearer (`Authorization: Bearer …`) when the data plane sits behind the RunPod proxy. |

> Set `SHIELD_PUBLIC_BASE_URL` on the **deployment** so MCP/SSF discovery
> metadata advertises the public host instead of the internal proxy IP.

---

## Live test scripts

### `test_agent_security_live.sh` — agent-security smoke test (per tenant)
End-to-end PASS/FAIL check of the agent-security features for one tenant:
MCP, auth telemetry counters, **closed-loop auto-revoke**, and **CAEP/SSF**.
Self-cleaning (timestamped throwaway instance ids); sections skip when their
inputs are absent; exits non-zero on any failure.
```bash
SHIELD_URL=… TENANT_KEY=… ADMIN_KEY=… RUNPOD_TOKEN=… \
  ./scripts/test_agent_security_live.sh
# optional: SSF_RECEIVER_TOKEN=… to test the SSF receiver accept path
```
Requires on the deployment: `SHIELD_ENABLE_AUTO_REVOKE=true` (auto-revoke) and
`SHIELD_SSF_RECEIVER_TOKEN` (SSF receiver). See [Continuous Identity docs](../docs/continuous-identity.md).

Section 5 also runs the **agentic-IdP end-to-end validator**
(`examples/langchain/agentic_idp_e2e_test.py`) when `python3` + `requests` are
available — covering identity, capability mint/verify/replay, RBAC denial,
guardrails, revocation, and audit in one shot. It runs with just the tenant key;
`ADMIN_KEY` is optional and only enables the **manual** revoke sub-test (without
it, the revoke step uses closed-loop auto-revoke, which needs
`SHIELD_ENABLE_AUTO_REVOKE=true` on the deployment).

### `guard_external_agent.sh` - one-shot guardrail proxy for an external agent
Stands up the Shield-guardrailed LiteLLM proxy, mints a tenant virtual key, and
runs a benign/injection gate test - then prints the Base URL + key + model to
paste into Hermes / openclaw. See [Guard an external agent](../docs/guard-external-agent.md).
```bash
SHIELD_URL=$RUNPOD_HOST RUNPOD_TOKEN=$RUNPOD_TOKEN TENANT_API_KEY=$TENANT_API_KEY \
  OPENAI_API_KEY=... ./scripts/guard_external_agent.sh
```

### `mcp_e2e_test.py` — MCP integration end-to-end
Deploy readiness (`/health`, `/v1/openapi/*`), MCP `initialize` / `tools/list` /
`tools/call`, and the OpenAPI→MCP import/call enforcement path.
```bash
SHIELD_URL=… TENANT_KEY=… RUNPOD_TOKEN=… python3 scripts/mcp_e2e_test.py
```

### `verify_cap_authz.py` — capability authorization verifier
Asserts the cap-authz Pass Criteria (registered-agent gating, cross-agent and
rogue-agent denial) against a live tenant, using two registered agents that own
disjoint tools. Pass the agent ids as CLI args.
```bash
python3 scripts/verify_cap_authz.py --shield-url $SHIELD_URL \
  --tenant-api-key $TENANT_KEY --runpod-token $RUNPOD_TOKEN \
  --agent customer-service-agent --owner-agent test-oidc-agent
# all flags also read from env: SHIELD_URL, TENANT_API_KEY, RUNPOD_TOKEN, AGENT, OWNER_AGENT, …
```

### `smoke_agent_auth.sh` — agent AuthN/AuthZ smoke
End-to-end mint → cap mint → verify → revoke flow.

### `smoke_customer_flow.sh` — tenant-key-only customer flow
Exercises the common guardrail/tool flow using only a tenant API key.

### `test_all_features.sh` — broad AuthN/AuthZ/OAuth/guardrail sweep
Wide coverage smoke of the auth + guardrail surfaces.

---

## CI / performance

### `shield_ci.py` — CI/CD guardrail gate
Runs guardrail test suites against a Shield instance; exit 0 = pass, 1 =
failures. Use as a pre-deploy gate.

### `benchmark_latency_runpod.py` / `benchmark_latency*.py`
Measure guardrail latency (direct, and with policy) against a deployment.

---

## Notes
- **Rotate any token that appears in a shell history or chat.** Prefer sourcing
  a local untracked env file (`source ~/votal-test.env`) over inline secrets.
- The data plane holds the guardrail models; point these scripts at it (not the
  admin/control plane).
