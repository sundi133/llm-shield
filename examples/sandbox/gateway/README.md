# Sandbox egress gateway (L2): a Shield-enforcing LiteLLM proxy

This is the L2 layer of the sandbox guardrails reference deployment
(`docs/spec-sandbox-guardrails.md`, architecture in
`docs/sandbox-guardrails-design.md`): a LiteLLM proxy that runs in your
trusted plane, outside every sandbox, with Votal Shield guardrails on every
request and response. The broker (`../broker.py`) points each sandbox's
`OPENAI_BASE_URL` at this proxy, and the provider's egress allowlist makes
it the only network path out. Any process in the sandbox that makes an LLM
call is screened, cooperative or not.

```
sandbox (trusted loop + untrusted agent-generated code)
   |
   |  OPENAI_BASE_URL          injected by the broker at launch
   v
LiteLLM egress gateway        <- this config; runs in YOUR trusted plane
   |  pre_call:   POST {SHIELD}/guardrails/input    blocked input never reaches the model
   |  post_call:  POST {SHIELD}/guardrails/output   output screening + tool-argument DLP
   v
upstream LLM (OpenAI / Anthropic / vLLM / any model in model_list)
```

The gateway holds the credentials the sandbox must never see: upstream
provider keys and, via per-key metadata, the Shield tenant key. The sandbox
holds only its instance-bound agent token (from the broker) and a LiteLLM
virtual key scoped to this proxy.

## Quickstart

1. Install the proxy and put the plugin where LiteLLM can import it:

   ```bash
   pip install "litellm[proxy]"
   cp votal_guardrail.py /path/to/gateway/   # from the repo root
   ```

2. Edit `config.yaml`: set `votal_guardrail.api_base` to your Shield data
   plane and fill in the `model_list` your agents need.

3. Start the gateway in your trusted plane:

   ```bash
   litellm --config examples/sandbox/gateway/config.yaml --port 4000
   ```

   Confirm the log line `VotalGuardrail initialized ... block_on_failure=True`.

4. Mint one virtual key per sandbox (or per agent). LiteLLM intercepts
   `X-API-Key` as its own key, so the Shield tenant key travels in the
   virtual key's metadata and is attached server-side, never by the sandbox:

   ```bash
   curl -X POST "$GATEWAY/key/generate" \
     -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
     -d '{"metadata": {"tenant_api_key": "<TENANT_API_KEY>",
                       "agent_key": "billing-bot", "user_role": "agent"}}'
   ```

5. Launch sandboxes through the broker with the gateway as base URL and the
   virtual key as the sandbox's OpenAI credential:

   ```python
   broker = SandboxBroker(..., gateway_base_url="https://llm-gw.internal:4000/v1")
   handle = broker.launch(SandboxSpec(
       agent_id="billing-bot", ...,
       extra_env={"OPENAI_API_KEY": "<sk-virtual-key-from-step-4>"},
   ))
   ```

The virtual key is not the tenant key: it only lets its holder make guarded
LLM calls through this proxy, and you can budget, rate-limit, and revoke it
per sandbox with LiteLLM key management. Rotate it with the same cadence as
the agent token if your threat model requires.

## Fail policy: `block_on_failure` (read before deploying)

LiteLLM guardrails default fail-open upstream: if the guard errors or
Shield is unreachable, traffic passes through unscreened. For a sandbox
egress gateway the guard IS the enforcement point, so the shipped
`config.yaml` sets `votal_guardrail.block_on_failure: true` (fail-closed):
when Shield is unreachable the LLM call is blocked and the sandbox degrades
to "can compute, cannot call the model".

The trade is availability: a Shield outage stops all sandboxed LLM traffic
behind this gateway. Set `block_on_failure: false` only if unscreened
egress during a Shield outage is acceptable in your threat model.
Non-sandbox deployments of the same plugin may reasonably choose fail-open;
a sandbox egress gateway should not.

Streaming has one caveat: tool calls arrive as deltas and can only be
assembled and checked at stream end, after content chunks have been sent.
With `streaming_tool_rbac: enforce` (the shipped default) a blocked tool
call fails the request at that point, so the sandbox never receives a
completed response containing it. `log` restores audit-only behavior for
clients that gate tool execution themselves. If you need blocking before
any output at all, disable streaming for guarded routes.

## Making L2 non-bypassable: provider egress allowlists

This gateway only screens traffic that reaches it. The claim "untrusted
code cannot make an unscreened LLM call" holds only when the sandbox
provider's network policy leaves the gateway (plus Shield, for the
in-sandbox runtime's own calls) as the sole egress path.

| Provider | Egress lockdown | Recommended posture |
|---|---|---|
| **Modal** | Strong | `ModalProvider(egress_cidrs=["<gateway-ip>/32", "<shield-ip>/32"])` in `../broker.py` becomes Modal's `cidr_allowlist`. With no `egress_cidrs` the broker defaults to `block_network=True` (compute only, no gateway either). |
| **K8s Agent Sandbox** | Strong (CNI-dependent) | NetworkPolicy deny-by-default egress plus an allowlist to the gateway Service; requires a NetworkPolicy-enforcing CNI (Cilium, Calico). The on-prem / in-VPC answer. Snippet below. |
| **E2B** | Partial | Point `base_url` at the gateway; rely on the L3 executor for anything side-effecting; the residual risk below applies. |
| **Daytona** | Partial | Same as E2B; apply runner-level egress allowlisting where supported. |

Illustrative NetworkPolicy for K8s Agent Sandbox pods (deny all egress
except DNS, the gateway, and Shield; adapt selectors and ports):

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sandbox-egress-gateway-only
spec:
  podSelector:
    matchLabels:
      agents.x-k8s.io/sandbox: "true"    # match your Sandbox pod labels
  policyTypes: [Egress]
  egress:
    - to:                                 # DNS
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - { protocol: UDP, port: 53 }
        - { protocol: TCP, port: 53 }
    - to:                                 # the egress gateway + Shield only
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: llm-gateway
          podSelector:
            matchLabels:
              app: litellm-gateway
      ports:
        - { protocol: TCP, port: 4000 }
```

## Residual risk

On providers without guaranteed egress lockdown (E2B, Daytona today),
untrusted code may make ungoverned read-only calls to third parties. It
still cannot perform Shield-mediated side effects or obtain credentials.
Close the gap with provider egress allowlisting: Modal
(`block_network`/`cidr_allowlist`) and K8s Agent Sandbox (NetworkPolicy
deny-by-default egress + allowlist to the gateway, CNI-dependent) both
support the strong posture, so the L2 non-bypassability claim holds on
either.

## What this changes in Shield: nothing

Off the hot path (spec section 2): the gateway is a client of
`/guardrails/input`, `/guardrails/output`, and `/v1/shield/tool/check`. No
Shield endpoint or plane changes, and non-sandbox traffic is unaffected.

## See also

- `docs/ai-gateway-interoperability.md` section 5: LiteLLM integration
  details, per-tenant routing, and the one-shot setup script.
- The sibling layers of the reference deployment (spec section 4):
  `../broker.py` (L0 identity), `agent_runtime.py` (L1 cooperative checks +
  cap flow), `tool_executor.py` (L3 cap-gated executor).
