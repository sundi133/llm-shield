# Runtime integration examples (infrastructure guardrails)

Reference scripts for running agents inside a boundary that Shield defines.
Guide: [docs/infra-guardrails.md](../../docs/infra-guardrails.md).
Spec: [docs/specs/infra-guardrails.md](../../docs/specs/infra-guardrails.md).

| File | Runs where | Does |
|---|---|---|
| `shield_runtime_sync.py` | Sandbox broker / CI (holds the tenant key) | Pulls the signed runtime bundle, verifies signature and claims, writes the policy file (and `--hash-file` for attestation). Refuses to write anything that does not verify. |
| `openshell_events.py` | Next to the sandbox | Tails `openshell logs` and forwards denials, degraded-boundary findings and policy loads to `/v1/shield/runtime/events`. |
| `envoy/ext_authz.yaml` | Egress proxy (reference, not run in CI) | Envoy asks `/v1/shield/runtime/ext-authz` about every outbound request. |

All three read the tenant key from `SHIELD_API_KEY`, never from a flag.
None of them belongs inside the sandbox.
