"""Cross-app flow control: session-aware source-to-destination policy for
agent tool calls. Spec: docs/specs/cross-app-flow-control.md.

  policy.py   validate, compile and evaluate a tenant's flow policy (pure)
  state.py    tenant-keyed record of what each session/principal has read
  runtime.py  the policy cache and the helpers the guard paths call
"""
