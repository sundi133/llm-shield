"""Infrastructure guardrails: one runtime profile per class of agent, compiled
into the sandboxes and proxies that enforce it at the kernel and network level.
Spec: docs/specs/infra-guardrails.md.

  model.py      validate, normalize and hash a runtime profile (pure)
  store.py      tenant-scoped profile storage
  compilers/    one module per enforcement target (openshell, ...)
  bundle.py     signed bundles for runtimes to pull and verify
"""
