# Validation - Votal AI Guardrails 0.2.0

18 automated tests passed on October 20, 2026 using Python 3 standard libraries.

Verified: explicit allow, block and contradictory decisions, redaction handling, malformed/oversized replies, HTTPS endpoint validation, missing credentials, timeout handling, redirect refusal, event parsing, request minimization, and omission of prompt/key material from adapter output. Launcher tests verify no child starts after a failed preflight and that environment credentials reach a mocked child without command-line or log exposure.

Portability check: copied the actual plugin into a temporary directory with spaces, invoked the actual hook command with PLUGIN_ROOT set to the relocated directory, and confirmed the adapter ran and returned a missing-credential block. Catalog paths and synchronized manifest versions were verified.

Not verified: authenticated customer policy decisions, customer Codex hook trust/activation, a real customer marketplace installation, desktop application launching, or managed enforcement. The customer must complete the acceptance tests in the plugin README before production rollout. Mock tests and direct adapter execution do not prove host-level protection.

Reproduce from the extracted kit root:

    python3 -m unittest discover -s tests -v
