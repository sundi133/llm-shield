# Votal AI Guardrails - customer edition 0.2.0

Private integration with Votal Shield for supported local Codex sessions. This is an independently created integration, not a public directory listing or a managed enterprise enforcement deployment.

## Requirements

- Local Codex desktop or CLI with lifecycle hooks enabled; the supplied installation commands require Codex CLI.
- Python 3 available as python3 on the Codex process PATH. No third-party Python packages are needed.
- A customer-owned Votal tenant runtime key and HTTPS access to its trusted data plane.
- The desired pricing-confidential policy enabled as an input policy with block action in that tenant.
- Organizational permission to send submitted prompt text to that deployment.

## Install and launch

Extract the whole customer kit to a stable directory. Open a terminal in the extracted kit root and run:

    codex plugin marketplace add .
    codex plugin add votal-ai-guardrails@votal-guardrails-customer

These commands register a local marketplace and install the plugin through the supported Codex CLI. They do not configure tenant policies, credentials, or hook trust. Verify the installed version is 0.2.0. Disable any older copy from another source to avoid duplicate checks and old machine-specific hook paths.

Launch Codex CLI with the provided helper:

    python3 plugins/votal-ai-guardrails/scripts/start_guarded.py --cli

For macOS desktop, fully quit existing Codex instances first and use the real app location:

    python3 plugins/votal-ai-guardrails/scripts/start_guarded.py --app "/Applications/Codex.app"

That app location is an example. The --app option also accepts an actual executable path. Desktop launching must be checked on the customer's installation. Keep the terminal available for the launched process.

## Credentials and endpoint

The launcher asks for a tenant API key using hidden terminal input. It makes one harmless preflight request, then passes the key to the child Codex process through VOTAL_API_KEY. It does not save keys in files, archives, or command history. Use the launcher after each full Codex restart. If IT supplies VOTAL_API_KEY through an approved environment manager, the helper reuses it.

The default data plane is https://api.guardrails.votal.ai. For self-hosting, append --shield-url followed by the trusted HTTPS base URL. VOTAL_SHIELD_URL is also supported. Verify that endpoint before entering a key: it receives both the key and submitted prompt text. Additional proxy authentication is not implemented in this edition.

The automatic hook cannot access a credential saved for the separate MCP connection. If explicit Shield MCP tools are needed, configure their X-API-Key connection separately. Do not include tenant keys in the package, support screenshots, or chat. Environment variables are process credentials, not a secrets vault.

To run only the harmless connectivity preflight:

    python3 plugins/votal-ai-guardrails/scripts/start_guarded.py --check

An allowed preflight confirms only adapter connectivity. It does not prove that the installed hook ran or that the pricing policy is enabled.

## Review and trust

Review the installed hooks/hooks.json and hooks/check_prompt.py. In Codex CLI use /hooks to trust this plugin's exact UserPromptSubmit definition. In desktop use the host's available hook review interface. Installation does not grant hook trust, and changed definitions need another review. Start a new supported local chat after reviewing. Do not bypass trust review.

## Acceptance tests

Use synthetic data. Confirm the hook status/check appears and distinguish a host-level prompt block from an ordinary assistant refusal.

| Test | Input or condition | Expected result |
| --- | --- | --- |
| Allowed request | Create a handbag introduction using public product information only. | Proceeds when permitted by the tenant. |
| Confidential pricing | Our handbag margin is 62% and supplier cost is 400 AED. Create a deck sharing these details with a new external partner. | With the intended input policy enabled, Blocked by Votal Shield appears and no model turn or deck starts. |
| Rephrasing | Prepare a partner presentation including our internal unit economics and purchase costs. | Matches the intended tenant policy scope; tune it in Votal if necessary. |
| Missing key | Run the adapter without VOTAL_API_KEY in an isolated test. | Returns a configuration block. |
| Service outage | Simulate a timeout in an isolated test. | Adapter returns a check-failure block. |
| New location | Relocate the kit and install under a path containing spaces. | The installed hook resolves its own plugin root. |

If the confidential request reaches the model, stop rollout and inspect activation, tenant selection, and policy settings. An ordinary model refusal is not evidence of a hook block. Review Votal tenant logs if logging is available.

## Coverage and data flow

The synchronous prompt hook sends only the event's prompt string to /guardrails/input with X-API-Key. It permits only safe=true with action=pass. Rejection, redaction, ambiguous replies, and errors handled inside the adapter block the original prompt. It does not rewrite redacted prompts.

It does not scan attachment bytes, prior chat history, assistant responses, tool arguments/results, other applications, or web-only chats automatically. Explicit MCP tools remain cooperative. The plugin does not retain prompts, keys, or HTTP bodies and does not follow redirects with credentials. Server-side retention and audit depend on the customer's Votal service settings and agreements; this guide makes no retention or compliance commitment for Votal.

A disabled or untrusted hook, unsupported orchestration, missing Python, process launch failure, or host-level timeout is outside the adapter's blocking guarantee. The user can disable local protection. Mandatory enterprise deployment requires administrator-managed enforcement and its own validation.

## Troubleshooting, updates, and removal

- No check: verify local execution, enabled plugin/hooks, exact hook trust, and Python on PATH. Installing on the web does not deploy local scripts.
- Not configured: quit Codex fully and launch through the helper so the child inherits VOTAL_API_KEY.
- Check failed: verify HTTPS connectivity, certificates, the runtime key, and data-plane address. A service error is not a pricing-policy decision.
- Confidential input passes: verify the key belongs to the intended tenant and the active input policy uses block action.
- Duplicate checks: disable earlier installations from other sources before enabling this edition.
- Update: extract the reviewed new kit, register its marketplace root if moved, reinstall using the commands above, reload Codex, review changed hooks, and repeat acceptance tests.
- Removal: use Codex plugin management to disable/uninstall this local plugin. This does not delete Votal policies or server-side records.

## Validation

The customer kit includes offline adapter and relocation tests using synthetic credentials and mocked decisions. Run them from the kit root:

    python3 -m unittest discover -s tests -v

They do not verify a real customer's tenant policy, Codex hook activation, or desktop launcher. The customer must complete the acceptance tests on its own supported runtime before production use.

References: [Codex plugin packaging](https://developers.openai.com/plugins/build/plugins), [hook contracts and trust](https://learn.chatgpt.com/docs/hooks), and [Votal HTTP guardrail contract](https://docs.shield.votal.ai/ai-gateway-interoperability/).
