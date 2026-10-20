---
name: votal-guardrails
description: Use when the user asks to check prompts or responses with Votal Shield, sanitize tool results, or validate a proposed tool call against Votal guardrails.
---

Use the connected Votal Shield MCP tools. Discover their live schemas before calling them; the provider documentation lists shield_check_input, shield_check_output, shield_check_tool, shield_sanitize_output, shield_disable_tool, and shield_enable_tool. Availability and argument requirements must come from the connected server.

Authentication uses a configurable tenant API key sent in X-API-Key. Let the user enter or update their key through the host connection setup. Never ask the user to paste credentials into chat or write credentials into plugin files. If authentication fails, report the connection error. Do not guess credentials or fall back to the shared sandbox. Deployments requiring an additional proxy bearer token need separate supported connection configuration.

For requested content checks, send only the content and context required by the relevant tool. The selected content is sent to Votal's service. Avoid transmitting unrelated conversation, files, or secrets. Describe explicit allow, block, or sanitized decisions accurately. Preserve relevant reasons and policy identifiers returned by the server. Do not repeat blocked sensitive material in the answer.

For a guarded workflow explicitly requested by the user:
1. Check the relevant user input before using it for the requested operation.
2. Before an external tool operation, check its exact tool name and arguments. Obtain the configured user role from trusted configuration or ask if it is missing; never assume an elevated role. A guardrail allow decision does not grant user authorization or override host permissions.
3. Stop the guarded operation on a block, error, unavailable service, missing required context, or ambiguous decision. Report that the check did not pass; do not infer safety from missing results.
4. Sanitize relevant tool results before using or displaying them. Use sanitized content returned by Shield; do not recover or echo removed values.
5. Check the final output when the user requested an output-guarded workflow. Honor blocks and use any sanitized replacement returned by Shield.

Kill-switch tools change enforcement state. Call shield_disable_tool or shield_enable_tool only when the user explicitly requests that specific action and target. Never enable a tool to bypass a blocked operation or test connection setup by changing policy.

Explain the coverage precisely: the bundled UserPromptSubmit command hook checks submitted prompt text automatically only in supported local sessions when the plugin and hook are enabled, credentials are configured, and the exact hook has been trusted. It blocks policy rejections and errors caught by the adapter. Do not claim that it scans attachment contents, prior conversation, replies, or tool calls. Explicit MCP tools remain cooperative. Missing runtime, untrusted/disabled hooks, process launch failure, and host-level timeouts are outside the adapter's blocking guarantee. Setup instructions are in README.md; the hook requires VOTAL_API_KEY in the environment inherited by Codex and cannot extract the MCP connection credential. Never save or hardcode a key in source files. Mandatory tool-boundary enforcement requires the Votal MCP gateway or a proxy in the execution path.

Provider references:
- https://docs.shield.votal.ai/developer-guide-mcp/
- https://docs.shield.votal.ai/connect-your-ide/
- https://docs.shield.votal.ai/mcp-gateway/
