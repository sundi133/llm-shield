#!/usr/bin/env bash
# Composite-action scan step. Reads inputs from INPUT_*/SHIELD_* env (set by
# action.yml), runs `shield-mcp scan`, writes step outputs, and exits with the
# scanner's own exit code so a findings result (2) fails the job.
set -uo pipefail

# Mask the API key so it can never surface in the job log.
if [ -n "${SHIELD_API_KEY:-}" ]; then
  echo "::add-mask::${SHIELD_API_KEY}"
fi

args=(scan "${INPUT_TARGET}" --fail-on "${INPUT_FAIL_ON}" --timeout "${INPUT_TIMEOUT}")
if [ "${INPUT_OFFLINE:-false}" = "true" ]; then
  args+=(--offline)
fi
if [ -n "${SHIELD_URL:-}" ]; then
  args+=(--shield-url "${SHIELD_URL}")
fi
# The api key travels via the SHIELD_API_KEY env var the CLI reads, never on the
# command line (which would be visible in a process listing / trace).

report="$(shield-mcp "${args[@]}" --json)"
code=$?

verdict="$(printf '%s' "$report" | jq -r '.verdict // "error"' 2>/dev/null || true)"
[ -z "$verdict" ] && verdict="error"

# Human summary to the log always; raw JSON too when requested.
if [ "${INPUT_JSON:-false}" = "true" ]; then
  printf '%s\n' "$report"
else
  printf '%s' "$report" | jq -r '
    "MCP scan verdict: \(.verdict)  (\(.counts.tools) tools, \(.counts.resources) resources, \(.counts.prompts) prompts)",
    (.findings[]? | "  [\(.severity)] \(.category): \(.subject_kind) \(.subject_name)")' 2>/dev/null \
    || echo "MCP scan exited ${code} (no JSON report; target may be unreachable)"
fi

{
  echo "exit-code=${code}"
  echo "verdict=${verdict}"
  echo "report<<__MCP_EOF__"
  printf '%s\n' "$report"
  echo "__MCP_EOF__"
} >> "$GITHUB_OUTPUT"

exit "$code"
