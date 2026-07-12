"use strict";

// `npx @votal/mcp-scan <target> [flags]` maps to `shield-mcp scan <target> [flags]`.
// Everything the user typed after `mcp-scan` is forwarded verbatim; the Python
// CLI stays the single source of truth for flags and --help, so the two can't
// drift. We only inject the implicit `scan` subcommand.
function buildChildArgs(userArgv) {
  return ["scan", ...userArgv];
}

module.exports = { buildChildArgs };
