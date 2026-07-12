#!/usr/bin/env node
"use strict";

const { resolveExecutable } = require("../src/resolve");
const { buildChildArgs } = require("../src/args");
const { run } = require("../src/run");

// Exit codes mirror the Python CLI: 0 clean, 2 findings, 3 unreachable, 4 usage.
async function main() {
  const userArgv = process.argv.slice(2);

  let exe;
  try {
    exe = await resolveExecutable();
  } catch (err) {
    process.stderr.write(
      `mcp-scan: ${err.message}\n` +
        "hint: install the scanner with `pipx install shield-mcp`, or ensure network " +
        "access so the standalone binary can be downloaded.\n"
    );
    process.exit(4);
  }

  try {
    const code = await run(exe.command, [...exe.args, ...buildChildArgs(userArgv)]);
    process.exit(code);
  } catch (err) {
    process.stderr.write(`mcp-scan: failed to run scanner: ${err.message}\n`);
    process.exit(3);
  }
}

main();
