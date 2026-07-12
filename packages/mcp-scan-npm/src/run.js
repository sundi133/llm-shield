"use strict";

const { spawn } = require("child_process");

// Run the resolved scanner, inheriting stdio so the child's stdout (including
// --json) passes through byte-for-byte. Resolves with the child's exit code so
// the wrapper can exit with the SAME code (a findings exit of 2 must never be
// coerced to 0). spawnFn is injectable for tests.
function run(command, args, { spawnFn = spawn } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawnFn(command, args, { stdio: "inherit" });
    child.on("error", reject);
    child.on("exit", (code, signal) => {
      if (signal) {
        resolve(1);
      } else {
        resolve(code == null ? 1 : code);
      }
    });
  });
}

module.exports = { run };
