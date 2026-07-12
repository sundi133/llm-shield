"use strict";

const { test } = require("node:test");
const assert = require("node:assert");
const { EventEmitter } = require("node:events");
const { run } = require("../src/run");
const { buildChildArgs } = require("../src/args");

function fakeSpawn(exitCode, signal) {
  const calls = [];
  const spawnFn = (command, args, opts) => {
    calls.push({ command, args, opts });
    const child = new EventEmitter();
    setImmediate(() => child.emit("exit", exitCode, signal));
    return child;
  };
  spawnFn.calls = calls;
  return spawnFn;
}

test("propagates the child exit code unchanged (2 stays 2, never 0)", async () => {
  const code = await run("shield-mcp", ["scan", "x"], { spawnFn: fakeSpawn(2) });
  assert.equal(code, 2);
});

test("clean exit 0 stays 0", async () => {
  assert.equal(await run("x", [], { spawnFn: fakeSpawn(0) }), 0);
});

test("null exit code (killed) resolves to 1", async () => {
  assert.equal(await run("x", [], { spawnFn: fakeSpawn(null) }), 1);
});

test("a terminating signal resolves to 1", async () => {
  assert.equal(await run("x", [], { spawnFn: fakeSpawn(null, "SIGTERM") }), 1);
});

test("forwards argv verbatim, inheriting stdio", async () => {
  const spawnFn = fakeSpawn(0);
  const childArgs = buildChildArgs(["stdio:python srv.py", "--json", "--fail-on", "high"]);
  await run("shield-mcp", childArgs, { spawnFn });
  assert.deepEqual(spawnFn.calls[0].args, [
    "scan",
    "stdio:python srv.py",
    "--json",
    "--fail-on",
    "high",
  ]);
  assert.equal(spawnFn.calls[0].opts.stdio, "inherit");
});

test("buildChildArgs injects the scan subcommand and forwards the rest", () => {
  assert.deepEqual(buildChildArgs([]), ["scan"]);
  assert.deepEqual(buildChildArgs(["sse:https://h/sse", "--offline"]), [
    "scan",
    "sse:https://h/sse",
    "--offline",
  ]);
});
