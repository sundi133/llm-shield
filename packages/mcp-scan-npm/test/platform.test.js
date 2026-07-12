"use strict";

const { test } = require("node:test");
const assert = require("node:assert");
const { assetName } = require("../src/platform");

test("maps known platform/arch to release asset names", () => {
  assert.equal(assetName("linux", "x64"), "shield-mcp-linux-x64");
  assert.equal(assetName("linux", "arm64"), "shield-mcp-linux-arm64");
  assert.equal(assetName("darwin", "x64"), "shield-mcp-macos-x64");
  assert.equal(assetName("darwin", "arm64"), "shield-mcp-macos-arm64");
  assert.equal(assetName("win32", "x64"), "shield-mcp-windows-x64.exe");
});

test("throws on unsupported platform or arch", () => {
  assert.throws(() => assetName("sunos", "x64"), /unsupported platform/);
  assert.throws(() => assetName("linux", "ppc64"), /unsupported platform/);
  assert.throws(() => assetName("win32", "arm64"), /windows is x64 only/);
});
