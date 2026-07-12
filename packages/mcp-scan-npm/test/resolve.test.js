"use strict";

const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const {
  findLocal,
  verifyChecksum,
  checksumFor,
  resolveExecutable,
  downloadBinary,
} = require("../src/resolve");
const { assetName } = require("../src/platform");

// ── findLocal ──
test("findLocal returns 'shield-mcp' when the CLI is on PATH", () => {
  const spawnSyncFn = () => ({ status: 0 });
  assert.equal(findLocal(spawnSyncFn), "shield-mcp");
});

test("findLocal returns null when the CLI is absent (ENOENT)", () => {
  const spawnSyncFn = () => ({ error: Object.assign(new Error("nope"), { code: "ENOENT" }) });
  assert.equal(findLocal(spawnSyncFn), null);
});

// ── checksum handling ──
test("verifyChecksum accepts a matching sha256 and rejects a wrong one", () => {
  const tmp = path.join(os.tmpdir(), `mcp-scan-test-${process.pid}.bin`);
  fs.writeFileSync(tmp, "hello world");
  const good = crypto.createHash("sha256").update("hello world").digest("hex");
  try {
    assert.equal(verifyChecksum(tmp, good), true);
    assert.equal(verifyChecksum(tmp, good.toUpperCase()), true); // case-insensitive
    assert.equal(verifyChecksum(tmp, "0".repeat(64)), false);
  } finally {
    fs.unlinkSync(tmp);
  }
});

test("checksumFor extracts the digest for one asset from SHA256SUMS", () => {
  const body =
    "aaaa  shield-mcp-linux-x64\n" +
    "bbbb  shield-mcp-macos-arm64\n" +
    "cccc *shield-mcp-windows-x64.exe\n";
  assert.equal(checksumFor(body, "shield-mcp-macos-arm64"), "bbbb");
  assert.equal(checksumFor(body, "shield-mcp-windows-x64.exe"), "cccc");
  assert.equal(checksumFor(body, "shield-mcp-nope"), null);
});

// ── resolveExecutable hybrid logic ──
test("resolveExecutable prefers a local CLI over downloading", async () => {
  const res = await resolveExecutable({ spawnSyncFn: () => ({ status: 0 }) });
  assert.deepEqual(res, { command: "shield-mcp", args: [] });
});

test("resolveExecutable throws when no local CLI and downloads disabled", async () => {
  await assert.rejects(
    resolveExecutable({
      spawnSyncFn: () => ({ error: Object.assign(new Error(), { code: "ENOENT" }) }),
      allowDownload: false,
    }),
    /not found on PATH/
  );
});

// ── downloadBinary: verified fetch with an injected httpGet (no network) ──
test("downloadBinary downloads, verifies checksum, and caches an executable", async () => {
  const asset = assetName();
  const payload = Buffer.from("#!/bin/sh\necho frozen\n");
  const digest = crypto.createHash("sha256").update(payload).digest("hex");
  const cache = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-scan-cache-"));
  process.env.MCP_SCAN_CACHE = cache;

  const httpGetFn = async (url) => {
    if (url.endsWith("SHA256SUMS")) return Buffer.from(`${digest}  ${asset}\n`);
    if (url.endsWith(asset)) return payload;
    throw new Error(`unexpected url ${url}`);
  };

  try {
    const dest = await downloadBinary({ httpGetFn });
    assert.ok(fs.existsSync(dest));
    assert.equal(fs.readFileSync(dest).toString(), payload.toString());
    // second call is served from cache (httpGet not needed)
    const again = await downloadBinary({ httpGetFn: () => { throw new Error("should be cached"); } });
    assert.equal(again, dest);
  } finally {
    delete process.env.MCP_SCAN_CACHE;
    fs.rmSync(cache, { recursive: true, force: true });
  }
});

test("downloadBinary refuses a checksum mismatch", async () => {
  const asset = assetName();
  const cache = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-scan-cache-"));
  process.env.MCP_SCAN_CACHE = cache;
  const httpGetFn = async (url) => {
    if (url.endsWith("SHA256SUMS")) return Buffer.from(`${"0".repeat(64)}  ${asset}\n`);
    return Buffer.from("tampered");
  };
  try {
    await assert.rejects(downloadBinary({ httpGetFn }), /checksum mismatch/);
  } finally {
    delete process.env.MCP_SCAN_CACHE;
    fs.rmSync(cache, { recursive: true, force: true });
  }
});
