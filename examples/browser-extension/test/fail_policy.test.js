// node --test examples/browser-extension/test
// No verdict from Shield (timeout, network or HTTP error): held in enforce
// mode unless managed policy sets failOpen, sent with a note in monitor mode.
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const { failsOpen, unavailableVerdict, unavailableNotice } = require("../fail_policy.js");

const EXT = path.join(__dirname, "..");
const id = { userId: "", deviceId: "inst-1" };

test("enforce mode holds a prompt Shield could not check", () => {
  const v = unavailableVerdict({ mode: "enforce" }, "Failed to fetch", id);
  assert.strictEqual(v.block, true);
  assert.strictEqual(v.reason, "guardrails unavailable");
  assert.strictEqual(v.error, "Failed to fetch");
  const n = unavailableNotice(v, "");
  assert.strictEqual(n.allow, false);
  assert.strictEqual(n.kind, "block");
  assert.match(n.detail, /Shield could not be reached \(Failed to fetch\)/);
  assert.match(n.detail, /prompts/);
});

test("enforce mode with managed failOpen sends it with a note", () => {
  const v = unavailableVerdict({ mode: "enforce", failOpen: true }, "HTTP 503", id);
  assert.strictEqual(v.block, false);
  const n = unavailableNotice(v, "");
  assert.deepStrictEqual([n.allow, n.kind], [true, "warn"]);
  assert.strictEqual(n.detail, "Sent without screening (HTTP 503).");
});

test("monitor mode never blocks", () => {
  for (const failOpen of [undefined, false, true]) {
    const v = unavailableVerdict({ mode: "monitor", failOpen }, "timeout", id);
    assert.strictEqual(v.block, false);
    assert.strictEqual(unavailableNotice(v, "").allow, true);
  }
});

test("only an explicit true fails open in enforce mode", () => {
  for (const failOpen of [undefined, false, "true", 1, null]) {
    assert.strictEqual(failsOpen({ mode: "enforce", failOpen }), false, String(failOpen));
  }
  assert.strictEqual(failsOpen(null), false);
});

test("an attachment names the file", () => {
  const held = unavailableNotice(unavailableVerdict({ mode: "enforce" }, "HTTP 401", id), "kyc.csv");
  assert.strictEqual(held.allow, false);
  assert.match(held.detail, /^Attachment 'kyc.csv': Shield could not be reached \(HTTP 401\)/);
  assert.match(held.detail, /files/);
  const sent = unavailableNotice(unavailableVerdict({ mode: "monitor" }, "HTTP 401", id), "kyc.csv");
  assert.strictEqual(sent.detail, "Attachment 'kyc.csv' sent without screening (HTTP 401).");
});

// The wiring: the page decides with the same helper, before any other check
// lets a verdict with an error through, and every no-verdict path in the
// background goes through unavailableVerdict.
test("the page and the background use the policy for every no-verdict path", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(EXT, "manifest.json"), "utf8"));
  const js = manifest.content_scripts[0].js;
  assert.ok(js.indexOf("fail_policy.js") > -1 && js.indexOf("fail_policy.js") < js.indexOf("content.js"));

  const bg = fs.readFileSync(path.join(EXT, "background.js"), "utf8");
  assert.ok(bg.includes('importScripts("fail_policy.js")'));
  assert.strictEqual((bg.match(/unavailableVerdict\(/g) || []).length, 6);
  assert.ok(!/block:\s*false[^}]*error:\s*("HTTP|String\(e\)|"no shieldUrl)/.test(bg),
    "a Shield error returns a hard-coded block: false");

  const content = fs.readFileSync(path.join(EXT, "content.js"), "utf8");
  const guard = content.slice(content.indexOf("async function guard("));
  const decide = guard.indexOf("unavailableNotice(v");
  assert.ok(decide > -1 && decide < guard.indexOf("blockBanner(text, v)") &&
    decide < guard.indexOf("if (v.warn) banner(\"warn\", { title: \"Flagged by Shield.\""),
    "the prompt path must decide on an error before anything else sends it");
  assert.ok(!content.includes("// fail-open\n"), "the old unconditional fail-open is back");
});
