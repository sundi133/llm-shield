// node --test extension/test/rules.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { evaluate } = require("../rules.js");

const BUNDLE = {
  rules: [
    { id: "ssn", regex: "\\d{3}-\\d{2}-\\d{4}", action: "block", severity: "critical" },
    { id: "phone", regex: "\\+1-\\d{3}-\\d{3}-\\d{4}", action: "redact", replacement: "[PHONE]" },
  ],
  blocklists: ["wire transfer"],
};

test("critical rule => block", () => {
  const r = evaluate("my ssn is 521-44-9087", BUNDLE);
  assert.equal(r.decision, "block");
  assert.ok(r.matched.includes("ssn"));
});

test("redact rule => redacted text", () => {
  const r = evaluate("call +1-415-555-2210 please", BUNDLE);
  assert.equal(r.decision, "redact");
  assert.match(r.redacted, /\[PHONE\]/);
  assert.doesNotMatch(r.redacted, /415-555-2210/);
});

test("blocklist word => block", () => {
  const r = evaluate("please do a WIRE TRANSFER now", BUNDLE);
  assert.equal(r.decision, "block");
});

test("clean text => allow (caller escalates)", () => {
  const r = evaluate("how do I request PTO?", BUNDLE);
  assert.equal(r.decision, "allow");
  assert.equal(r.matched.length, 0);
});

test("malformed regex is skipped, not thrown", () => {
  const r = evaluate("anything", { rules: [{ id: "bad", regex: "(" }] });
  assert.equal(r.decision, "allow");
});

test("empty inputs are safe", () => {
  assert.equal(evaluate("", BUNDLE).decision, "allow");
  assert.equal(evaluate("hi", null).decision, "allow");
});
