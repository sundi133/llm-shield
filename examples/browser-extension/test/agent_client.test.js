// node --test examples/browser-extension/test
// The extension's device-agent client, with chrome.runtime and fetch stubbed.
const test = require("node:test");
const assert = require("node:assert");

function load({ hello, responses }) {
  delete require.cache[require.resolve("../agent_client.js")];
  const calls = { native: 0, fetch: [] };
  global.chrome = {
    runtime: {
      lastError: null,
      sendNativeMessage(name, msg, cb) {
        calls.native++;
        assert.strictEqual(name, "ai.votal.device_agent");
        const r = typeof hello === "function" ? hello(calls.native) : hello;
        global.chrome.runtime.lastError = r === "missing" ? { message: "not found" } : null;
        cb(r === "missing" ? undefined : r);
      },
    },
  };
  global.fetch = async (url, opts) => {
    calls.fetch.push({ url, opts });
    const next = responses.shift();
    if (next instanceof Error) throw next;
    return { status: next.status || 200, ok: (next.status || 200) < 400, json: async () => next.body };
  };
  const mod = require("../agent_client.js");
  return { mod, calls };
}

const HELLO = { ok: true, port: 47823, secret: "s3cret" };

test("no agent: null, so the extension screens through Shield as before", async () => {
  const { mod, calls } = load({ hello: "missing", responses: [] });
  assert.strictEqual(await mod.agentScreen("hi", "chatgpt.com"), null);
  assert.strictEqual(await mod.agentScreen("hi", "chatgpt.com"), null);
  assert.strictEqual(calls.native, 1, "a missing agent is remembered, not asked every prompt");
  assert.strictEqual(calls.fetch.length, 0);
});

test("asks the loopback API with the secret and maps a block", async () => {
  const { mod, calls } = load({ hello: HELLO, responses: [{ body: {
    action: "block", verdict: "block", enforced: true, notice: "Blocked: credentials",
    prompt_sha256: "ab", destination: "chatgpt.com" } }] });
  const v = await mod.agentScreen("my password", "chatgpt.com");
  assert.deepStrictEqual([v.block, v.source, v.reason], [true, "agent", "Blocked: credentials"]);
  const call = calls.fetch[0];
  assert.strictEqual(call.url, "http://127.0.0.1:47823/v1/local/check");
  assert.strictEqual(call.opts.headers["X-Votal-Local-Secret"], "s3cret");
  assert.deepStrictEqual(JSON.parse(call.opts.body), { text: "my password", destination: "chatgpt.com", app: "browser" });
});

test("redact carries the text to send; justify carries what the reason needs", async () => {
  const { mod } = load({ hello: HELLO, responses: [
    { body: { action: "redact", verdict: "redact", enforced: true, text: "key [AWS_KEY]" } },
    { body: { action: "justify", verdict: "justify", enforced: true, prompt_sha256: "cd", destination: "claude.ai", notice: "Looks like health data" } },
    { body: { granted: true } },
  ] });
  const r = await mod.agentScreen("key AKIA...", "chatgpt.com");
  assert.deepStrictEqual([r.redact, r.text], [true, "key [AWS_KEY]"]);
  const j = await mod.agentScreen("patient notes", "claude.ai");
  assert.deepStrictEqual([j.justify, j.prompt_sha256, j.destination], [true, "cd", "claude.ai"]);
  assert.strictEqual(await mod.agentJustify("cd", "claude.ai", "case 42"), true);
});

test("monitor mode allows and says what would have happened", async () => {
  const { mod } = load({ hello: HELLO, responses: [
    { body: { action: "allow", verdict: "block", enforced: false } }] });
  const v = await mod.agentScreen("x", "chatgpt.com");
  assert.deepStrictEqual([v.block, v.warn, v.mode], [false, true, "monitor"]);
});

test("a new secret after a reinstall is fetched once, then the call is retried", async () => {
  let n = 0;
  const { mod, calls } = load({ hello: () => ({ ok: true, port: 47823, secret: "s" + (++n) }), responses: [
    { status: 401, body: { error: "wrong secret" } },
    { body: { action: "allow", verdict: "allow", enforced: true } }] });
  const v = await mod.agentScreen("x", "chatgpt.com");
  assert.strictEqual(v.block, false);
  assert.strictEqual(calls.fetch[1].opts.headers["X-Votal-Local-Secret"], "s2");
});

test("an agent that stopped answering falls back, and is looked for again", async () => {
  const { mod, calls } = load({ hello: HELLO, responses: [new Error("ECONNREFUSED"),
    { body: { action: "allow", verdict: "allow", enforced: true } }] });
  assert.strictEqual(await mod.agentScreen("x", "chatgpt.com"), null);
  assert.notStrictEqual(await mod.agentScreen("x", "chatgpt.com"), null);
  assert.strictEqual(calls.native, 2);
});
