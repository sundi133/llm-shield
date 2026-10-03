// node --test examples/browser-extension/test
// Exception requests from the extension's side, with fetch and storage stubbed.
const test = require("node:test");
const assert = require("node:assert");
const crypto = require("node:crypto");
const ex = require("../exception_client.js");

function deps(responses, now = 1000) {
  const data = {};
  const calls = [];
  return {
    calls, data,
    base: "https://shield.example/",
    headers: { "X-API-Key": "k", "X-Agent-Key": "alice@co.com" },
    now: () => now,
    store: {
      async get(k) { return data[k] || null; },
      async set(k, v) { data[k] = v; },
      async remove(k) { delete data[k]; },
      async all() { return { ...data }; },
    },
    async fetch(url, opts) {
      calls.push({ url, method: opts.method, headers: opts.headers, body: opts.body && JSON.parse(opts.body) });
      const next = responses.shift();
      if (next instanceof Error) throw next;
      return { status: next.status || 200, ok: (next.status || 200) < 400, json: async () => next.body };
    },
  };
}

const sha = (t) => crypto.createHash("sha256").update(t).digest("hex");
const PROMPT = "our margin is 62%";

test("the hash matches the server's: NFC and outer whitespace", async () => {
  assert.strictEqual(await ex.promptHash("  " + PROMPT + "\n"), sha(PROMPT));
  assert.strictEqual(await ex.promptHash("café"), sha("café"));
});

test("a request is sent with the prompt, site and reason, and remembered", async () => {
  const d = deps([{ status: 201, body: { request_id: "pex_1", status: "pending", expires_at: 9000 } }]);
  const r = await ex.requestException(d, { text: PROMPT, destination: "ChatGPT", reason: "NDA" });
  assert.deepStrictEqual(r, { ok: true, status: "pending", request_id: "pex_1" });
  assert.strictEqual(d.calls[0].url, "https://shield.example/v1/shield/exceptions");
  assert.deepStrictEqual(d.calls[0].body, { prompt: PROMPT, destination: "ChatGPT", reason: "NDA" });
  assert.strictEqual(d.calls[0].headers["X-Agent-Key"], "alice@co.com");
  assert.strictEqual(d.data[ex.keyFor(sha(PROMPT), "ChatGPT")].request_id, "pex_1");
});

test("server refusals become sentences the user can act on", async () => {
  const cases = [
    [404, "exceptions_disabled", /not turned on/],
    [409, "not_blocked", /no longer blocked/],
    [403, "not_appealable", /does not accept/],
    [429, "too_many_pending", /3 requests/],
  ];
  for (const [status, error, re] of cases) {
    const d = deps([{ status, body: { detail: { error, message: "You already have 3 requests waiting for review." } } }]);
    const r = await ex.requestException(d, { text: PROMPT, destination: "ChatGPT", reason: "NDA" });
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.code, error);
    assert.match(r.message, re);
    assert.deepStrictEqual(d.data, {});
  }
  const offline = deps([new Error("network")]);
  assert.strictEqual((await ex.requestException(offline, { text: PROMPT, destination: "x", reason: "abc" })).code, "unreachable");
});

test("nothing is attached for a prompt without an approval", async () => {
  const d = deps([]);
  assert.deepStrictEqual(await ex.grantFor(d, PROMPT, "ChatGPT"), { grant: "", rec: null });
  assert.strictEqual(d.calls.length, 0);
});

test("an approved request is collected once, and its grant reused until near expiry", async () => {
  const d = deps([{ body: { status: "approved", grant: "g1", grant_expires_at: 1900, decision: { reason: "ok" } } }]);
  d.data[ex.keyFor(sha(PROMPT), "ChatGPT")] = { request_id: "pex_1", status: "approved", destination: "ChatGPT", hash: sha(PROMPT) };
  assert.strictEqual((await ex.grantFor(d, PROMPT, "ChatGPT")).grant, "g1");
  assert.strictEqual((await ex.grantFor(d, PROMPT, "ChatGPT")).grant, "g1");
  assert.strictEqual(d.calls.length, 1);                         // reused
  assert.strictEqual(d.calls[0].url, "https://shield.example/v1/shield/exceptions/pex_1");
  // Another site, or other text, gets nothing.
  assert.strictEqual((await ex.grantFor(d, PROMPT, "Claude")).grant, "");
  assert.strictEqual((await ex.grantFor(d, PROMPT + "!", "ChatGPT")).grant, "");
});

test("a grant about to expire is replaced before it is sent", async () => {
  const d = deps([{ body: { status: "approved", grant: "g2", grant_expires_at: 1900 } }], 1000);
  d.data[ex.keyFor(sha(PROMPT), "ChatGPT")] = { request_id: "pex_1", status: "approved", destination: "ChatGPT",
                                                hash: sha(PROMPT), grant: "g1", grant_expires_at: 1010 };
  assert.strictEqual((await ex.grantFor(d, PROMPT, "ChatGPT")).grant, "g2");
});

test("a released send forgets the approval; a used one is dropped; an expired grant is refreshed next time", async () => {
  const key = ex.keyFor(sha(PROMPT), "ChatGPT");
  const rec = { request_id: "pex_1", status: "approved", destination: "ChatGPT", hash: sha(PROMPT), grant: "g", grant_expires_at: 5000 };
  let d = deps([]);
  d.data[key] = { ...rec };
  assert.strictEqual(await ex.afterSend(d, PROMPT, "ChatGPT", { exception: { request_id: "pex_1" } }), "released");
  assert.deepStrictEqual(d.data, {});
  d.data[key] = { ...rec };
  assert.strictEqual(await ex.afterSend(d, PROMPT, "ChatGPT", { exception_error: "grant_used" }), "grant_used");
  assert.deepStrictEqual(d.data, {});
  d.data[key] = { ...rec };
  assert.strictEqual(await ex.afterSend(d, PROMPT, "ChatGPT", { exception_error: "grant_expired" }), "grant_expired");
  assert.strictEqual(d.data[key].grant, null);
  assert.strictEqual(await ex.afterSend(d, PROMPT, "ChatGPT", { action: "pass" }), "");
});

test("polling reports decisions for this site only and keeps a denial to show later", async () => {
  const d = deps([
    { body: { status: "denied", decision: { reason: "No NDA on file", approver: "carol" } } },
    { body: { status: "pending" } },
  ]);
  const add = (id, text, dest, status) =>
    (d.data[ex.keyFor(sha(text), dest)] = { request_id: id, status, destination: dest, hash: sha(text) });
  add("pex_1", "a", "ChatGPT", "pending");
  add("pex_2", "b", "ChatGPT", "pending");
  add("pex_3", "c", "Claude", "pending");
  add("pex_4", "d", "ChatGPT", "denied");
  d.data["unrelated"] = { status: "pending", destination: "ChatGPT" };
  const changes = await ex.poll(d, "ChatGPT");
  assert.deepStrictEqual(changes, [{ request_id: "pex_1", status: "denied",
                                     decision: { reason: "No NDA on file", approver: "carol" } }]);
  assert.deepStrictEqual(d.calls.map((c) => c.url.split("/").pop()), ["pex_1", "pex_2"]);
  assert.strictEqual(d.data[ex.keyFor(sha("a"), "ChatGPT")].status, "denied");   // kept for the banner
});

test("a request Shield no longer knows is forgotten; an outage changes nothing", async () => {
  const key = ex.keyFor(sha(PROMPT), "ChatGPT");
  const rec = { request_id: "pex_1", status: "pending", destination: "ChatGPT", hash: sha(PROMPT) };
  let d = deps([{ status: 404, body: {} }]);
  d.data[key] = rec;
  assert.strictEqual((await ex.refresh(d, rec)).status, "gone");
  assert.deepStrictEqual(d.data, {});
  d = deps([new Error("offline")]);
  d.data[key] = rec;
  assert.deepStrictEqual(await ex.refresh(d, rec), rec);
  assert.ok(d.data[key]);
});

test("a resend right after approval collects the grant without waiting for the poll", async () => {
  // The production report: approved at 12:09:33, resent at 12:09:48, blocked,
  // because the tab still held "pending" and only asked Shield every 30 s.
  const d = deps([{ body: { status: "approved", grant: "g-now", grant_expires_at: 1900 } }]);
  d.data[ex.keyFor(sha(PROMPT), "chatgpt.com")] = { request_id: "pex_1", status: "pending",
                                                    destination: "chatgpt.com", hash: sha(PROMPT) };
  const out = await ex.grantFor(d, PROMPT, "chatgpt.com");
  assert.strictEqual(out.grant, "g-now");
  assert.strictEqual(d.calls.length, 1);
});

test("a resend while still pending asks once and sends nothing", async () => {
  const d = deps([{ body: { status: "pending" } }]);
  d.data[ex.keyFor(sha(PROMPT), "chatgpt.com")] = { request_id: "pex_1", status: "pending",
                                                    destination: "chatgpt.com", hash: sha(PROMPT) };
  const out = await ex.grantFor(d, PROMPT, "chatgpt.com");
  assert.deepStrictEqual([out.grant, out.rec.status], ["", "pending"]);
});

test("a denial learned at send time is kept for the banner", async () => {
  const d = deps([{ body: { status: "denied", decision: { reason: "No NDA" } } }]);
  d.data[ex.keyFor(sha(PROMPT), "chatgpt.com")] = { request_id: "pex_1", status: "pending",
                                                    destination: "chatgpt.com", hash: sha(PROMPT) };
  const out = await ex.grantFor(d, PROMPT, "chatgpt.com");
  assert.strictEqual(out.grant, "");
  assert.strictEqual(out.rec.status, "denied");
  assert.strictEqual(out.rec.decision.reason, "No NDA");
});

test("requests past their expiry are dropped from storage, for every site", async () => {
  const d = deps([], 10_000);
  const put = (text, dest, status, expires_at) =>
    (d.data[ex.keyFor(sha(text), dest)] = { request_id: "pex_" + text, status, destination: dest,
                                            hash: sha(text), expires_at });
  put("old-approved", "chatgpt.com", "approved", 9_000);
  put("old-denied", "claude.ai", "denied", 9_999);
  put("live", "chatgpt.com", "approved", 20_000);
  d.data.tenantKey = "k";                                   // the extension's own settings stay
  assert.deepStrictEqual(await ex.poll(d, "chatgpt.com"), []);
  assert.deepStrictEqual(Object.keys(d.data).sort(),
                         [ex.keyFor(sha("live"), "chatgpt.com"), "tenantKey"].sort());
  assert.strictEqual(d.calls.length, 0);                    // nothing pending: no call to Shield
});
