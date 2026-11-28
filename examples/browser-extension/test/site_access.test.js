// node --test examples/browser-extension/test
// Withdrawn site access: which AI sites and Shield the extension can still
// reach, and what the badge, popup and Test connection say about it.
const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const sa = require("../site_access.js");

const EXT = path.join(__dirname, "..");
const manifest = JSON.parse(fs.readFileSync(path.join(EXT, "manifest.json"), "utf8"));
const SHIELD = "https://api.guardrails.votal.ai";
const granted = (set) => async (o) => set.has(o);
const all = () => new Set([...sa.accessTargets(manifest, SHIELD).sites, SHIELD + "/*"]);

test("the targets are the content-script sites and the Shield origin, not loopback", () => {
  const { sites, shield } = sa.accessTargets(manifest, SHIELD + ":8443/v1");
  assert.deepStrictEqual(sites, manifest.content_scripts[0].matches.filter((m) => !/127\.0\.0\.1|localhost/.test(m)));
  assert.ok(sites.length >= 5);
  assert.strictEqual(shield, SHIELD + "/*"); // the port is dropped
  assert.strictEqual(sa.accessTargets(manifest, "not a url").shield, null);
  const withLocal = { content_scripts: [{ matches: ["https://chatgpt.com/*", "http://localhost/*"] }] };
  assert.deepStrictEqual(sa.accessTargets(withLocal, SHIELD).sites, ["https://chatgpt.com/*"]);
});

test("everything granted: no badge, nothing to say", async () => {
  const s = await sa.checkSiteAccess(granted(all()), manifest, SHIELD);
  assert.deepStrictEqual([s.missing, s.shieldMissing], [[], false]);
  assert.deepStrictEqual(sa.accessBadge(s), { text: "", color: "", title: "VotalAI Guardrails" });
  assert.deepStrictEqual(sa.accessLines(s, "enforce"), []);
  assert.deepStrictEqual(sa.originsToRequest(s), []);
});

test("a withdrawn AI site is named, badged and asked for again", async () => {
  const set = all(); set.delete("https://chatgpt.com/*"); set.delete("https://claude.ai/*");
  const s = await sa.checkSiteAccess(granted(set), manifest, SHIELD);
  assert.deepStrictEqual(s.missing.map(sa.patternHost).sort(), ["chatgpt.com", "claude.ai"]);
  const badge = sa.accessBadge(s);
  assert.strictEqual(badge.text, "!");
  assert.match(badge.title, /claude\.ai/);
  assert.deepStrictEqual(sa.accessLines(s, "monitor"),
    ["Not screened on claude.ai, chatgpt.com: this extension's access to these sites is off."]);
  assert.deepStrictEqual(sa.originsToRequest(s).sort(), ["https://chatgpt.com/*", "https://claude.ai/*"]);
});

test("no access to Shield says what happens in each mode", async () => {
  const set = all(); set.delete(SHIELD + "/*");
  const s = await sa.checkSiteAccess(granted(set), manifest, SHIELD);
  assert.strictEqual(s.shieldMissing, true);
  assert.match(sa.accessLines(s, "enforce")[0], /^No access to Shield \(api\.guardrails\.votal\.ai\): .*held, not sent/);
  assert.match(sa.accessLines(s, "monitor")[0], /sent unchecked/);
  assert.deepStrictEqual(sa.originsToRequest(s), [SHIELD + "/*"]);
  assert.strictEqual(sa.accessBadge(s).text, "!");
});

test("a failing permission check never raises a false alarm", async () => {
  const s = await sa.checkSiteAccess(async () => { throw new Error("no API"); }, manifest, SHIELD);
  assert.deepStrictEqual([s.missing, s.shieldMissing], [[], false]);
  assert.strictEqual(sa.accessBadge(s).text, "");
});

test("the background, the Firefox build and the popup all load it", () => {
  const bg = fs.readFileSync(path.join(EXT, "background.js"), "utf8");
  assert.ok(bg.includes('importScripts("site_access.js")'));
  assert.ok(bg.includes("chrome.permissions.onRemoved.addListener"));
  const popup = fs.readFileSync(path.join(EXT, "popup.html"), "utf8");
  assert.ok(popup.indexOf('src="site_access.js"') > -1 &&
            popup.indexOf('src="site_access.js"') < popup.indexOf('src="popup.js"'));
});
