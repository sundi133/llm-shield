/* Votal Shield — service worker: config + network (bundle fetch, escalation).
 * Content scripts never hold the tenant key or talk to Shield directly; they
 * message the worker, which does the authenticated calls. */
const DEFAULTS = { shieldUrl: "", tenantKey: "", proxyToken: "", escalate: true, enabled: true };
const TTL_MS = 5 * 60 * 1000;
let _bundle = null, _etag = null, _at = 0;

async function cfg() { return Object.assign({}, DEFAULTS, await chrome.storage.sync.get(DEFAULTS)); }
function headers(c) {
  const h = { "Content-Type": "application/json", "X-API-Key": c.tenantKey };
  if (c.proxyToken) h["Authorization"] = "Bearer " + c.proxyToken;
  return h;
}
const base = (u) => u.replace(/\/+$/, "");

async function getBundle(force) {
  const c = await cfg();
  if (!c.shieldUrl || !c.tenantKey) return { rules: [], blocklists: [] };
  if (_bundle && !force && Date.now() - _at < TTL_MS) return _bundle;
  try {
    const h = headers(c);
    if (_etag) h["If-None-Match"] = _etag;
    const r = await fetch(base(c.shieldUrl) + "/v1/edge/policy-bundle", { headers: h });
    if (r.status === 304) { _at = Date.now(); return _bundle || { rules: [], blocklists: [] }; }
    if (r.ok) { _bundle = await r.json(); _etag = r.headers.get("ETag"); _at = Date.now(); }
  } catch (_e) { /* offline: keep last good bundle (still enforces T0) */ }
  return _bundle || { rules: [], blocklists: [] };
}

async function escalate(text) {
  const c = await cfg();
  if (!c.shieldUrl || !c.tenantKey) return { blocked: false, error: "unconfigured" };
  try {
    const r = await fetch(base(c.shieldUrl) + "/guardrails/input", {
      method: "POST", headers: headers(c), body: JSON.stringify({ message: text }),
    });
    if (!r.ok) return { blocked: false, error: "http " + r.status };  // fail-open on server error
    const d = await r.json();
    return { blocked: d.safe === false || d.action === "block", detail: d };
  } catch (e) { return { blocked: false, error: String(e) }; }  // fail-open on network error
}

chrome.runtime.onMessage.addListener((msg, _sender, send) => {
  if (msg && msg.type === "getBundle") { getBundle(msg.force).then(send); return true; }
  if (msg && msg.type === "escalate") { escalate(msg.text).then(send); return true; }
  if (msg && msg.type === "getFlags") { cfg().then((c) => send({ escalate: c.escalate, enabled: c.enabled })); return true; }
});
