// Background service worker — does the actual Shield call.
// Runs in the extension origin (not the page), so it is NOT subject to the AI
// site's Content-Security-Policy and CAN attach the optional proxy bearer,
// tenant X-API-Key, and identity/attribution headers. Content script talks to
// it via sendMessage.

// The on-laptop Votal device agent, when present, decides first (agent_client.js).
importScripts("agent_client.js");
// Turns a verdict into the line the user reads (verdict_text.js).
importScripts("verdict_text.js");
// Exception requests and the grant that releases an approved prompt once.
importScripts("exception_client.js");

const DEFAULTS = {
  shieldUrl: "https://api.guardrails.votal.ai",
  tenantKey: "",
  proxyToken: "",
  mode: "warn",
  // Measured against the cloud data plane: an input screen with LLM-evaluated
  // custom policies takes 14-20s, and an output screen 17-20s. A 20s deadline
  // sat AT the p99, so ordinary requests aborted. 45s leaves real headroom.
  timeoutMs: 45000,
  // On a timeout or transport error: false = block (fail closed). "enforce"
  // that silently passes unscreened prompts when Shield is slow is not
  // enforcement. Warn mode still fails open — it never blocks anything.
  failOpen: false,
};

// Resolve the configured screening timeout, clamped to a sane range. Local
// storage returns a string (from the options input); managed policy returns
// an integer — both coerce here. Falls back to the default on junk values.
// The previous default. Anyone who never changed the setting has this SAVED,
// and a saved value beats a new default — which is why raising the default
// alone fixed nobody who had already opened the options page.
const STALE_DEFAULT_MS = 20000;

function resolveTimeoutMs(cfg) {
  const n = parseInt(cfg.timeoutMs, 10);
  if (!Number.isFinite(n) || n < 1000) return DEFAULTS.timeoutMs;
  // A screen against the cloud data plane measures 14-20s. Treat the old
  // default as unset rather than as a deliberate choice: it is not a
  // preference, it is a value that predates knowing the real latency.
  if (n === STALE_DEFAULT_MS) return DEFAULTS.timeoutMs;
  return Math.min(n, 120000);
}

// Managed (policy-pushed) config wins over local config where set. Lets a
// Chrome Enterprise admin force the endpoint/keys/mode/deviceId for the fleet.
async function getManaged() {
  try {
    return (await chrome.storage.managed.get(null)) || {};
  } catch (_) {
    return {}; // no managed policy present
  }
}

async function getConfig() {
  const local = await chrome.storage.local.get(Object.keys(DEFAULTS));
  const managed = await getManaged();
  const pick = (k) =>
    managed[k] != null && managed[k] !== "" ? managed[k] : local[k];
  const out = {};
  for (const k of Object.keys(DEFAULTS)) out[k] = pick(k) || DEFAULTS[k];
  return out;
}

// A stable per-install id, generated once — the fallback when neither a
// policy-pushed userId nor a policy-pushed deviceId is available.
async function getInstallId() {
  const { installId } = await chrome.storage.local.get("installId");
  if (installId) return installId;
  const id = "inst-" + (self.crypto?.randomUUID?.() || Date.now().toString(36));
  await chrome.storage.local.set({ installId: id });
  return id;
}

// Where exception requests are remembered: session storage (gone when the
// browser closes), or local storage on a Chrome without it.
const EXC_AREA = (chrome.storage && chrome.storage.session) || chrome.storage.local;
const excStore = {
  async get(k) { return (await EXC_AREA.get(k))[k] || null; },
  async set(k, v) { await EXC_AREA.set({ [k]: v }); },
  async remove(k) { await EXC_AREA.remove(k); },
  async all() { return (await EXC_AREA.get(null)) || {}; },
};

// The headers every call to Shield carries: tenant key, proxy bearer, and who
// is asking from where. An exception request is bound to the same identity.
function shieldHeaders(cfg, identity, origin) {
  const headers = {};
  if (cfg.tenantKey) headers["X-API-Key"] = cfg.tenantKey;
  if (cfg.proxyToken) headers["Authorization"] = "Bearer " + cfg.proxyToken;
  const who = identity.userId || identity.deviceId;
  if (who) headers["X-Agent-Key"] = who;
  if (identity.deviceId) headers["X-Device-Id"] = identity.deviceId;
  if (origin) headers["X-Shield-Destination"] = origin;
  return headers;
}

async function excDeps(origin) {
  const cfg = await getConfig();
  const identity = await resolveIdentity();
  return { fetch: (...a) => fetch(...a), store: excStore, base: cfg.shieldUrl || "",
           headers: shieldHeaders(cfg, identity, origin), now: () => Date.now() / 1000 };
}

// Who + which device sent this prompt. The extension itself collects no PII;
// identity is whatever the org's MDM policy injects (storage.managed):
//  - userId:   employee id / AD account / email — the org's choice
//  - deviceId: machine name or asset tag, else the per-install id
async function resolveIdentity() {
  const managed = await getManaged();
  const userId = (managed.userId || "").trim();
  const deviceId = (managed.deviceId || "").trim() || (await getInstallId());
  return { userId, deviceId };
}

// Returns { block, warn, reason, error?, mode, identity }
async function screen(text, origin) {
  const cfg = await getConfig();
  const identity = await resolveIdentity();
  if (cfg.mode === "off") return { block: false, warn: false, reason: "", mode: "off", identity };
  // A managed laptop with the Votal device agent decides locally, on the
  // tenant's signed policy: the prompt does not leave the laptop to be judged.
  const local = await agentScreen(text, origin);
  if (local) return { ...local, identity };
  if (!cfg.shieldUrl) return { block: false, warn: false, reason: "", error: "no shieldUrl configured", mode: cfg.mode, identity };

  // Attribution: X-Agent-Key drives the Telemetry "agent" column; device and
  // destination (the AI site being sent to) are carried alongside for audit.
  const headers = { "Content-Type": "application/json", ...shieldHeaders(cfg, identity, origin) };
  // An approved exception for exactly this prompt and site travels with it.
  const deps = { fetch: (...a) => fetch(...a), store: excStore, base: cfg.shieldUrl,
                 headers: shieldHeaders(cfg, identity, origin), now: () => Date.now() / 1000 };
  let exc = { grant: "", rec: null };
  try { exc = await grantFor(deps, text, origin); } catch (_) {}
  if (exc.grant) headers[GRANT_HEADER] = exc.grant;

  const url = cfg.shieldUrl.replace(/\/+$/, "") + "/guardrails/input";
  const body = JSON.stringify({
    message: text,
    user_id: identity.userId || undefined,
    device_id: identity.deviceId || undefined,
  });

  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), resolveTimeoutMs(cfg)); // fail-open on slow/cold worker
    const resp = await fetch(url, { method: "POST", headers, body, signal: ctrl.signal });
    clearTimeout(t);
    if (!resp.ok) return { block: false, warn: false, reason: "", error: "HTTP " + resp.status, mode: cfg.mode, identity };
    const data = await resp.json();
    const flagged = data.safe === false || data.action === "block";
    // `reason` is what the banner shows: the policy and why. `blocked_by`
    // keeps each failed guardrail for an exception request.
    const { reason, items: blocked_by } = explainVerdict(data);
    let outcome = "";
    if (exc.grant) { try { outcome = await afterSend(deps, text, origin, data); } catch (_) {} }
    const exception = {
      released: outcome === "released",                 // sent on an approval
      error: outcome && outcome !== "released" ? outcome : "",
      status: exc.rec && outcome !== "released" ? exc.rec.status : "",   // earlier request for this prompt
      decision: (exc.rec && exc.rec.decision) || null,
    };
    if (cfg.mode === "warn") return { block: false, warn: flagged, reason, blocked_by, exception, mode: "warn", identity };
    return { block: flagged, warn: false, reason, blocked_by, exception, mode: "enforce", identity };
  } catch (e) {
    // A timeout is not an approval. In enforce mode the prompt is held unless
    // the operator has explicitly opted into failing open.
    const timedOut = e && (e.name === "AbortError" || String(e).includes("aborted"));
    const secs = Math.round(resolveTimeoutMs(cfg) / 1000);
    const error = timedOut
      ? `Shield did not respond within ${secs}s`
      : `Could not reach Shield: ${e && e.message ? e.message : String(e)}`;
    const failOpen = cfg.failOpen === true || cfg.mode === "warn";
    return {
      block: !failOpen,
      warn: failOpen && cfg.mode === "warn",
      reason: failOpen ? "" : "guardrails unavailable",
      error,
      mode: cfg.mode,
      identity,
    };
  }
}

// ── file attachment screening ─────────────────────────────────────────────
const FILE_MAX_BYTES = 10 * 1024 * 1024; // keep in sync with SHIELD_FILE_MAX_BYTES

function fileTimeoutMs(size, base) {
  // configured base + 2s per MB, capped at base + 18s — uploads take longer
  // than text, and the headroom scales with the configured timeout.
  return Math.min(base + Math.ceil(size / 1048576) * 2000, base + 18000);
}

function b64ToBlob(b64, type) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new Blob([bytes], { type: type || "application/octet-stream" });
}

// Returns { block, warn, reason, error?, note?, mode, identity }
async function screenFile(meta) {
  const cfg = await getConfig();
  const identity = await resolveIdentity();
  if (cfg.mode === "off") return { block: false, warn: false, reason: "", mode: "off", identity };
  if (!cfg.shieldUrl) return { block: false, warn: false, reason: "", error: "no shieldUrl configured", mode: cfg.mode, identity };
  if (meta.size > FILE_MAX_BYTES) {
    // fail-open above the cap — the server would 413 anyway; skip the upload
    return { block: false, warn: false, reason: "", note: "too large to screen", mode: cfg.mode, identity };
  }

  const headers = {};
  if (cfg.tenantKey) headers["X-API-Key"] = cfg.tenantKey;
  if (cfg.proxyToken) headers["Authorization"] = "Bearer " + cfg.proxyToken;
  const who = identity.userId || identity.deviceId;
  if (who) headers["X-Agent-Key"] = who;
  if (identity.deviceId) headers["X-Device-Id"] = identity.deviceId;
  if (meta.origin) headers["X-Shield-Destination"] = meta.origin;
  // NOTE: no Content-Type header — fetch sets the multipart boundary itself.

  const form = new FormData();
  form.append("file", b64ToBlob(meta.dataB64, meta.mime), meta.name || "attachment");
  if (identity.deviceId) form.append("device_id", identity.deviceId);

  const url = cfg.shieldUrl.replace(/\/+$/, "") + "/guardrails/file";
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), fileTimeoutMs(meta.size, resolveTimeoutMs(cfg)));
    const resp = await fetch(url, { method: "POST", headers, body: form, signal: ctrl.signal });
    clearTimeout(t);
    if (!resp.ok) return { block: false, warn: false, reason: "", error: "HTTP " + resp.status, mode: cfg.mode, identity };
    const data = await resp.json();
    const flagged = data.safe === false || data.action === "block";
    // `reason` is what the banner shows: the policy and why. `blocked_by`
    // keeps each failed guardrail for an exception request.
    const { reason, items: blocked_by } = explainVerdict(data);
    const note = data.file && data.file.note ? data.file.note : undefined;
    if (cfg.mode === "warn") return { block: false, warn: flagged, reason, blocked_by, note, mode: "warn", identity };
    return { block: flagged, warn: false, reason, blocked_by, note, mode: "enforce", identity };
  } catch (e) {
    return { block: false, warn: false, reason: "", error: String(e), mode: cfg.mode, identity };
  }
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === "shield-screen") {
    screen(String(msg.text || ""), msg.origin).then(sendResponse);
    return true; // async
  }
  if (msg && msg.type === "shield-screen-file") {
    // The rejection handler matters: a throw before screenFile's own
    // try/catch (e.g. atob on bad base64) would otherwise leave the message
    // channel open forever and hang the content script fail-closed.
    screenFile(msg.file || {}).then(sendResponse, () =>
      sendResponse({ block: false, warn: false, reason: "", error: "file screening failed" }));
    return true;
  }
  if (msg && msg.type === "shield-exception-request") {
    excDeps(msg.origin)
      .then((deps) => requestException(deps, { text: String(msg.text || ""), destination: String(msg.origin || ""),
                                               reason: String(msg.reason || "") }))
      .then(sendResponse, () => sendResponse({ ok: false, message: "The request could not be sent." }));
    return true;
  }
  if (msg && msg.type === "shield-exception-poll") {
    excDeps(msg.origin).then((deps) => poll(deps, String(msg.origin || ""))).then(sendResponse, () => sendResponse([]));
    return true;
  }
  if (msg && msg.type === "shield-justify") {
    agentJustify(String(msg.prompt_sha256 || ""), String(msg.destination || ""), String(msg.reason || ""))
      .then((granted) => sendResponse({ granted }), () => sendResponse({ granted: false }));
    return true;
  }
  if (msg && msg.type === "shield-test") {
    // Report the settings actually in effect. The last round of this bug was
    // invisible because the popup showed a verdict but never the timeout or
    // mode it used.
    getConfig().then((cfg) =>
      screen("Shield connection test from browser extension").then((r) =>
        sendResponse({
          ...r,
          effective: {
            timeoutMs: resolveTimeoutMs(cfg),
            mode: cfg.mode,
            failOpen: cfg.failOpen === true || cfg.mode === "warn",
            shieldUrl: cfg.shieldUrl,
          },
        })
      )
    );
    return true;
  }
});
