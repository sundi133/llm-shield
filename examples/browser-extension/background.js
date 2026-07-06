// Background service worker — does the actual Shield call.
// Runs in the extension origin (not the page), so it is NOT subject to the AI
// site's Content-Security-Policy and CAN attach the optional proxy bearer,
// tenant X-API-Key, and identity/attribution headers. Content script talks to
// it via sendMessage.

const DEFAULTS = {
  shieldUrl: "https://api.guardrails.votal.ai",
  tenantKey: "",
  proxyToken: "",
  mode: "warn",
};

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
  if (!cfg.shieldUrl) return { block: false, warn: false, reason: "", error: "no shieldUrl configured", mode: cfg.mode, identity };

  const headers = { "Content-Type": "application/json" };
  if (cfg.tenantKey) headers["X-API-Key"] = cfg.tenantKey;
  if (cfg.proxyToken) headers["Authorization"] = "Bearer " + cfg.proxyToken;
  // Attribution: X-Agent-Key drives the Telemetry "agent" column; device and
  // destination (the AI site being sent to) are carried alongside for audit.
  const who = identity.userId || identity.deviceId;
  if (who) headers["X-Agent-Key"] = who;
  if (identity.deviceId) headers["X-Device-Id"] = identity.deviceId;
  if (origin) headers["X-Shield-Destination"] = origin;

  const url = cfg.shieldUrl.replace(/\/+$/, "") + "/guardrails/input";
  const body = JSON.stringify({
    message: text,
    user_id: identity.userId || undefined,
    device_id: identity.deviceId || undefined,
  });

  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 12000); // fail-open on slow/cold worker
    const resp = await fetch(url, { method: "POST", headers, body, signal: ctrl.signal });
    clearTimeout(t);
    if (!resp.ok) return { block: false, warn: false, reason: "", error: "HTTP " + resp.status, mode: cfg.mode, identity };
    const data = await resp.json();
    const flagged = data.safe === false || data.action === "block";
    const reason =
      (data.guardrail_results || [])
        .filter((g) => g && g.passed === false)
        .map((g) => g.guardrail)
        .join(", ") || (data.action || "");
    if (cfg.mode === "warn") return { block: false, warn: flagged, reason, mode: "warn", identity };
    return { block: flagged, warn: false, reason, mode: "enforce", identity };
  } catch (e) {
    return { block: false, warn: false, reason: "", error: String(e), mode: cfg.mode, identity };
  }
}

// ── file attachment screening ─────────────────────────────────────────────
const FILE_MAX_BYTES = 10 * 1024 * 1024; // keep in sync with SHIELD_FILE_MAX_BYTES

function fileTimeoutMs(size) {
  // base 12s + 2s per MB, capped at 30s — uploads take longer than text.
  return Math.min(12000 + Math.ceil(size / 1048576) * 2000, 30000);
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
    const t = setTimeout(() => ctrl.abort(), fileTimeoutMs(meta.size));
    const resp = await fetch(url, { method: "POST", headers, body: form, signal: ctrl.signal });
    clearTimeout(t);
    if (!resp.ok) return { block: false, warn: false, reason: "", error: "HTTP " + resp.status, mode: cfg.mode, identity };
    const data = await resp.json();
    const flagged = data.safe === false || data.action === "block";
    const reason =
      (data.guardrail_results || [])
        .filter((g) => g && g.passed === false)
        .map((g) => g.guardrail)
        .join(", ") || (data.action || "");
    const note = data.file && data.file.note ? data.file.note : undefined;
    if (cfg.mode === "warn") return { block: false, warn: flagged, reason, note, mode: "warn", identity };
    return { block: flagged, warn: false, reason, note, mode: "enforce", identity };
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
  if (msg && msg.type === "shield-test") {
    screen("Shield connection test from browser extension").then(sendResponse);
    return true;
  }
});
