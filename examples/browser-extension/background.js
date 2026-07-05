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
async function screen(text) {
  const cfg = await getConfig();
  const identity = await resolveIdentity();
  if (cfg.mode === "off") return { block: false, warn: false, reason: "", mode: "off", identity };
  if (!cfg.shieldUrl) return { block: false, warn: false, reason: "", error: "no shieldUrl configured", mode: cfg.mode, identity };

  const headers = { "Content-Type": "application/json" };
  if (cfg.tenantKey) headers["X-API-Key"] = cfg.tenantKey;
  if (cfg.proxyToken) headers["Authorization"] = "Bearer " + cfg.proxyToken;
  // Attribution: X-Agent-Key drives the Telemetry "agent" column; device is
  // carried alongside for audit.
  const who = identity.userId || identity.deviceId;
  if (who) headers["X-Agent-Key"] = who;
  if (identity.deviceId) headers["X-Device-Id"] = identity.deviceId;

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

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === "shield-screen") {
    screen(String(msg.text || "")).then(sendResponse);
    return true; // async
  }
  if (msg && msg.type === "shield-test") {
    screen("Shield connection test from browser extension").then(sendResponse);
    return true;
  }
});
