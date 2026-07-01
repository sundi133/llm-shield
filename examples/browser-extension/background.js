// Background service worker — does the actual Shield call.
// Runs in the extension origin (not the page), so it is NOT subject to
// claude.ai's Content-Security-Policy and CAN attach the RunPod bearer +
// tenant X-API-Key headers. Content script talks to it via sendMessage.

const DEFAULTS = { shieldUrl: "", tenantKey: "", proxyToken: "", mode: "warn" };

async function getConfig() {
  const c = await chrome.storage.local.get(Object.keys(DEFAULTS));
  return { ...DEFAULTS, ...c };
}

// Returns { block:boolean, warn:boolean, reason:string, error?:string, mode }
async function screen(text) {
  const cfg = await getConfig();
  if (cfg.mode === "off") return { block: false, warn: false, reason: "", mode: "off" };
  if (!cfg.shieldUrl) return { block: false, warn: false, reason: "", error: "no shieldUrl configured", mode: cfg.mode };

  const headers = { "Content-Type": "application/json" };
  if (cfg.tenantKey) headers["X-API-Key"] = cfg.tenantKey;
  if (cfg.proxyToken) headers["Authorization"] = "Bearer " + cfg.proxyToken;

  const url = cfg.shieldUrl.replace(/\/+$/, "") + "/guardrails/input";
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 12000); // fail-open on slow/cold worker
    const resp = await fetch(url, {
      method: "POST", headers, body: JSON.stringify({ message: text }),
      signal: ctrl.signal,
    });
    clearTimeout(t);
    if (!resp.ok) return { block: false, warn: false, reason: "", error: "HTTP " + resp.status, mode: cfg.mode };
    const data = await resp.json();
    const flagged = data.safe === false || data.action === "block";
    const reason = (data.guardrail_results || [])
      .filter((g) => g && g.passed === false)
      .map((g) => g.guardrail)
      .join(", ") || (data.action || "");
    // monitor mode: report but never block
    if (cfg.mode === "warn") return { block: false, warn: flagged, reason, mode: "warn" };
    // enforce mode: block only on a definite verdict (fail-open on errors above)
    return { block: flagged, warn: false, reason, mode: "enforce" };
  } catch (e) {
    return { block: false, warn: false, reason: "", error: String(e), mode: cfg.mode };
  }
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === "shield-screen") {
    screen(String(msg.text || "")).then(sendResponse);
    return true; // keep the message channel open for async response
  }
  if (msg && msg.type === "shield-test") {
    screen("Shield connection test from browser extension").then(sendResponse);
    return true;
  }
});
