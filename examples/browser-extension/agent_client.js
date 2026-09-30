// The Votal device agent, when this laptop has one (docs/specs/device-dlp-agent.md).
//
// The agent decides on the laptop: the prompt is never sent to Shield for
// inspection. The extension finds it through native messaging (the host hands
// over the loopback port and a per-install secret), then asks
// http://127.0.0.1:<port>/v1/local/check. No agent, or no answer in time:
// null, and the caller falls back to screening through Shield as before.
//
// Loaded by background.js with importScripts; exported for node --test.

const VOTAL_AGENT = {
  hostName: "ai.votal.device_agent",
  timeoutMs: 3000,        // rules take microseconds; the model at most model_timeout_ms
  retryAfterMs: 60000,    // how long to remember "no agent here"
  conn: null,             // {port, secret}
  missingUntil: 0,
};

function votalNow() { return Date.now(); }

function agentHello(force) {
  if (VOTAL_AGENT.conn && !force) return Promise.resolve(VOTAL_AGENT.conn);
  if (!force && votalNow() < VOTAL_AGENT.missingUntil) return Promise.resolve(null);
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendNativeMessage(VOTAL_AGENT.hostName, { type: "hello" }, (r) => {
        const err = chrome.runtime.lastError;
        if (err || !r || !r.ok || !r.port || !r.secret) {
          VOTAL_AGENT.conn = null;
          VOTAL_AGENT.missingUntil = votalNow() + VOTAL_AGENT.retryAfterMs;
          return resolve(null);
        }
        VOTAL_AGENT.conn = { port: r.port, secret: r.secret };
        resolve(VOTAL_AGENT.conn);
      });
    } catch (_) {
      VOTAL_AGENT.missingUntil = votalNow() + VOTAL_AGENT.retryAfterMs;
      resolve(null);
    }
  });
}

async function agentCall(path, body, retried) {
  const conn = await agentHello(false);
  if (!conn) return null;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), VOTAL_AGENT.timeoutMs);
  try {
    const resp = await fetch(`http://127.0.0.1:${conn.port}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Votal-Local-Secret": conn.secret },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    if (resp.status === 401 && !retried) {
      // The agent was reinstalled and has a new secret.
      await agentHello(true);
      return agentCall(path, body, true);
    }
    if (!resp.ok && resp.status !== 409) return null;
    return await resp.json();
  } catch (_) {
    VOTAL_AGENT.conn = null;   // agent stopped: look again next time
    return null;
  } finally {
    clearTimeout(t);
  }
}

// The agent's decision in the shape content.js understands, or null.
async function agentScreen(text, destination) {
  const d = await agentCall("/v1/local/check", { text, destination, app: "browser" });
  if (!d || !d.action) return null;
  const notice = d.notice || d.reason || "";
  const base = {
    source: "agent", mode: d.enforced ? "enforce" : "monitor", reason: notice,
    verdict: d.verdict, prompt_sha256: d.prompt_sha256, destination: d.destination,
  };
  if (d.action === "block") return { ...base, block: true, warn: false };
  if (d.action === "justify") return { ...base, block: false, warn: false, justify: true };
  if (d.action === "redact") return { ...base, block: false, warn: false, redact: true, text: d.text };
  // allow: in monitor mode say what would have happened
  const flagged = !d.enforced && ["block", "justify", "redact"].includes(d.verdict);
  return { ...base, block: false, warn: flagged || d.verdict === "monitor" };
}

async function agentJustify(prompt_sha256, destination, reason) {
  const r = await agentCall("/v1/local/justify", { prompt_sha256, destination, reason });
  return !!(r && r.granted);
}

if (typeof module !== "undefined") {
  module.exports = { VOTAL_AGENT, agentHello, agentScreen, agentJustify };
}
