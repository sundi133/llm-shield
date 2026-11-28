// Which AI sites this browser can screen, and whether it can reach Shield
// (docs/specs/firefox-extension.md, task 2).
//
// The user can withdraw the extension's access to a site: in Firefox from the
// add-on's Permissions tab, in Chrome and Edge from its "Site access" menu.
// The content script then stops running there, so nothing on that site is
// screened and nothing says so. This finds those sites so the toolbar badge,
// the popup and Test connection can. Pure functions: the permission check is
// passed in. Loaded by the background worker (importScripts), by the Firefox
// background page (manifest scripts) and by the popup.

const LOOPBACK_PATTERN = /^[a-z*]+:\/\/(127\.0\.0\.1|localhost)(:\d+)?\//i;

// "https://chatgpt.com/*" -> "chatgpt.com"
function patternHost(pattern) {
  const m = /^[a-z*]+:\/\/([^/]+)\//i.exec(String(pattern || ""));
  return m ? m[1] : String(pattern || "");
}

// The AI sites the content script runs on, and the Shield origin it calls.
// The port is dropped: match patterns cover every port of a host.
function accessTargets(manifest, shieldUrl) {
  const sites = [];
  for (const cs of (manifest && manifest.content_scripts) || []) {
    for (const m of cs.matches || []) {
      if (!LOOPBACK_PATTERN.test(m) && !sites.includes(m)) sites.push(m);
    }
  }
  let shield = null;
  try {
    if (shieldUrl) {
      const u = new URL(shieldUrl);
      shield = u.protocol + "//" + u.hostname + "/*";
    }
  } catch (_) {}
  return { sites, shield };
}

// contains(originPattern) -> Promise<boolean>. A check that fails is not
// reported as missing: a broken API must not raise a false alarm.
async function checkSiteAccess(contains, manifest, shieldUrl) {
  const has = async (o) => {
    try { return !!(await contains(o)); } catch (_) { return true; }
  };
  const { sites, shield } = accessTargets(manifest, shieldUrl);
  const missing = [];
  for (const s of sites) if (!(await has(s))) missing.push(s);
  const shieldMissing = shield ? !(await has(shield)) : false;
  return { sites, missing, shield, shieldMissing };
}

// The origins to ask the user for again.
function originsToRequest(state) {
  const out = [...((state && state.missing) || [])];
  if (state && state.shieldMissing && state.shield) out.push(state.shield);
  return out;
}

// The toolbar badge: "!" while something is not covered.
function accessBadge(state) {
  const gaps = originsToRequest(state).map(patternHost);
  if (!gaps.length) return { text: "", color: "", title: "VotalAI Guardrails" };
  return { text: "!", color: "#b91c1c", title: "VotalAI Guardrails: no access to " + gaps.join(", ") };
}

// What the popup and Test connection say. Empty when everything is covered.
function accessLines(state, mode) {
  const lines = [];
  const missing = ((state && state.missing) || []).map(patternHost);
  if (missing.length) {
    lines.push("Not screened on " + missing.join(", ") +
      ": this extension's access to " + (missing.length > 1 ? "these sites" : "this site") + " is off.");
  }
  if (state && state.shieldMissing && state.shield) {
    lines.push("No access to Shield (" + patternHost(state.shield) + "): " +
      (mode === "enforce" ? "prompts on the AI sites are held, not sent."
                          : "prompts on the AI sites are sent unchecked."));
  }
  return lines;
}

if (typeof module !== "undefined") {
  module.exports = { patternHost, accessTargets, checkSiteAccess, originsToRequest, accessBadge, accessLines };
}
