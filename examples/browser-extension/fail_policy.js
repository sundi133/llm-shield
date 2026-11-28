// What the extension does when it cannot get a verdict from Shield: a
// timeout, a network error, an HTTP error (bad key, rate limit, outage) or no
// Shield URL. Pure functions; no chrome.* or fetch here. Loaded by the
// background worker (importScripts) and as a content script before content.js.
//
// A missing verdict is not an approval. In enforce mode the prompt or file is
// held, unless managed policy sets failOpen: true. Monitor mode never blocks,
// so it sends and says it was not checked.

function failsOpen(cfg) {
  return !!cfg && (cfg.failOpen === true || cfg.mode === "monitor");
}

// The verdict the background worker returns when Shield gave none.
function unavailableVerdict(cfg, error, identity) {
  const open = failsOpen(cfg);
  return {
    block: !open,
    warn: false,
    reason: open ? "" : "guardrails unavailable",
    error: String(error || "Shield unavailable"),
    mode: cfg ? cfg.mode : undefined,
    identity,
  };
}

// What the page tells the user about such a verdict. `fileName` is set for
// an attachment and empty for a prompt.
function unavailableNotice(v, fileName) {
  const err = String((v && v.error) || "Shield unavailable");
  const what = fileName ? "Attachment '" + fileName + "'" : "";
  if (v && v.block) {
    return {
      allow: false,
      kind: "block",
      title: "Not sent.",
      detail: (what ? what + ": " : "") + "Shield could not be reached (" + err + "). " +
        "Your organisation does not send " + (what ? "files" : "prompts") +
        " to AI tools unchecked, so try again in a moment.",
    };
  }
  return {
    allow: true,
    kind: "warn",
    title: "Shield unreachable.",
    detail: (what ? what + " sent" : "Sent") + " without screening (" + err + ").",
  };
}

if (typeof module !== "undefined") {
  module.exports = { failsOpen, unavailableVerdict, unavailableNotice };
}
