// Content script injected into claude.ai.
// Intercepts the "send" action (Enter key + send button), screens the composer
// text through Shield (via the background worker), and blocks/warns/allows.
//
// NOTE: this is inherently brittle — it depends on claude.ai's DOM. If Anthropic
// changes the composer markup, the selectors below may need updating. This is a
// best-effort client-side control, NOT a security boundary (a user can disable
// the extension). See README.

(() => {
  "use strict";

  // When we approve a message we re-trigger the send; this flag tells our own
  // capturing handlers to let that one synthetic action pass through.
  let bypassNext = false;

  function getComposer(from) {
    return (
      (from && from.closest && from.closest('[contenteditable="true"]')) ||
      document.querySelector('div.ProseMirror[contenteditable="true"]') ||
      document.querySelector('[contenteditable="true"]')
    );
  }

  function getText(el) {
    if (!el) return "";
    return (el.innerText || el.textContent || "").trim();
  }

  function isSendButton(btn) {
    if (!btn) return false;
    const label = (btn.getAttribute("aria-label") || "").toLowerCase();
    if (label.includes("send")) return true;
    // fallback: a submit-type button sitting inside the composer area
    return btn.type === "submit" && !!btn.closest("form");
  }

  function screen(text) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage({ type: "shield-screen", text }, (r) =>
          resolve(r || { block: false })
        );
      } catch (_) {
        resolve({ block: false }); // extension context gone -> fail open
      }
    });
  }

  // ── minimal in-page banner ────────────────────────────────────────────────
  function banner(kind, msg) {
    let el = document.getElementById("shield-guard-banner");
    if (!el) {
      el = document.createElement("div");
      el.id = "shield-guard-banner";
      el.style.cssText =
        "position:fixed;top:0;left:0;right:0;z-index:2147483647;padding:10px 16px;" +
        "font:600 13px/1.4 -apple-system,Segoe UI,Roboto,sans-serif;text-align:center;" +
        "box-shadow:0 2px 8px rgba(0,0,0,.15);transition:opacity .2s;";
      document.documentElement.appendChild(el);
    }
    const styles = {
      block: "background:#fee2e2;color:#991b1b;border-bottom:2px solid #ef4444;",
      warn: "background:#fef9c3;color:#854d0e;border-bottom:2px solid #eab308;",
    };
    el.style.cssText += styles[kind] || styles.warn;
    el.textContent = msg;
    el.style.opacity = "1";
    clearTimeout(el._t);
    el._t = setTimeout(() => (el.style.opacity = "0"), kind === "block" ? 6000 : 3500);
  }

  // ── the interception core ─────────────────────────────────────────────────
  async function guard(getComposerEl, replay) {
    const composer = getComposerEl();
    const text = getText(composer);
    if (!text) return { allow: true };
    const v = await screen(text);
    if (v.error) {
      // fail-open, but surface it so you know screening didn't happen
      banner("warn", "Shield unreachable — sent unscreened (" + v.error + ")");
      return { allow: true };
    }
    if (v.block) {
      banner("block", "Blocked by Shield: " + (v.reason || "policy violation"));
      return { allow: false };
    }
    if (v.warn) banner("warn", "Shield flagged (" + (v.reason || "flagged") + ") — allowed in monitor mode");
    return { allow: true };
  }

  // Enter to send (not Shift+Enter, not during IME composition)
  document.addEventListener(
    "keydown",
    async (e) => {
      if (e.key !== "Enter" || e.shiftKey || e.isComposing) return;
      const composer = getComposer(e.target);
      if (!composer) return;
      if (bypassNext) { bypassNext = false; return; } // our approved replay
      e.preventDefault();
      e.stopImmediatePropagation();
      const { allow } = await guard(() => composer);
      if (!allow) return;
      // approved -> replay the Enter so claude.ai actually sends it
      bypassNext = true;
      composer.dispatchEvent(
        new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true })
      );
    },
    true // capture phase, so we run before claude.ai's handler
  );

  // Clicking the send button
  document.addEventListener(
    "click",
    async (e) => {
      const btn = e.target && e.target.closest && e.target.closest("button");
      if (!isSendButton(btn)) return;
      if (bypassNext) { bypassNext = false; return; }
      e.preventDefault();
      e.stopImmediatePropagation();
      const { allow } = await guard(() => getComposer());
      if (!allow) return;
      bypassNext = true;
      btn.click(); // approved replay
    },
    true
  );

  console.log("[Shield Prompt Guard] active on claude.ai");
})();
