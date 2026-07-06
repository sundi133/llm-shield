// Content script injected into supported public-AI sites (Claude, ChatGPT,
// Gemini, Copilot). Intercepts the "send" action (Enter key + send button),
// screens the composer text through Shield (via the background worker), and
// blocks/warns/allows.
//
// NOTE: this is inherently brittle — it depends on each site's DOM. If a site
// changes its composer/send markup, update that site's entry in SITES below.
// This is a best-effort client-side control, NOT a security boundary (a user
// can disable the extension). See README.

(() => {
  "use strict";

  // ── per-site selectors ─────────────────────────────────────────────────────
  // Each site lists candidate selectors (first match wins); generic fallbacks
  // are appended so a minor markup change still has a chance of working.
  const GENERIC_COMPOSER = ['div[contenteditable="true"]', "textarea"];
  const GENERIC_SEND = ['button[aria-label*="send" i]', 'button[aria-label*="submit" i]'];

  const SITES = {
    "claude.ai": {
      composer: ['div.ProseMirror[contenteditable="true"]', 'div[contenteditable="true"]'],
      send: ['button[aria-label*="send" i]'],
    },
    "chatgpt.com": {
      composer: ['#prompt-textarea', 'div[contenteditable="true"]', "textarea"],
      send: ['button[data-testid="send-button"]', 'button[aria-label*="send" i]'],
    },
    "chat.openai.com": {
      composer: ['#prompt-textarea', 'div[contenteditable="true"]', "textarea"],
      send: ['button[data-testid="send-button"]', 'button[aria-label*="send" i]'],
    },
    "gemini.google.com": {
      composer: ['rich-textarea .ql-editor[contenteditable="true"]', 'div.ql-editor[contenteditable="true"]', 'div[contenteditable="true"]'],
      send: ['button[aria-label*="send" i]', "button.send-button"],
    },
    "copilot.microsoft.com": {
      composer: ['textarea#userInput', 'textarea[data-testid="composer-input"]', 'div[contenteditable="true"]', "textarea"],
      send: ['button[data-testid="submit-button"]', 'button[aria-label*="submit" i]', 'button[aria-label*="send" i]'],
    },
  };

  function siteConfig() {
    const host = location.hostname;
    // match by suffix so www./app. subdomains still resolve
    const key = Object.keys(SITES).find((h) => host === h || host.endsWith("." + h));
    const cfg = key ? SITES[key] : {};
    return {
      name: key || host,
      composer: [...(cfg.composer || []), ...GENERIC_COMPOSER],
      send: [...(cfg.send || []), ...GENERIC_SEND],
    };
  }

  const CFG = siteConfig();

  // When we approve a message we re-trigger the send; this flag tells our own
  // capturing handlers to let that one synthetic action pass through.
  let bypassNext = false;

  function firstMatch(selectors, root = document) {
    for (const sel of selectors) {
      try {
        const el = root.querySelector(sel);
        if (el) return el;
      } catch (_) {}
    }
    return null;
  }

  function getComposer(from) {
    if (from && from.closest) {
      for (const sel of CFG.composer) {
        try {
          const el = from.closest(sel);
          if (el) return el;
        } catch (_) {}
      }
    }
    return firstMatch(CFG.composer);
  }

  function getText(el) {
    if (!el) return "";
    // textarea / input use .value; contenteditable uses innerText
    if ("value" in el && typeof el.value === "string") return el.value.trim();
    return (el.innerText || el.textContent || "").trim();
  }

  function isSendButton(btn) {
    if (!btn) return false;
    for (const sel of CFG.send) {
      try {
        if (btn.matches(sel)) return true;
      } catch (_) {}
    }
    const label = (btn.getAttribute("aria-label") || "").toLowerCase();
    if (label.includes("send") || label.includes("submit")) return true;
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
  async function guard(getComposerEl) {
    const composer = getComposerEl();
    const text = getText(composer);
    if (!text) return { allow: true };
    const v = await screen(text);
    if (v.error) {
      banner("warn", "Shield unreachable — sent unscreened (" + v.error + ")");
      return { allow: true }; // fail-open
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
      bypassNext = true;
      composer.dispatchEvent(
        new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true })
      );
    },
    true // capture phase, so we run before the site's handler
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

  // ── file attachment screening ─────────────────────────────────────────────
  // Same capture-screen-replay idea as the send interceptors above, applied to
  // the three ways a file reaches the composer: picker (<input type=file>
  // change), drag-and-drop, and paste. Fail-open: screening problems show a
  // banner but never eat the file.

  const FILE_MAX_BYTES = 10 * 1024 * 1024; // mirror of background's cap

  let bypassFileChange = false;
  let bypassDrop = false;
  let bypassPaste = false;

  function readAsB64(file) {
    return new Promise((resolve, reject) => {
      const fr = new FileReader();
      fr.onerror = () => reject(fr.error || new Error("read failed"));
      fr.onload = () => {
        const s = String(fr.result || "");
        resolve(s.slice(s.indexOf(",") + 1)); // strip data:...;base64, prefix
      };
      fr.readAsDataURL(file);
    });
  }

  function screenOneFile(file) {
    return new Promise(async (resolve) => {
      if (file.size > FILE_MAX_BYTES) {
        // don't read 100MB into memory just to skip it
        resolve({ block: false, note: "too large to screen" });
        return;
      }
      let dataB64 = "";
      try {
        dataB64 = await readAsB64(file);
      } catch (_) {
        resolve({ block: false, error: "could not read file" });
        return;
      }
      try {
        chrome.runtime.sendMessage(
          { type: "shield-screen-file",
            file: { name: file.name, mime: file.type, size: file.size, dataB64 } },
          (r) => resolve(r || { block: false })
        );
      } catch (_) {
        resolve({ block: false }); // extension context gone -> fail open
      }
    });
  }

  // Screens every file; any block blocks the whole batch.
  async function guardFiles(files) {
    const list = Array.from(files || []);
    if (!list.length) return { allow: true };
    for (const f of list) {
      const v = await screenOneFile(f);
      if (v.error) {
        banner("warn", "Shield unreachable — attachment '" + f.name + "' sent unscreened (" + v.error + ")");
        continue; // fail-open
      }
      if (v.note && !v.block && !v.warn) {
        banner("warn", "Attachment '" + f.name + "' " + v.note + " — sent unscreened");
        continue;
      }
      if (v.block) {
        banner("block", "Blocked by Shield: attachment '" + f.name + "' (" + (v.reason || "policy violation") + ")");
        return { allow: false };
      }
      if (v.warn) {
        banner("warn", "Shield flagged attachment '" + f.name + "' (" + (v.reason || "flagged") + ") — allowed in monitor mode");
      }
    }
    return { allow: true };
  }

  function rebuildDataTransfer(files) {
    const dt = new DataTransfer();
    for (const f of files) dt.items.add(f);
    return dt;
  }

  // 1. File picker: <input type="file"> change
  document.addEventListener(
    "change",
    async (e) => {
      const input = e.target;
      if (!input || input.type !== "file" || !input.files || !input.files.length) return;
      if (bypassFileChange) { bypassFileChange = false; return; }
      e.stopImmediatePropagation(); // hold the site's handler until screened
      const files = Array.from(input.files);
      const { allow } = await guardFiles(files);
      if (!allow) {
        input.value = ""; // clear the selection so the site never sees it
        return;
      }
      bypassFileChange = true;
      input.dispatchEvent(new Event("change", { bubbles: true })); // approved replay
    },
    true
  );

  // 2. Drag-and-drop onto the page
  document.addEventListener(
    "drop",
    async (e) => {
      const files = e.dataTransfer && e.dataTransfer.files;
      if (!files || !files.length) return; // text drags pass through
      if (bypassDrop) { bypassDrop = false; return; }
      e.preventDefault();
      e.stopImmediatePropagation();
      const target = e.target;
      const kept = Array.from(files);
      const { allow } = await guardFiles(kept);
      if (!allow) return;
      try {
        bypassDrop = true;
        target.dispatchEvent(new DragEvent("drop", {
          bubbles: true, cancelable: true, dataTransfer: rebuildDataTransfer(kept),
        }));
      } catch (_) {
        bypassDrop = false;
        banner("warn", "Attachment approved — please drop it again");
      }
    },
    true
  );

  // 3. Paste with files (screenshots, copied files)
  document.addEventListener(
    "paste",
    async (e) => {
      const files = e.clipboardData && e.clipboardData.files;
      if (!files || !files.length) return; // plain text paste passes through
      if (bypassPaste) { bypassPaste = false; return; }
      e.preventDefault();
      e.stopImmediatePropagation();
      const target = e.target;
      const kept = Array.from(files);
      const { allow } = await guardFiles(kept);
      if (!allow) return;
      try {
        bypassPaste = true;
        target.dispatchEvent(new ClipboardEvent("paste", {
          bubbles: true, cancelable: true, clipboardData: rebuildDataTransfer(kept),
        }));
      } catch (_) {
        bypassPaste = false;
        banner("warn", "Attachment approved — please paste it again");
      }
    },
    true
  );

  console.log("[Shield Prompt Guard] active on " + CFG.name);
})();
