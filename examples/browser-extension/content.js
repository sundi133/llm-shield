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
        chrome.runtime.sendMessage({ type: "shield-screen", text, origin: CFG.name }, (r) =>
          resolve(r || { block: false })
        );
      } catch (_) {
        resolve({ block: false }); // extension context gone -> fail open
      }
    });
  }

  // ── minimal in-page banner ────────────────────────────────────────────────
  // One banner for everything the extension tells the user, so every message
  // looks the same: an optional bold title, the detail, then any buttons.
  //   msg:  "text", or { title, detail }
  //   kind: "block" (red), "warn" (amber) or "ok" (green)
  //   opts.actions: [{ label, onClick, primary }]
  //   opts.sticky:  stay until the user acts or dismisses it
  const BANNER_KINDS = {
    block: { bg: "#fef2f2", fg: "#991b1b", line: "#ef4444", button: "#b91c1c" },
    warn: { bg: "#fffbeb", fg: "#92400e", line: "#f59e0b", button: "#b45309" },
    ok: { bg: "#f0fdf4", fg: "#166534", line: "#22c55e", button: "#15803d" },
  };
  const BANNER_FONT = "-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif";

  function banner(kind, msg, opts = {}) {
    const k = BANNER_KINDS[kind] || BANNER_KINDS.warn;
    let el = document.getElementById("shield-guard-banner");
    if (!el) {
      el = document.createElement("div");
      el.id = "shield-guard-banner";
      el.setAttribute("role", "status");
      document.documentElement.appendChild(el);
    }
    el.style.cssText =
      "position:fixed;top:0;left:0;right:0;z-index:2147483647;padding:10px 16px;" +
      "display:flex;flex-wrap:wrap;align-items:center;justify-content:center;gap:8px 14px;" +
      "font:400 13px/1.45 " + BANNER_FONT + ";box-shadow:0 2px 8px rgba(0,0,0,.12);transition:opacity .2s;" +
      `background:${k.bg};color:${k.fg};border-bottom:2px solid ${k.line};`;
    el.replaceChildren();
    const { title, detail } = typeof msg === "string" ? { title: "", detail: msg } : msg;
    // Text nodes only: the detail can contain the user's own words.
    const text = document.createElement("span");
    text.style.cssText = "max-width:920px;";
    if (title) {
      const t = document.createElement("strong");
      t.style.fontWeight = "600";
      t.textContent = title;
      text.appendChild(t);
      if (detail) text.appendChild(document.createTextNode(" "));
    }
    if (detail) text.appendChild(document.createTextNode(detail));
    el.appendChild(text);
    const actions = document.createElement("span");
    actions.style.cssText = "display:inline-flex;gap:8px;align-items:center;flex-wrap:wrap;";
    for (const a of opts.actions || []) actions.appendChild(bannerButton(a.label, a.onClick, a.primary, k));
    if (opts.sticky && !opts.noDismiss) actions.appendChild(bannerButton(opts.dismissLabel || "Dismiss", hideBanner, false, k));
    if (actions.childNodes.length) el.appendChild(actions);
    el.style.opacity = "1";
    el.style.pointerEvents = "auto";
    clearTimeout(el._t);
    if (opts.sticky) return el;
    // A block explains which policy and why: long enough to read.
    const len = String(title || "").length + String(detail || "").length;
    const ms = kind === "block" ? Math.min(20000, 6000 + 40 * len) : 4000;
    el._t = setTimeout(hideBanner, ms);
    return el;
  }

  function hideBanner() {
    const el = document.getElementById("shield-guard-banner");
    if (el) { el.style.opacity = "0"; el.style.pointerEvents = "none"; }
  }

  function bannerButton(label, onClick, primary, k) {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = label;
    b.style.cssText =
      "padding:4px 12px;border-radius:6px;font:600 12px/1.4 " + BANNER_FONT + ";cursor:pointer;" +
      (primary ? `background:${k.button};color:#fff;border:1px solid ${k.button};`
               : `background:transparent;color:${k.fg};border:1px solid ${k.line};`);
    b.addEventListener("click", (e) => { e.preventDefault(); e.stopPropagation(); onClick(); });
    return b;
  }

  // Our own banner's controls are never the site's composer or send button.
  function inBanner(el) {
    return !!(el && el.closest && el.closest("#shield-guard-banner"));
  }

  // Every detail ends as a sentence, whatever the server's message did.
  function sentence(t) {
    const s = String(t || "").trim();
    return !s || /[.!?]$/.test(s) ? s : s + ".";
  }

  // ── exception requests (docs/specs/prompt-exception-requests.md) ─────────
  function excSend(msg) {
    return new Promise((resolve) => {
      try { chrome.runtime.sendMessage(msg, (r) => resolve(r)); } catch (_) { resolve(null); }
    });
  }

  // The block banner, with what the user can do next about this prompt.
  function blockBanner(text, v) {
    const title = "Blocked by Shield.";
    const why = sentence(v.reason || "This prompt breaks your organisation's AI policy");
    const ex = v.exception || {};
    const ask = { label: "Request exception", primary: true, onClick: () => askForm(text) };
    if (ex.error === "new_violation") {
      return banner("block", { title, detail: why + " Your approved exception does not cover this." }, { sticky: true });
    }
    if (ex.status === "pending") {
      return banner("block", { title, detail: why + " Your exception request is waiting for review." }, { sticky: true });
    }
    if (ex.status === "denied") {
      const note = ex.decision && ex.decision.reason ? ": " + ex.decision.reason : "";
      return banner("block", { title, detail: why + " Your earlier request was denied" + sentence(note || ".") },
                    { sticky: true, actions: [{ ...ask, label: "Ask again" }] });
    }
    return banner("block", { title, detail: why }, { sticky: true, actions: [ask] });
  }

  // The reason form, in the banner itself.
  function askForm(text) {
    const el = banner("block", { title: "Request an exception.",
                                 detail: "Say why this prompt should be sent. Reviewers will see the prompt and your reason." },
                      { sticky: true, dismissLabel: "Cancel" });
    const k = BANNER_KINDS.block;
    const input = document.createElement("input");
    input.type = "text";
    input.maxLength = 500;
    input.placeholder = "For example: the partner is under NDA";
    input.setAttribute("aria-label", "Reason for the exception");
    input.style.cssText = `width:min(380px,70vw);padding:4px 10px;border-radius:6px;border:1px solid ${k.line};` +
      `font:400 13px/1.4 ${BANNER_FONT};color:#111827;background:#fff;outline:none;`;
    // The page's own Enter handling must not see keys typed here.
    input.addEventListener("keydown", (e) => { e.stopPropagation(); if (e.key === "Enter") submit(); }, true);
    const submit = async () => {
      const reason = input.value.trim();
      if (reason.length < 3) { input.focus(); input.style.borderColor = k.button; return; }
      banner("warn", { title: "Sending your request..." }, { sticky: true, noDismiss: true });
      const r = await excSend({ type: "shield-exception-request", text, origin: CFG.name, reason });
      if (r && r.ok) {
        banner("warn", { title: "Request sent.",
                         detail: "You will see the answer here. You can also come back later and send the same prompt again." },
               { sticky: true });
      } else {
        banner("block", { title: "Request not sent.", detail: sentence((r && r.message) || "Try again") },
               { sticky: true });
      }
    };
    const actions = el.lastChild;
    actions.insertBefore(bannerButton("Send request", submit, true, k), actions.firstChild);
    actions.insertBefore(input, actions.firstChild);
    setTimeout(() => input.focus(), 0);
  }

  // Answers arrive while the tab is open: ask every 30 seconds. The background
  // only calls Shield when this site has a request waiting.
  setInterval(async () => {
    const changes = await excSend({ type: "shield-exception-poll", origin: CFG.name });
    for (const c of changes || []) {
      if (c.status === "approved") {
        banner("ok", { title: "Exception approved.", detail: "Send the same prompt again to send it once." }, { sticky: true });
      } else if (c.status === "denied") {
        const note = c.decision && c.decision.reason ? c.decision.reason : "No reason was given";
        banner("block", { title: "Exception denied.", detail: sentence(note) }, { sticky: true });
      } else if (c.status === "expired") {
        banner("block", { title: "Exception request expired.", detail: "Nobody reviewed it in time. You can ask again." },
               { sticky: true });
      }
    }
  }, 30000);

  // Replace the composer's text (the device agent's redaction). Returns whether
  // the page now holds exactly that text; if not, the caller blocks instead of
  // sending the unredacted prompt.
  function setText(el, text) {
    try {
      el.focus();
      if ("value" in el && typeof el.value === "string") {
        const proto = Object.getPrototypeOf(el);
        const setter = Object.getOwnPropertyDescriptor(proto, "value").set;
        setter.call(el, text);
        el.dispatchEvent(new Event("input", { bubbles: true }));
      } else {
        // Rich editors (ProseMirror, Quill) follow execCommand, not textContent.
        document.execCommand("selectAll", false, null);
        document.execCommand("insertText", false, text);
      }
    } catch (_) {
      return false;
    }
    return getText(el) === text.trim();
  }

  function justifyAsk(v) {
    return new Promise((resolve) => {
      const reason = window.prompt(
        (v.reason || "This looks like sensitive data.") +
          "\n\nTo send it anyway, say why (recorded with the decision):", "");
      if (!reason || reason.trim().length < 3) return resolve(false);
      try {
        chrome.runtime.sendMessage(
          { type: "shield-justify", prompt_sha256: v.prompt_sha256, destination: v.destination, reason },
          (r) => resolve(!!(r && r.granted)));
      } catch (_) {
        resolve(false);
      }
    });
  }

  // ── the interception core ─────────────────────────────────────────────────
  async function guard(getComposerEl) {
    const composer = getComposerEl();
    const text = getText(composer);
    if (!text) return { allow: true };
    const v = await screen(text);
    if (v.source === "agent") {
      // The device agent decided on this laptop.
      if (v.block) {
        banner("block", v.reason || "Blocked by your company's AI data policy");
        return { allow: false };
      }
      if (v.redact) {
        if (typeof v.text === "string" && setText(composer, v.text)) {
          banner("warn", v.reason || "Sensitive values were replaced before sending");
          return { allow: true };
        }
        banner("block", "Blocked: sensitive values could not be removed from this prompt");
        return { allow: false };
      }
      if (v.justify) {
        const granted = await justifyAsk(v);
        if (!granted) banner("block", v.reason || "Not sent: a reason is needed");
        return { allow: granted };
      }
      if (v.warn) banner("warn", { title: "Flagged.", detail: sentence(v.reason || v.verdict || "Policy") + " Allowed because your policy is in monitor mode." });
      return { allow: true };
    }
    if (v.error) {
      banner("warn", { title: "Shield unreachable.", detail: "Sent without screening (" + v.error + ")." });
      return { allow: true }; // fail-open
    }
    if (v.block) {
      blockBanner(text, v);
      return { allow: false };
    }
    if (v.exception && v.exception.released) {
      banner("ok", { title: "Sent with an approved exception.", detail: "It covered this prompt once." });
      return { allow: true };
    }
    if (v.warn) banner("warn", { title: "Flagged by Shield.", detail: sentence(v.reason || "Flagged") + " Allowed because Shield is in monitor mode." });
    return { allow: true };
  }

  // Enter to send (not Shift+Enter, not during IME composition)
  document.addEventListener(
    "keydown",
    async (e) => {
      if (e.key !== "Enter" || e.shiftKey || e.isComposing) return;
      if (inBanner(e.target)) return;   // Enter in the exception reason field
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
      if (inBanner(btn) || !isSendButton(btn)) return;
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

  // Cached mode so interceptors can no-op synchronously when mode=off — the
  // event must be cancelled before any await, so we can't ask the background
  // worker first. Managed policy wins over local, like getConfig().
  let shieldMode = "warn";
  async function refreshShieldMode() {
    try {
      let managedMode = "";
      try {
        managedMode = ((await chrome.storage.managed.get("mode")) || {}).mode || "";
      } catch (_) {}
      const local = (await chrome.storage.local.get("mode")) || {};
      shieldMode = managedMode || local.mode || "warn";
    } catch (_) {}
  }
  refreshShieldMode();
  try { chrome.storage.onChanged.addListener(refreshShieldMode); } catch (_) {}

  // Approved synthetic events are marked directly (not via a global flag) so
  // an unrelated event of the same type can never consume the approval while
  // a screen is in flight.
  const approvedEvents = new WeakSet();

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

  async function screenOneFile(file) {
    if (file.size > FILE_MAX_BYTES) {
      // don't read 100MB into memory just to skip it
      return { block: false, note: "too large to screen" };
    }
    let dataB64 = "";
    try {
      dataB64 = await readAsB64(file);
    } catch (_) {
      return { block: false, error: "could not read file" };
    }
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(
          { type: "shield-screen-file",
            file: { name: file.name, mime: file.type, size: file.size, dataB64, origin: CFG.name } },
          (r) => resolve(r || { block: false })
        );
      } catch (_) {
        resolve({ block: false }); // extension context gone -> fail open
      }
    });
  }

  // Screens all files concurrently; any block blocks the whole batch.
  async function guardFiles(files) {
    const list = Array.from(files || []);
    if (!list.length) return { allow: true };
    const verdicts = await Promise.all(list.map(screenOneFile));
    for (let i = 0; i < list.length; i++) {
      const f = list[i], v = verdicts[i];
      if (v.block) {
        banner("block", { title: "Blocked by Shield.", detail: "Attachment '" + f.name + "': " + sentence(v.reason || "policy violation") });
        return { allow: false };
      }
    }
    for (let i = 0; i < list.length; i++) {
      const f = list[i], v = verdicts[i];
      if (v.error) {
        banner("warn", { title: "Shield unreachable.", detail: "Attachment '" + f.name + "' sent without screening (" + v.error + ")." });
      } else if (v.note === "too large to screen") {
        banner("warn", { title: "Attachment not screened.", detail: "'" + f.name + "' is too large to screen and was sent without screening." });
      } else if (v.note && !v.warn) {
        banner("warn", "Attachment '" + f.name + "': " + v.note + " (filename screened)");
      } else if (v.warn) {
        banner("warn", { title: "Flagged by Shield.", detail: "Attachment '" + f.name + "': " + sentence(v.reason || "flagged") + " Allowed because Shield is in monitor mode." });
      }
    }
    return { allow: true };
  }

  // Reads must happen synchronously in the event handler — DataTransfer is
  // neutered once the handler returns / awaits.
  function captureStringItems(dt) {
    const out = [];
    try {
      for (const type of dt.types || []) {
        if (type === "Files") continue;
        const v = dt.getData(type);
        if (v) out.push([type, v]);
      }
    } catch (_) {}
    return out;
  }

  function rebuildDataTransfer(files, stringItems) {
    const dt = new DataTransfer();
    for (const f of files) dt.items.add(f);
    for (const [type, value] of stringItems || []) {
      try { dt.setData(type, value); } catch (_) {}
    }
    return dt;
  }

  // 1. File picker: <input type="file"> change
  document.addEventListener(
    "change",
    async (e) => {
      if (shieldMode === "off") return;
      const input = e.target;
      if (!input || input.type !== "file" || !input.files || !input.files.length) return;
      if (approvedEvents.has(e)) return;
      e.stopImmediatePropagation(); // hold the site's handler until screened
      const { allow } = await guardFiles(input.files);
      if (!allow) {
        input.value = ""; // clear the selection so the site never sees it
        return;
      }
      const replay = new Event("change", { bubbles: true });
      approvedEvents.add(replay);
      input.dispatchEvent(replay);
    },
    true
  );

  // 2. Drag-and-drop onto the page
  document.addEventListener(
    "drop",
    async (e) => {
      if (shieldMode === "off") return;
      const files = e.dataTransfer && e.dataTransfer.files;
      if (!files || !files.length) return; // text drags pass through
      if (approvedEvents.has(e)) return;
      e.preventDefault();
      e.stopImmediatePropagation();
      const target = e.target;
      const kept = Array.from(files);
      const strings = captureStringItems(e.dataTransfer);
      const { allow } = await guardFiles(kept);
      if (!allow) return;
      try {
        const replay = new DragEvent("drop", {
          bubbles: true, cancelable: true,
          dataTransfer: rebuildDataTransfer(kept, strings),
        });
        approvedEvents.add(replay);
        target.dispatchEvent(replay);
      } catch (_) {
        banner("ok", { title: "Attachment allowed.", detail: "Drop it again to attach it." });
      }
    },
    true
  );

  // 3. Paste with files (screenshots, copied files)
  document.addEventListener(
    "paste",
    async (e) => {
      if (shieldMode === "off") return;
      const files = e.clipboardData && e.clipboardData.files;
      if (!files || !files.length) return; // plain text paste passes through
      if (approvedEvents.has(e)) return;
      e.preventDefault();
      e.stopImmediatePropagation();
      const target = e.target;
      const kept = Array.from(files);
      const strings = captureStringItems(e.clipboardData);
      const { allow } = await guardFiles(kept);
      if (!allow) return;
      try {
        const replay = new ClipboardEvent("paste", {
          bubbles: true, cancelable: true,
          clipboardData: rebuildDataTransfer(kept, strings),
        });
        approvedEvents.add(replay);
        target.dispatchEvent(replay);
      } catch (_) {
        banner("ok", { title: "Attachment allowed.", detail: "Paste it again to attach it." });
      }
    },
    true
  );

  console.log("[VotalAI Guardrails] active on " + CFG.name);
})();
