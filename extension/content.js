/* Votal Shield — content script: intercept the prompt at submit, enforce T0
 * locally, escalate ambiguous text to the server, then let it send.
 *
 * MVP design (honest):
 *   - T0 (local rules) is PREVENTIVE: block or redact before the prompt leaves.
 *   - On locally-clean text we "hold and check" with the server; if clean we
 *     re-send. Re-send uses a per-element pass-through guard + a Send-button
 *     fallback. Per-site DOM varies, so this is best-effort — the *blocking*
 *     path (the important one) does not depend on re-send.
 */
(async function () {
  const flags = await chrome.runtime.sendMessage({ type: "getFlags" }).catch(() => ({}));
  if (!flags || flags.enabled === false) return;
  let bundle = await chrome.runtime.sendMessage({ type: "getBundle" }).catch(() => null);
  setInterval(async () => {
    bundle = await chrome.runtime.sendMessage({ type: "getBundle" }).catch(() => bundle);
  }, 5 * 60 * 1000);

  const PASS = new WeakSet();

  const isEditable = (el) => el && (el.isContentEditable || el.tagName === "TEXTAREA");
  const readText = (el) => (el.value != null ? el.value : (el.innerText || el.textContent || ""));
  function writeText(el, t) {
    if (el.value != null) { el.value = t; } else { el.innerText = t; }
    el.dispatchEvent(new Event("input", { bubbles: true }));
  }

  // --- minimal overlay ---
  let _ov;
  function overlay(text, spinner) {
    hide();
    _ov = document.createElement("div");
    _ov.style.cssText = "position:fixed;z-index:2147483647;top:16px;right:16px;max-width:360px;background:#16213e;color:#fff;font:13px/1.4 system-ui;padding:12px 14px;border-radius:10px;box-shadow:0 6px 24px rgba(0,0,0,.3)";
    _ov.textContent = (spinner ? "⏳ " : "🛡️ ") + text;
    document.documentElement.appendChild(_ov);
    if (!spinner) setTimeout(hide, 5000);
  }
  function hide() { if (_ov && _ov.parentNode) _ov.parentNode.removeChild(_ov); _ov = null; }

  const SEND_BUTTON_SELECTOR = ['button[data-testid="send-button"]', 'button[aria-label*="Send" i]',
    'button[aria-label*="Submit" i]', 'button[type="submit"]'].join(", ");

  function findSendButton(near) {
    const b = document.querySelector(SEND_BUTTON_SELECTOR);
    return b || null;
  }

  function findComposer() {
    const el = document.activeElement;
    if (isEditable(el)) return el;
    return document.querySelector('textarea, [contenteditable="true"]');
  }

  async function gate(el) {
    const text = (readText(el) || "").trim();
    if (!text) { resend(el); return; }
    const r = (globalThis.ShieldRules || {}).evaluate ? globalThis.ShieldRules.evaluate(text, bundle || {}) : { decision: "allow" };
    if (r.decision === "block") { overlay("Blocked — sensitive content: " + r.reasons.join(", ")); return; }
    if (r.decision === "redact") { writeText(el, r.redacted); overlay("Redacted sensitive data — review, then press Enter to send."); return; }
    // T1 — local heuristic classifier (injection / secrets) before the server hop
    const t1 = (globalThis.ShieldClassifier || {}).classify
      ? globalThis.ShieldClassifier.classify(text) : { label: "clean" };
    if (t1.label === "malicious") { overlay("Blocked — " + (t1.reasons.join(", ") || "high-risk prompt")); return; }
    const mustEscalate = flags.escalate || t1.label === "suspicious";
    if (mustEscalate) {
      overlay("Checking with Shield…", true);
      const e = await chrome.runtime.sendMessage({ type: "escalate", text }).catch(() => ({}));
      hide();
      if (e && e.blocked) { overlay("Blocked by Shield policy."); return; }
    }
    resend(el);
  }

  function resend(el) {
    const btn = findSendButton(el);
    // Programmatic button clicks are isTrusted=false, so the click
    // interceptor below ignores them — no PASS token needed on this path.
    // (Adding one anyway would leak: an unconsumed token lets the NEXT
    // genuine Enter keypress bypass the gate entirely.)
    if (btn) { btn.click(); return; }
    PASS.add(el);
    el.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
  }

  document.addEventListener("keydown", function (ev) {
    if (ev.key !== "Enter" || ev.shiftKey || ev.isComposing) return;
    const el = ev.target;
    if (!isEditable(el)) return;
    if (PASS.has(el)) { PASS.delete(el); return; }  // our own re-send — let it through
    ev.preventDefault();
    ev.stopPropagation();
    gate(el);
  }, true);

  // Clicking the site's Send button previously bypassed the gate entirely —
  // only the Enter key was intercepted. Capture-phase click listener closes
  // that path. isTrusted=false clicks (our own resend()) pass through; page
  // scripts could synthesize such clicks, but the threat model here is the
  // user's own accidental paste/submit, not an adversarial host page.
  document.addEventListener("click", function (ev) {
    if (!ev.isTrusted) return;
    const target = ev.target;
    const btn = target && target.closest ? target.closest(SEND_BUTTON_SELECTOR) : null;
    if (!btn) return;
    const el = findComposer();
    if (!el) return;
    ev.preventDefault();
    ev.stopPropagation();
    gate(el);
  }, true);
})();
