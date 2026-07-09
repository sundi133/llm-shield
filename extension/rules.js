/* Votal Shield — edge T0 rules engine.
 *
 * Pure, offline policy evaluation that mirrors the server bundle semantics:
 *   - a rule with action "block" (or severity "critical") => BLOCK
 *   - a rule with action "redact" => redact the match with its replacement
 *   - a blocklist word present => BLOCK
 *   - nothing matched => ALLOW (caller may escalate to the server, /guardrails/input)
 *
 * Edge blocks the obvious; the server stays the source of truth. This runs in
 * the browser content script (globalThis.ShieldRules) and under Node for tests
 * (module.exports).
 */
(function (g) {
  function _compile(rx) {
    try { return new RegExp(rx, "gi"); } catch (_e) { return null; }
  }

  // Evaluate `text` against a policy bundle ({rules:[...], blocklists:[...]}).
  // Returns { decision: "block"|"redact"|"allow", redacted, matched:[ids], reasons:[] }.
  function evaluate(text, bundle) {
    const out = { decision: "allow", redacted: text, matched: [], reasons: [] };
    if (!text || !bundle) return out;

    let redacted = text;
    let blocked = false;
    let didRedact = false;

    for (const rule of bundle.rules || []) {
      const re = _compile(rule.regex);
      if (!re) continue;
      if (!re.test(text)) continue;
      out.matched.push(rule.id || rule.regex);
      const action = rule.action || (rule.severity === "critical" ? "block" : "redact");
      if (action === "block" || rule.severity === "critical") {
        blocked = true;
        out.reasons.push(`rule ${rule.id || rule.regex} (block)`);
      } else if (action === "redact") {
        didRedact = true;
        redacted = redacted.replace(_compile(rule.regex), rule.replacement || "[REDACTED]");
        out.reasons.push(`rule ${rule.id || rule.regex} (redact)`);
      }
    }

    const lower = text.toLowerCase();
    for (const word of bundle.blocklists || []) {
      if (word && lower.includes(String(word).toLowerCase())) {
        blocked = true;
        out.matched.push(`blocklist:${word}`);
        out.reasons.push(`blocklist '${word}'`);
      }
    }

    if (blocked) out.decision = "block";
    else if (didRedact) { out.decision = "redact"; out.redacted = redacted; }
    else out.decision = "allow";
    return out;
  }

  const api = { evaluate };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  g.ShieldRules = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
