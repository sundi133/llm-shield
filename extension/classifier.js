/* Votal Shield — edge T1 local classifier (heuristic baseline).
 *
 * Sits between T0 (tenant regex rules) and T2 (server /guardrails/input): a
 * fast, offline, explainable check for prompt-injection / jailbreak attempts
 * and secret material that the tenant's regex rules may not cover.
 *
 * This is a HEURISTIC baseline, not an ML model — but it's the T1 seam: swap
 * `classify` for an ONNX/WASM model later (same return shape) without touching
 * content.js. Returns { label: "clean"|"suspicious"|"malicious", score, reasons }.
 */
(function (g) {
  const INJECTION = [
    /ignore (all |the )?(previous|above|prior) (instructions|rules|prompts?)/i,
    /disregard (the )?(system|previous|above) (prompt|instructions)/i,
    /you are now (in )?(developer|dan|jailbreak) mode/i,
    /reveal (your )?(the )?(system )?(prompt|instructions)/i,
    /print (your )?(the )?(system )?(prompt|instructions)/i,
    /(bypass|override|disable) (the )?(safety|guardrails?|filters?|restrictions?)/i,
  ];
  const SECRET = [
    /\b(sk|rk|pk)-[A-Za-z0-9]{20,}\b/,                 // generic API keys
    /\bAKIA[0-9A-Z]{16}\b/,                            // AWS access key id
    /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/, // private keys
    /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,                  // GitHub tokens
    /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,                // Slack tokens
  ];

  function classify(text) {
    const reasons = [];
    let score = 0;
    if (!text) return { label: "clean", score: 0, reasons };
    if (INJECTION.some((re) => re.test(text))) { reasons.push("prompt-injection phrasing"); score += 0.6; }
    if (SECRET.some((re) => re.test(text))) { reasons.push("secret/credential pattern"); score += 0.8; }
    if (/[A-Za-z0-9+/]{160,}={0,2}/.test(text)) { reasons.push("long base64 blob"); score += 0.3; }
    score = Math.min(score, 1);
    let label = "clean";
    if (score >= 0.8) label = "malicious";
    else if (score >= 0.4) label = "suspicious";
    return { label, score, reasons };
  }

  const api = { classify };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  g.ShieldClassifier = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
