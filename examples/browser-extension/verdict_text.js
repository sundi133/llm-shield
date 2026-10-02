// What to tell the user when Shield flags a prompt or file: which policy, and
// why, instead of the guardrail's internal name ("custom_policy_input").
// Pure functions over the /guardrails/* response; no chrome.* or fetch here.

const GUARDRAIL_LABELS = {
  custom_policy_input: "Company policy",
  custom_policy: "Company policy",
  adversarial_detection: "Prompt injection check",
  system_prompt_leak: "System prompt protection",
  keyword_blocklist: "Blocked keyword",
  pii_detection: "Personal data",
  pii_leakage: "Personal data",
  topic_restriction: "Restricted topic",
  length_limit: "Prompt length limit",
};
const WHY_MAX = 220;
const SHOWN_MAX = 2;

function guardrailLabel(name) {
  if (GUARDRAIL_LABELS[name]) return GUARDRAIL_LABELS[name];
  const words = String(name || "policy").replace(/[_-]+/g, " ").trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

function clip(text, max) {
  const t = String(text || "").replace(/\s+/g, " ").trim();
  return t.length > max ? t.slice(0, max - 1).trimEnd() + "…" : t;
}

// One failed guardrail result -> { guardrail, policy, policyId, label, why }.
function explainResult(g) {
  const d = (g && g.details) || {};
  const primary = d.primary_violation || {};
  const policy = String(primary.policy_name || d.policy_name || "").trim();
  let why = String(primary.reasoning || g.message || "").trim();
  // The custom policy guardrail wraps its reason: "2 custom input policy
  // violation(s). Worst: Custom input policy 'X': <reason>".
  why = why.replace(/^\d+ custom (?:input|output) policy violation\(s\)\. Worst: /i, "");
  why = why.replace(/^Custom (?:input|output) policy '[^']*': /i, "");
  return {
    guardrail: String(g.guardrail || ""),
    policy,
    policyId: String(primary.policy_id || d.policy_id || ""),
    label: policy ? "“" + policy + "” policy" : guardrailLabel(g.guardrail),
    why: clip(why, WHY_MAX),
  };
}

// "Label: why", without saying the same thing twice: a message that already
// starts with its label ("Blocked keyword(s) detected: ...") stands alone.
function line(i) {
  if (!i.why) return i.label;
  const plain = (t) => t.toLowerCase().replace(/\(s\)/g, "").replace(/[^a-z0-9 ]/g, "");
  return plain(i.why).startsWith(plain(i.label)) ? i.why : i.label + ": " + i.why;
}

// The whole response -> { reason, items, guardrails }.
//   reason      one line for the banner
//   items       every failed guardrail, explained (for an exception request)
//   guardrails  the internal names, comma-separated (what `reason` used to be)
function explainVerdict(data) {
  const failed = ((data && data.guardrail_results) || []).filter((g) => g && g.passed === false);
  const items = failed.map(explainResult);
  const guardrails = items.map((i) => i.guardrail).join(", ");
  if (!items.length) return { reason: String((data && data.action) || ""), items, guardrails };
  const shown = items.slice(0, SHOWN_MAX).map(line);
  const more = items.length - SHOWN_MAX;
  const reason = shown.join("; ") + (more > 0 ? " (+" + more + " more)" : "");
  return { reason, items, guardrails };
}

if (typeof module !== "undefined") {
  module.exports = { explainVerdict, explainResult, guardrailLabel };
}
