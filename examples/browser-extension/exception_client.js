// Exception requests (docs/specs/prompt-exception-requests.md, task 5).
// A user whose prompt Shield blocked asks for an exception; an admin approves
// it in the portal; the next send of the same prompt carries the signed grant
// and goes through once.
//
// No chrome.* here: `deps` supplies fetch, a key-value store, the Shield base
// URL and the request headers, so this is testable in node.
//   deps = { fetch, store: { get(k), set(k, v), remove(k), all() }, base, headers, now() }

const EXC_PREFIX = "exc:";
const GRANT_HEADER = "X-Shield-Exception-Grant";
// Collect a fresh grant when the one held has less than this left.
const GRANT_MARGIN_S = 15;
// Outcomes after which the request is finished: nothing more to send or poll.
const FINISHED = new Set(["used", "denied", "expired", "gone"]);

// The same identity the server binds a grant to: NFC, outer whitespace trimmed.
async function promptHash(text) {
  const data = new TextEncoder().encode(String(text || "").normalize("NFC").trim());
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function keyFor(hash, destination) {
  return EXC_PREFIX + destination + ":" + hash;
}

async function call(deps, method, path, body) {
  const headers = { ...deps.headers };
  if (body) headers["Content-Type"] = "application/json";
  const r = await deps.fetch(deps.base.replace(/\/+$/, "") + path, {
    method, headers, body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try { data = await r.json(); } catch (_) {}
  return { status: r.status, ok: r.ok, data };
}

// What the server's error says, in words the user can act on.
function explainError(status, data) {
  const d = (data && data.detail) || {};
  const code = (typeof d === "object" && d.error) || "";
  const messages = {
    exceptions_disabled: "Your organisation has not turned on exception requests.",
    not_blocked: "This prompt is no longer blocked. Send it again.",
    not_appealable: "This policy does not accept exception requests.",
    too_many_pending: (typeof d === "object" && d.message) || "You have too many requests waiting for review.",
    approvals_not_configured: "Exception requests are not available on this Shield yet.",
    invalid_request: "The request could not be sent: " + ((d.errors || []).join("; ") || "invalid"),
  };
  return { code: code || "http_" + status, message: messages[code] || (typeof d === "object" && d.message) || "Request failed (HTTP " + status + ")" };
}

// Ask for an exception for a blocked prompt. Returns
// { ok, status, request_id, code?, message? }.
async function requestException(deps, { text, destination, reason }) {
  let res;
  try {
    res = await call(deps, "POST", "/v1/shield/exceptions", { prompt: text, destination, reason });
  } catch (e) {
    return { ok: false, code: "unreachable", message: "Shield could not be reached. Try again." };
  }
  if (!res.ok) return { ok: false, ...explainError(res.status, res.data) };
  const hash = await promptHash(text);
  const rec = { request_id: res.data.request_id, status: res.data.status, destination, hash,
                expires_at: res.data.expires_at };
  await deps.store.set(keyFor(hash, destination), rec);
  return { ok: true, status: rec.status, request_id: rec.request_id };
}

// Ask Shield where a request stands; an approved one comes back with a grant.
async function refresh(deps, rec) {
  let res;
  try {
    res = await call(deps, "GET", "/v1/shield/exceptions/" + encodeURIComponent(rec.request_id));
  } catch (_) {
    return rec; // offline: keep what we know
  }
  const key = keyFor(rec.hash, rec.destination);
  if (res.status === 404) {
    await deps.store.remove(key);
    return { ...rec, status: "gone" };
  }
  if (!res.ok) return rec;
  const d = res.data;
  const next = { ...rec, status: d.status, decision: d.decision || null,
                 grant: d.grant || null, grant_expires_at: d.grant_expires_at || null };
  if (FINISHED.has(next.status) && next.status !== "denied") await deps.store.remove(key);
  else await deps.store.set(key, next);
  return next;
}

// The grant to attach when sending this prompt, if an approval is waiting for
// it. Returns { grant, rec }: grant is "" when there is nothing to attach.
async function grantFor(deps, text, destination) {
  const hash = await promptHash(text);
  let rec = await deps.store.get(keyFor(hash, destination));
  if (!rec) return { grant: "", rec: null };
  if (rec.status === "approved" &&
      (!rec.grant || (rec.grant_expires_at || 0) - deps.now() < GRANT_MARGIN_S)) {
    rec = await refresh(deps, rec);
  }
  return { grant: rec.status === "approved" && rec.grant ? rec.grant : "", rec };
}

// After a send that carried a grant: forget a used approval; drop a grant
// Shield refused as expired so the next send collects a new one.
async function afterSend(deps, text, destination, data) {
  const hash = await promptHash(text);
  const key = keyFor(hash, destination);
  if (data && data.exception) {
    await deps.store.remove(key);
    return "released";
  }
  const why = data && data.exception_error;
  if (!why) return "";
  const rec = await deps.store.get(key);
  if (why === "grant_used" || why === "exceptions_disabled" || why === "not_appealable" ||
      why === "new_violation") {
    await deps.store.remove(key);
  } else if (rec && why === "grant_expired") {
    await deps.store.set(key, { ...rec, grant: null, grant_expires_at: null });
  }
  return why;
}

// Every pending request for this site, refreshed. Returns the ones whose
// status changed: [{ request_id, status, decision }].
async function poll(deps, destination) {
  const all = await deps.store.all();
  const changed = [];
  for (const [key, rec] of Object.entries(all || {})) {
    if (!key.startsWith(EXC_PREFIX) || !rec || rec.destination !== destination ||
        rec.status !== "pending") continue;
    const next = await refresh(deps, rec);
    if (next.status !== "pending") {
      changed.push({ request_id: next.request_id, status: next.status, decision: next.decision || null });
    }
  }
  return changed;
}

if (typeof module !== "undefined") {
  module.exports = { promptHash, keyFor, requestException, refresh, grantFor, afterSend, poll,
                     explainError, GRANT_HEADER };
}
