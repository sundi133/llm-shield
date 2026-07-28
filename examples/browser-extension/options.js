const FIELDS = ["shieldUrl", "tenantKey", "proxyToken", "mode", "timeoutMs"];
// Stored as a boolean: the select yields the STRING "false", which is truthy.
const BOOL_FIELDS = ["failOpen"];

async function load() {
  const c = await chrome.storage.local.get([...FIELDS, ...BOOL_FIELDS]);
  for (const f of FIELDS) if (c[f] != null) document.getElementById(f).value = c[f];
  for (const f of BOOL_FIELDS) document.getElementById(f).value = c[f] === true ? "true" : "false";
  if (!c.mode) document.getElementById("mode").value = "warn";
}

async function save() {
  const out = {};
  for (const f of FIELDS) out[f] = document.getElementById(f).value.trim();
  for (const f of BOOL_FIELDS) out[f] = document.getElementById(f).value === "true";
  await chrome.storage.local.set(out);
  const s = document.getElementById("status");
  s.textContent = "Saved ✓";
  setTimeout(() => (s.textContent = ""), 1500);
}

document.getElementById("save").addEventListener("click", save);
load();
