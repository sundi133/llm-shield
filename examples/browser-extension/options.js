const FIELDS = ["shieldUrl", "tenantKey", "proxyToken", "mode", "timeoutMs"];

async function load() {
  const c = await chrome.storage.local.get(FIELDS);
  for (const f of FIELDS) if (c[f] != null) document.getElementById(f).value = c[f];
  if (!c.mode) document.getElementById("mode").value = "warn";
}

async function save() {
  const out = {};
  for (const f of FIELDS) out[f] = document.getElementById(f).value.trim();
  await chrome.storage.local.set(out);
  const s = document.getElementById("status");
  s.textContent = "Saved ✓";
  setTimeout(() => (s.textContent = ""), 1500);
}

document.getElementById("save").addEventListener("click", save);
load();
