const DEFAULTS = { shieldUrl: "", tenantKey: "", proxyToken: "", escalate: true, enabled: true };
const $ = (id) => document.getElementById(id);

async function load() {
  const c = Object.assign({}, DEFAULTS, await chrome.storage.sync.get(DEFAULTS));
  $("shieldUrl").value = c.shieldUrl;
  $("tenantKey").value = c.tenantKey;
  $("proxyToken").value = c.proxyToken;
  $("escalate").checked = c.escalate;
  $("enabled").checked = c.enabled;
}

$("save").addEventListener("click", async () => {
  const c = {
    shieldUrl: $("shieldUrl").value.trim().replace(/\/+$/, ""),
    tenantKey: $("tenantKey").value.trim(),
    proxyToken: $("proxyToken").value.trim(),
    escalate: $("escalate").checked,
    enabled: $("enabled").checked,
  };
  // Request permission to reach the configured Shield host (background fetches it).
  if (c.shieldUrl) {
    try {
      const origin = new URL(c.shieldUrl).origin + "/*";
      await chrome.permissions.request({ origins: [origin] });
    } catch (_e) { /* user may decline; surfaced as fetch errors later */ }
  }
  await chrome.storage.sync.set(c);
  $("status").textContent = "Saved";
  setTimeout(() => ($("status").textContent = ""), 2000);
});

load();
